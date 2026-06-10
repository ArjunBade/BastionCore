package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"edr-core/pkg/api"
	"edr-core/pkg/process"
)

func main() {
	serverAddr := flag.String("server", "localhost:50051", "gRPC server address")
	loop := flag.Bool("loop", false, "send sequence in a loop every 10s")
	flag.Parse()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "real-agent"
	}

	restAddr := os.Getenv("REST_ADDR")
	if restAddr == "" {
		restAddr = "http://localhost:8080"
	}

	client, conn, err := newTelemetryClient(*serverAddr)
	if err != nil {
		log.Fatalf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Background heartbeat + response poller so this single process can both
	// generate the attack and act on operator kill commands.
	go heartbeatLoop(client, restAddr, hostname)

	for {
		if err := sendSequence(client, hostname); err != nil {
			log.Printf("sequence send failed: %v", err)
		}
		if !*loop {
			break
		}
		time.Sleep(10 * time.Second)
	}
}

// newTelemetryClient dials the server over mTLS, matching the server's
// RequireAndVerifyClientCert policy, and returns a Telemetry client.
func newTelemetryClient(serverAddr string) (api.TelemetryClient, *grpc.ClientConn, error) {
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert: %w", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		return nil, nil, fmt.Errorf("failed to append CA cert to pool")
	}

	clientCert, err := tls.LoadX509KeyPair("certs/agent-cert.pem", "certs/agent-key.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client cert/key: %w", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
	})

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial server: %w", err)
	}

	return api.NewTelemetryClient(conn), conn, nil
}

// heartbeatLoop keeps the host marked ONLINE and polls the REST control plane
// for queued response commands, executing them locally.
func heartbeatLoop(client api.TelemetryClient, restAddr, hostname string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		hb := &api.HeartbeatEvent{
			AgentId:   hostname,
			Status:    "ONLINE",
			Timestamp: time.Now().UnixMilli(),
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := client.SendHeartbeat(ctx, hb); err != nil {
			log.Printf("failed to send heartbeat: %v", err)
		} else {
			log.Println("[+] Heartbeat sent")
		}
		cancel()

		pollResponseCommands(restAddr, hostname)
	}
}

// sendSequence emits a scripted attack chain that exercises the rule engine:
//   cmd.exe -> powershell.exe -EncodedCommand -> C2 connection -> mimikatz.exe
func sendSequence(client api.TelemetryClient, hostname string) error {
	ts := time.Now().UnixMilli()

	proc := func(t int64, pid, ppid uint32, image, cmdLine string) *api.ProcessEvent {
		return &api.ProcessEvent{
			Timestamp:       t,
			ProcessId:       pid,
			ParentProcessId: ppid,
			ImagePath:       image,
			CommandLine:     cmdLine,
			EventType:       "START",
		}
	}

	// 1. cmd.exe starts (PID 1200)
	sendEvent(client, proc(ts, 1200, 0, "cmd.exe", "cmd.exe"))

	// 2. powershell.exe starts as child of cmd.exe (PID 1201) with -EncodedCommand
	//    -> triggers HIGH "Encoded PowerShell Command"
	sendEvent(client, proc(ts+100, 1201, 1200, "powershell.exe", "powershell.exe -EncodedCommand KABU..."))

	// 3. outbound connection from PID 1201 to a known-bad host on port 4444
	//    -> triggers HIGH "Suspicious Remote Port"
	netEv := &api.NetworkEvent{
		Timestamp: ts + 200,
		ProcessId: 1201,
		Protocol:  "TCP",
		SourceIp:  "10.0.2.15",
		DestIp:    "185.220.101.45",
		DestPort:  4444,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := client.SendNetworkEvent(ctx, netEv); err != nil {
		cancel()
		return fmt.Errorf("failed to send network event: %w", err)
	}
	cancel()

	// 4. mimikatz starts (PID 1202)
	sendEvent(client, proc(ts+300, 1202, 1201, "mimikatz.exe", "mimikatz.exe"))

	log.Printf("attack sequence sent for host=%s", hostname)
	return nil
}

func sendEvent(client api.TelemetryClient, ev *api.ProcessEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.SendEvent(ctx, ev); err != nil {
		log.Printf("failed to send process event pid=%d: %v", ev.ProcessId, err)
	}
}

// pendingCommand mirrors the JSON returned by GET /api/response/pending.
type pendingCommand struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	TargetPID int32  `json:"target_pid"`
}

// pollResponseCommands fetches and executes any pending response commands
// queued for this host via the server's REST control plane.
func pollResponseCommands(restAddr, hostname string) {
	endpoint := fmt.Sprintf("%s/api/response/pending?hostname=%s", restAddr, url.QueryEscape(hostname))
	resp, err := http.Get(endpoint)
	if err != nil {
		log.Printf("failed to poll pending commands: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var cmds []pendingCommand
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		log.Printf("failed to decode pending commands: %v", err)
		return
	}

	for _, c := range cmds {
		if c.Action != "KILL_PID" {
			continue
		}
		status := "EXECUTED"
		if err := process.TerminateProcess(uint32(c.TargetPID)); err != nil {
			log.Printf("failed to execute kill command id=%s pid=%d: %v", c.ID, c.TargetPID, err)
			status = "FAILED"
		} else {
			log.Printf("executed kill command id=%s pid=%d", c.ID, c.TargetPID)
		}
		reportCommandComplete(restAddr, c.ID, status)
	}
}

// reportCommandComplete marks a response command as EXECUTED or FAILED.
func reportCommandComplete(restAddr, id, status string) {
	body, _ := json.Marshal(map[string]string{"id": id, "status": status})
	resp, err := http.Post(restAddr+"/api/response/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("failed to report command completion id=%s: %v", id, err)
		return
	}
	resp.Body.Close()
}
