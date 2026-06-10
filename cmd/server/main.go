package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"edr-core/pkg/api"
	"edr-core/pkg/rules"
)

type telemServer struct {
	api.UnimplementedTelemetryServer
	db         *sql.DB
	ruleEngine *rules.RuleEngine
	hostname   string
}

func (s *telemServer) SendEvent(ctx context.Context, ev *api.ProcessEvent) (*api.EventResponse, error) {
	fmt.Printf("Received ProcessEvent: timestamp=%d pid=%d ppid=%d image=%s cmd=%s type=%s\n",
		ev.Timestamp, ev.ProcessId, ev.ParentProcessId, ev.ImagePath, ev.CommandLine, ev.EventType)
	if s.db != nil {
		// try to determine hostname from peer TLS certificate CN
		hostname := getPeerHostname(ctx)
		if hostname == "" {
			hostname = "unknown"
		}
		processEvent := rules.ProcessEvent{
			Timestamp:   ev.Timestamp,
			Hostname:    hostname,
			PID:         ev.ProcessId,
			PPID:        ev.ParentProcessId,
			Executable:  normalizeExecutablePath(ev.ImagePath),
			CommandLine: ev.CommandLine,
			Username:    currentUsername(),
			Action:      strings.ToUpper(ev.EventType),
		}

		if err := insertProcessEvent(s.db, processEvent); err == nil {
			s.ruleEngine.EvaluateProcess(s.hostname, processEvent)
		}
		if err := updateHostSeen(s.db, processEvent.Hostname); err != nil {
			log.Printf("failed to update host seen: %v", err)
		}
	}
	return &api.EventResponse{Success: true}, nil
}

func (s *telemServer) SendHeartbeat(ctx context.Context, hb *api.HeartbeatEvent) (*api.EventResponse, error) {
	fmt.Printf("[💓] Heartbeat received from: %s\n", hb.AgentId)
	if s.db != nil {
		if err := updateHostSeen(s.db, hb.AgentId); err != nil {
			log.Printf("failed to update host seen from heartbeat: %v", err)
		}
	}
	// Response actions are driven by the REST control plane
	// (/api/response/kill) and polled by the agent, not synthesized here.
	resp := &api.EventResponse{Success: true}
	return resp, nil
}

func (s *telemServer) SendNetworkEvent(ctx context.Context, ev *api.NetworkEvent) (*api.EventResponse, error) {
	fmt.Printf("[🌐 NETWORK] PID: %d connected to %s:%d\n", ev.ProcessId, ev.DestIp, ev.DestPort)
	if s.db != nil {
		hostname := getPeerHostname(ctx)
		if hostname == "" {
			hostname = "unknown"
		}
		networkEvent := rules.NetworkEvent{
			Timestamp:  ev.Timestamp,
			Hostname:   hostname,
			PID:        ev.ProcessId,
			LocalIP:    ev.SourceIp,
			RemoteIP:   ev.DestIp,
			RemotePort: ev.DestPort,
			Protocol:   ev.Protocol,
		}

		if err := insertNetworkEvent(s.db, networkEvent); err == nil {
			s.ruleEngine.EvaluateNetwork(s.hostname, networkEvent)
		}
		if err := updateHostSeen(s.db, networkEvent.Hostname); err != nil {
			log.Printf("failed to update host seen for network event: %v", err)
		}
	}
	return &api.EventResponse{Success: true}, nil
}

func getPeerHostname(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	if p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				return tlsInfo.State.PeerCertificates[0].Subject.CommonName
			}
		}
	}
	if p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	var db *sql.DB
	if dsn := os.Getenv("CLICKHOUSE_DSN"); dsn != "" {
		db, err = sql.Open("clickhouse", dsn)
		if err != nil {
			log.Fatalf("failed to open ClickHouse connection: %v", err)
		}
		if err := db.Ping(); err != nil {
			log.Fatalf("failed to ping ClickHouse: %v", err)
		}
		log.Printf("connected to ClickHouse")
	} else {
		log.Printf("CLICKHOUSE_DSN not set; running without ClickHouse persistence")
	}

	// Load CA cert to verify client certificates
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("failed to append CA cert to client CA pool")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("certs/server-cert.pem", "certs/server-key.pem")
	if err != nil {
		log.Fatalf("failed to load server cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	ruleEngine := rules.NewRuleEngine(db)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	api.RegisterTelemetryServer(grpcServer, &telemServer{db: db, ruleEngine: ruleEngine, hostname: hostname})

	// Start grpc server (mTLS) on :50051
	go func() {
		log.Printf("gRPC server listening on :50051")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server exited with error: %v", err)
		}
	}()

	// Ensure response_commands table exists if ClickHouse is available
	if db != nil {
		if err := ensureResponseCommandsTable(db); err != nil {
			log.Printf("failed to ensure response_commands table: %v", err)
		}

		if err := ensureHostsTable(db); err != nil {
			log.Printf("failed to ensure hosts table: %v", err)
		}

		if err := ensureProcessEventsTable(db); err != nil {
			log.Printf("failed to ensure process_events table: %v", err)
		}

		if err := ensureNetworkEventsTable(db); err != nil {
			log.Printf("failed to ensure network_events table: %v", err)
		}

		if err := ensureAlertsTable(db); err != nil {
			log.Printf("failed to ensure alerts table: %v", err)
		}

		// background goroutine to mark hosts OFFLINE if no event in 30s
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				rows, err := db.Query("SELECT hostname, max(last_seen) FROM edr.hosts GROUP BY hostname")
				if err != nil {
					log.Printf("hosts offline checker query failed: %v", err)
					continue
				}
				for rows.Next() {
					var host string
					var lastSeen time.Time
					if err := rows.Scan(&host, &lastSeen); err != nil {
						log.Printf("failed to scan host row: %v", err)
						continue
					}
					if time.Since(lastSeen) > 30*time.Second {
						_, err := db.Exec("INSERT INTO edr.hosts (hostname, last_seen, status) VALUES (?, ?, ?)", host, time.Now(), "OFFLINE")
						if err != nil {
							log.Printf("failed to mark host offline: %v", err)
						}
					}
				}
				rows.Close()
			}
		}()
	}

	// REST API server on :8080
	go func() {
		mux := http.NewServeMux()

		mux.HandleFunc("/api/response/kill", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				setCORSHeaders(w)
				w.WriteHeader(http.StatusOK)
				return
			}
			setCORSHeaders(w)
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if db == nil {
				http.Error(w, "ClickHouse not configured", http.StatusInternalServerError)
				return
			}
			var req struct {
				Hostname string `json:"hostname"`
				Pid      int32  `json:"pid"`
				IssuedBy string `json:"issued_by"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			id, err := genUUID()
			if err != nil {
				http.Error(w, "failed to generate id", http.StatusInternalServerError)
				return
			}
			ts := time.Now()
			_, err = db.Exec(
				"INSERT INTO edr.response_commands (id, timestamp, hostname, action, target_pid, issued_by, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
				id, ts, req.Hostname, "KILL_PID", req.Pid, req.IssuedBy, "PENDING",
			)
			if err != nil {
				http.Error(w, "insert failed", http.StatusInternalServerError)
				return
			}
			resp := map[string]any{"id": id, "status": "PENDING"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})

		mux.HandleFunc("/api/response/pending", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				setCORSHeaders(w)
				w.WriteHeader(http.StatusOK)
				return
			}
			setCORSHeaders(w)
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if db == nil {
				http.Error(w, "ClickHouse not configured", http.StatusInternalServerError)
				return
			}
			hostname := r.URL.Query().Get("hostname")
			rows, err := db.Query("SELECT id, timestamp, hostname, action, target_pid, issued_by, status FROM edr.response_commands WHERE status = 'PENDING' AND hostname = ?", hostname)
			if err != nil {
				http.Error(w, "query failed", http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			type cmd struct {
				ID        string    `json:"id"`
				Timestamp time.Time `json:"timestamp"`
				Hostname  string    `json:"hostname"`
				Action    string    `json:"action"`
				TargetPID int32     `json:"target_pid"`
				IssuedBy  string    `json:"issued_by"`
				Status    string    `json:"status"`
			}
			var out []cmd
			for rows.Next() {
				var c cmd
				if err := rows.Scan(&c.ID, &c.Timestamp, &c.Hostname, &c.Action, &c.TargetPID, &c.IssuedBy, &c.Status); err != nil {
					http.Error(w, "scan failed", http.StatusInternalServerError)
					return
				}
				out = append(out, c)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		})

		mux.HandleFunc("/api/response/complete", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				setCORSHeaders(w)
				w.WriteHeader(http.StatusOK)
				return
			}
			setCORSHeaders(w)
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if db == nil {
				http.Error(w, "ClickHouse not configured", http.StatusInternalServerError)
				return
			}
			var req struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.Status != "EXECUTED" && req.Status != "FAILED" {
				http.Error(w, "invalid status", http.StatusBadRequest)
				return
			}
			// ClickHouse uses ALTER TABLE ... UPDATE for mutations
			_, err := db.Exec("ALTER TABLE edr.response_commands UPDATE status = ? WHERE id = ?", req.Status, req.ID)
			if err != nil {
				http.Error(w, "update failed", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		srv := &http.Server{Addr: ":8080", Handler: mux}
		log.Printf("REST server listening on :8080 (CORS enabled)")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("REST server error: %v", err)
		}
	}()

	// Block forever
	select {}
}

func insertProcessEvent(db *sql.DB, event rules.ProcessEvent) error {
	_, err := db.Exec(
		"INSERT INTO edr.process_events (timestamp, hostname, pid, ppid, executable, command_line, user, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		time.UnixMilli(event.Timestamp),
		event.Hostname,
		event.PID,
		event.PPID,
		event.Executable,
		event.CommandLine,
		event.Username,
		event.Action,
	)
	return err
}

func insertNetworkEvent(db *sql.DB, event rules.NetworkEvent) error {
	_, err := db.Exec(
		"INSERT INTO edr.network_events (timestamp, hostname, pid, protocol, local_ip, remote_ip, remote_port) VALUES (?, ?, ?, ?, ?, ?, ?)",
		time.UnixMilli(event.Timestamp),
		event.Hostname,
		event.PID,
		event.Protocol,
		event.LocalIP,
		event.RemoteIP,
		event.RemotePort,
	)
	return err
}

func normalizeExecutablePath(imagePath string) string {
	if imagePath == "" {
		return ""
	}
	return filepath.Base(imagePath)
}

func currentUsername() string {
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	return "unknown"
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func genUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func ensureResponseCommandsTable(db *sql.DB) error {
	ddl := `CREATE TABLE IF NOT EXISTS edr.response_commands (
		id UUID DEFAULT generateUUIDv4(),
		timestamp DateTime DEFAULT now(),
		hostname String,
		action String,
		target_pid Int32,
		issued_by String,
		status String
	) ENGINE = MergeTree() ORDER BY (timestamp)`
	_, err := db.Exec(ddl)
	return err
}

func ensureHostsTable(db *sql.DB) error {
	ddl := `CREATE TABLE IF NOT EXISTS edr.hosts (
		hostname String,
		last_seen DateTime,
		status String
	) ENGINE = MergeTree() ORDER BY (hostname)`
	_, err := db.Exec(ddl)
	return err
}

func ensureProcessEventsTable(db *sql.DB) error {
	ddl := `CREATE TABLE IF NOT EXISTS edr.process_events (
		timestamp DateTime64(3),
		hostname String,
		pid UInt32,
		ppid UInt32,
		executable String,
		command_line String,
		user String,
		action String
	) ENGINE = MergeTree() ORDER BY (timestamp)`
	_, err := db.Exec(ddl)
	return err
}

func ensureNetworkEventsTable(db *sql.DB) error {
	ddl := `CREATE TABLE IF NOT EXISTS edr.network_events (
		timestamp DateTime64(3),
		hostname String,
		pid UInt32,
		protocol String,
		local_ip String,
		remote_ip String,
		remote_port UInt32
	) ENGINE = MergeTree() ORDER BY (timestamp)`
	_, err := db.Exec(ddl)
	return err
}

func ensureAlertsTable(db *sql.DB) error {
	ddl := `CREATE TABLE IF NOT EXISTS edr.alerts (
		timestamp DateTime64(3),
		hostname String,
		severity String,
		source String,
		title String,
		description String
	) ENGINE = MergeTree() ORDER BY (timestamp)`
	_, err := db.Exec(ddl)
	return err
}

func updateHostSeen(db *sql.DB, hostname string) error {
	if hostname == "" {
		return nil
	}
	ts := time.Now()
	_, err := db.Exec("INSERT INTO edr.hosts (hostname, last_seen, status) VALUES (?, ?, ?)", hostname, ts, "ONLINE")
	return err
}
