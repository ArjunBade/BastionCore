package rules

import (
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

type RuleEngine struct {
	db *sql.DB
}

type ProcessEvent struct {
	Timestamp   int64
	Hostname    string
	PID         uint32
	PPID        uint32
	Executable  string
	CommandLine string
	Username    string
	Action      string
}

type NetworkEvent struct {
	Timestamp  int64
	Hostname   string
	PID        uint32
	LocalIP    string
	RemoteIP   string
	RemotePort uint32
	Protocol   string
}

func NewRuleEngine(db *sql.DB) *RuleEngine {
	return &RuleEngine{db: db}
}

func (re *RuleEngine) EvaluateProcess(hostname string, event ProcessEvent) {
	if re == nil || re.db == nil {
		return
	}

	executable := normalizeExecutable(event.Executable)
	commandLine := strings.ToLower(event.CommandLine)
	action := strings.ToUpper(strings.TrimSpace(event.Action))
	username := strings.ToUpper(strings.TrimSpace(event.Username))

	if (executable == "cmd.exe" || executable == "cmd") && re.childIsPowerShell(hostname, event.PID) {
		re.insertAlert(hostname, "HIGH", "Suspicious Shell Spawn", "cmd spawned a PowerShell child process")
	}

	if strings.Contains(commandLine, "-encodedcommand") || strings.Contains(commandLine, "-enc ") {
		re.insertAlert(hostname, "HIGH", "Encoded PowerShell Command", "process command line contains an encoded PowerShell payload")
	}

	if executable == "net.exe" || executable == "net1.exe" {
		re.insertAlert(hostname, "MEDIUM", "Net Utility Usage", "net.exe or net1.exe execution observed")
	}

	if action == "START" && username == "SYSTEM" && !isKnownSystemProcess(executable) {
		re.insertAlert(hostname, "MEDIUM", "Unexpected SYSTEM Process", "a non-system process started under the SYSTEM account")
	}
}

func (re *RuleEngine) EvaluateNetwork(hostname string, event NetworkEvent) {
	if re == nil || re.db == nil {
		return
	}

	if isReverseShellPort(event.RemotePort) {
		re.insertAlert(hostname, "HIGH", "Suspicious Remote Port", fmt.Sprintf("outbound connection to common reverse shell port %d", event.RemotePort))
	}

	if !isPrivateIP(event.RemoteIP) && re.pidBelongsToSystemProcess(hostname, event.PID) {
		re.insertAlert(hostname, "MEDIUM", "System Process Internet Access", fmt.Sprintf("system process PID %d connected to public IP %s", event.PID, event.RemoteIP))
	}
}

func (re *RuleEngine) childIsPowerShell(hostname string, ppid uint32) bool {
	if re == nil || re.db == nil {
		return false
	}

	var executable string
	err := re.db.QueryRow(
		"SELECT executable FROM edr.process_events WHERE hostname = ? AND ppid = ? ORDER BY timestamp DESC LIMIT 1",
		hostname,
		ppid,
	).Scan(&executable)
	if err != nil {
		return false
	}

	return strings.EqualFold(normalizeExecutable(executable), "powershell.exe") || strings.EqualFold(normalizeExecutable(executable), "powershell")
}

func (re *RuleEngine) pidBelongsToSystemProcess(hostname string, pid uint32) bool {
	if re == nil || re.db == nil {
		return false
	}

	var executable string
	err := re.db.QueryRow(
		"SELECT executable FROM edr.process_events WHERE hostname = ? AND pid = ? ORDER BY timestamp DESC LIMIT 1",
		hostname,
		pid,
	).Scan(&executable)
	if err != nil {
		return false
	}

	return isKnownSystemProcess(normalizeExecutable(executable))
}

func (re *RuleEngine) insertAlert(hostname, severity, title, description string) {
	if re == nil || re.db == nil {
		return
	}

	_, _ = re.db.Exec(
		"INSERT INTO edr.alerts (timestamp, hostname, severity, source, title, description) VALUES (?, ?, ?, ?, ?, ?)",
		time.Now().UnixMilli(),
		hostname,
		severity,
		"rule_engine",
		title,
		description,
	)
}

func normalizeExecutable(executable string) string {
	base := filepath.Base(strings.TrimSpace(executable))
	return strings.ToLower(base)
}

func isKnownSystemProcess(executable string) bool {
	switch normalizeExecutable(executable) {
	case "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe", "explorer.exe", "runtimebroker.exe", "dwm.exe":
		return true
	default:
		return false
	}
}

func isReverseShellPort(port uint32) bool {
	switch port {
	case 4444, 1337, 9001, 31337:
		return true
	default:
		return false
	}
}

func isPrivateIP(ipString string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipString))
	if ip == nil {
		return false
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	switch {
	case ipv4[0] == 10:
		return true
	case ipv4[0] == 192 && ipv4[1] == 168:
		return true
	case ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31:
		return true
	default:
		return false
	}
}
