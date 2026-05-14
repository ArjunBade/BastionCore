package etw

// ProcessInfo represents a simplified process creation event.
type ProcessInfo struct {
	ProcessID       uint32
	ParentProcessID uint32
	ImageName       string
	CommandLine     string
}

// NetworkInfo represents a simplified outbound network event.
type NetworkInfo struct {
	ProcessID  uint32
	SourceIP   string
	SourcePort uint32
	DestIP     string
	DestPort   uint32
	Protocol   string
}
