package etw

// ProcessInfo represents a simplified process creation event.
type ProcessInfo struct {
	ProcessID       uint32
	ParentProcessID uint32
	ImageName       string
	CommandLine     string
}
