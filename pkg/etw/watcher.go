//go:build windows

package etw

import (
	"log"
	"time"
)

// StartWatching is a Windows implementation placeholder that keeps the package
// buildable in Codespaces without external ETW dependencies.
func StartWatching(callback func(ProcessInfo)) error {
	go func() {
		for {
			time.Sleep(3 * time.Second)
			callback(ProcessInfo{
				ProcessID:       1337,
				ParentProcessID: 1,
				ImageName:       "C:\\Windows\\System32\\svchost.exe",
				CommandLine:     "svchost.exe -k netsvcs",
			})
		}
	}()

	log.Println("etw: windows watcher running in placeholder mode")
	return nil
}
