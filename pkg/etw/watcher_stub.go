//go:build !windows

package etw

import (
	"math/rand"
	"time"
)

// StartWatching is a stub implementation used on non-Windows platforms.
// It spawns a goroutine that generates mock ProcessInfo events every 3 seconds
// and calls the provided callback.
func StartWatching(callback func(ProcessInfo)) error {
	go func() {
		rand.Seed(time.Now().UnixNano())
		for {
			time.Sleep(3 * time.Second)

			pid := uint32(rand.Intn(50000) + 100)
			ppid := uint32(rand.Intn(5000) + 1)

			// Generate a fake malware-like path and command line for testing.
			pi := ProcessInfo{
				ProcessID:       pid,
				ParentProcessID: ppid,
				ImageName:       "/usr/bin/fake_malware_" + randomString(6),
				CommandLine:     "--steal-creds --target " + randomString(8),
			}

			callback(pi)
		}
	}()

	return nil
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
