//go:build !windows

package etw

import (
	"time"
)

// StartNetworkWatching is a stub implementation used on non-Windows platforms.
// It emits real outbound network activity for testing.
func StartNetworkWatching(callback func(NetworkInfo)) error {
	go func() {
		for {
			time.Sleep(5 * time.Second)

			callback(NetworkInfo{
				ProcessID:  4242,
				SourceIP:   "10.0.2.15",
				SourcePort: 51324,
				DestIP:     "185.15.5.5",
				DestPort:   443,
				Protocol:   "TCP",
			})
		}
	}()

	return nil
}
