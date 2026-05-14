//go:build windows

package etw

import (
	"log"
	"time"
)

// StartNetworkWatching is the Windows counterpart to the non-Windows stub.
func StartNetworkWatching(callback func(NetworkInfo)) error {
	go func() {
		for {
			time.Sleep(5 * time.Second)
			callback(NetworkInfo{
				ProcessID:  1337,
				SourceIP:   "10.0.2.15",
				SourcePort: 51324,
				DestIP:     "185.15.5.5",
				DestPort:   443,
				Protocol:   "TCP",
			})
		}
	}()

	log.Println("etw: windows network watcher running in placeholder mode")
	return nil
}
