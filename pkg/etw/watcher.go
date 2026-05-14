//go:build windows

package etw

import (
	"log"

	bietw "github.com/bi-zone/etw"
)

// StartWatching connects to the ETW provider and invokes callback for each process event.
func StartWatching(callback func(ProcessInfo)) error {
	go func() {
		consumer, err := bietw.NewConsumer()
		if err != nil {
			log.Printf("etw: failed to create consumer: %v", err)
			return
		}
		defer consumer.Close()

		providerGUID := "2273A10F-DB27-46C1-8E09-EFCEB44D0F8E"

		if err := consumer.EnableProvider(providerGUID); err != nil {
			log.Printf("etw: enable provider failed: %v", err)
			return
		}

		events := consumer.Events()
		for ev := range events {
			if ev.EventID != 1 {
				continue
			}

			var pi ProcessInfo

			if v, ok := ev.Fields["ProcessId"].(uint32); ok {
				pi.ProcessID = v
			} else if v, ok := ev.Fields["ProcessID"].(uint32); ok {
				pi.ProcessID = v
			}

			if v, ok := ev.Fields["ParentProcessId"].(uint32); ok {
				pi.ParentProcessID = v
			} else if v, ok := ev.Fields["ParentProcessID"].(uint32); ok {
				pi.ParentProcessID = v
			}

			if v, ok := ev.Fields["ImageName"].(string); ok {
				pi.ImageName = v
			} else if v, ok := ev.Fields["ImagePath"].(string); ok {
				pi.ImageName = v
			}

			if v, ok := ev.Fields["CommandLine"].(string); ok {
				pi.CommandLine = v
			}

			callback(pi)
		}
	}()

	return nil
}
