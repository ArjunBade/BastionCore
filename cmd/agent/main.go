//go:build windows
// +build windows

package main

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// getProcessMap returns a map of PID to process name by taking a snapshot
// of all running processes using the Windows ToolHelp32 API
func getProcessMap() (map[uint32]string, error) {
	processes := make(map[uint32]string)

	// Create a snapshot of all processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	// Initialize process entry structure
	pe := &windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}

	// Get the first process in the snapshot
	if err := windows.Process32First(snapshot, pe); err != nil {
		return nil, fmt.Errorf("failed to get first process: %w", err)
	}

	// Add the first process to our map
	processes[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])

	// Iterate through all remaining processes
	for {
		if err := windows.Process32Next(snapshot, pe); err != nil {
			// ERROR_NO_MORE_FILES indicates we've reached the end of the snapshot
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("failed to get next process: %w", err)
		}
		processes[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
	}

	return processes, nil
}

func main() {
	fmt.Println("=== EDR Agent Started - Process Monitoring ===")

	var previousProcesses map[uint32]string
	isFirstRun := true

	// Create a ticker that fires every 1 second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Get current list of running processes
		currentProcesses, err := getProcessMap()
		if err != nil {
			fmt.Printf("Error getting process map: %v\n", err)
			continue
		}

		// On first iteration, just populate the baseline without alerting
		if isFirstRun {
			previousProcesses = currentProcesses
			fmt.Printf("[*] Initial baseline established: %d processes\n", len(previousProcesses))
			isFirstRun = false
			continue
		}

		// Compare current processes against previous snapshot
		// Look for processes that exist now but didn't exist before
		for pid, name := range currentProcesses {
			if _, existed := previousProcesses[pid]; !existed {
				fmt.Printf("[+] New process detected: %s (PID: %d)\n", name, pid)
			}
		}

		// Update the baseline for the next iteration
		previousProcesses = currentProcesses
	}
}
