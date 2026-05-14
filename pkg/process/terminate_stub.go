//go:build !windows

package process

import "fmt"

func TerminateProcess(pid uint32) error {
	fmt.Printf("[🛡️ MOCK DEFENSE] Terminated malicious PID: %d\n", pid)
	return nil
}
