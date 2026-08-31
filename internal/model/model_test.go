package model

import "testing"

func TestTerminalStatuses(t *testing.T) {
	terminal := []string{PolicyRejected, Denied, Expired, Succeeded, Failed, Cancelled}
	for _, current := range terminal {
		if !Terminal(current) {
			t.Fatalf("%s should be terminal", current)
		}
	}
	for _, current := range []string{Created, Queued, Synced, Waiting, Approved, Executing, "UNKNOWN"} {
		if Terminal(current) {
			t.Fatalf("%s should not be terminal", current)
		}
	}
}
