package vmware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunningListRejectsMalformedOrTruncatedOutput(t *testing.T) {
	dir := fakeTools(t)
	h, err := Detect("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", "0", "Error: host unavailable", "Total running VMs: 1", "Total running VMs: 0\n/a.vmx"} {
		if err := os.WriteFile(filepath.Join(dir, "vmrun"), []byte("#!/bin/sh\ncat <<'EOF'\n"+output+"\nEOF\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := h.IsRunning("/a.vmx"); err == nil {
			t.Errorf("malformed list %q was trusted", output)
		}
	}
}
