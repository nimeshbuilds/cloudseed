package vmware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVMXReadsLongLines(t *testing.T) {
	// guestinfo.userdata holds the whole base64 user-data on one line: well past bufio.Scanner's 64 KiB default
	s := VMSpec{Name: "vm", Dir: t.TempDir(), GuestOSID: "ubuntu-64", Firmware: "efi", CPUs: 2, MemoryMB: 2048,
		DiskFile: "disk.vmdk", UserData: "#cloud-config\n" + strings.Repeat("x", 200*1024)}
	vmx := filepath.Join(s.Dir, "vm.vmx")
	if err := os.WriteFile(vmx, []byte(s.Render()), 0o644); err != nil {
		t.Fatal(err)
	}
	kv, err := ParseVMX(vmx)
	if err != nil || kv["numvcpus"] != "2" || kv["guestinfo.userdata"] == "" {
		t.Fatalf("ParseVMX: %v (numvcpus=%q)", err, kv["numvcpus"])
	}
}

func TestHWVersionFollowsTheRelease(t *testing.T) {
	cases := []struct {
		product, version string
		want             int
	}{
		{"fusion", "13.6.4", 21}, {"fusion", "13.5.0", 21}, {"fusion", "13.0.2", 20}, {"fusion", "13.1", 20},
		{"fusion", "12.2.5", 20}, {"fusion", "25H2", 21}, {"fusion", "unknown", 21}, {"fusion", "", 21},
		{"workstation", "VMware Workstation 17.5.2 build-23775571", 21}, {"workstation", "VMware Workstation 17.0.2 build-1", 20},
		{"workstation", "VMware Workstation 25H2 build-2", 21}, {"workstation", "unknown", 21},
	}
	for _, c := range cases {
		if got := (&Host{Product: c.product, Version: c.version}).HWVersion(); got != c.want {
			t.Errorf("%s %q: hardware version %d, want %d", c.product, c.version, got, c.want)
		}
	}
	if !strings.Contains((&VMSpec{HWVersion: 20}).Render(), "virtualHW.version = \"20\"") {
		t.Error("Render ignores HWVersion")
	}
}
