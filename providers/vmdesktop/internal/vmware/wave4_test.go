package vmware

import "testing"

// Windows: Workstation's version comes from the registry (reg query), so HWVersion can tell 17.0.x from 17.5+.
func TestParseRegProductVersion(t *testing.T) {
	out := "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\VMware, Inc.\\VMware Workstation\r\n" +
		"    ProductVersion    REG_SZ    17.5.2.23775571\r\n\r\n"
	if got := parseRegProductVersion(out); got != "17.5.2.23775571" {
		t.Fatalf("parseRegProductVersion = %q", got)
	}
	if got := (&Host{Product: "workstation", Version: parseRegProductVersion(out)}).HWVersion(); got != 21 {
		t.Errorf("17.5.2: hardware version %d, want 21", got)
	}
	old := "HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Workstation\n    ProductVersion    REG_SZ    17.0.2.21581411\n"
	if got := (&Host{Product: "workstation", Version: parseRegProductVersion(old)}).HWVersion(); got != 20 {
		t.Errorf("17.0.2: hardware version %d, want 20", got)
	}
	for _, none := range []string{"", "ERROR: The system was unable to find the specified registry key or value.\r\n",
		"    InstallPath    REG_SZ    C:\\Program Files (x86)\\VMware\\VMware Workstation\\\r\n",
		"    ProductVersion    REG_SZ    \r\n    InstallPath    REG_SZ    C:\\VMware\r\n"} {
		if got := parseRegProductVersion(none); got != "" {
			t.Errorf("parseRegProductVersion(%q) = %q, want empty", none, got)
		}
	}
}
