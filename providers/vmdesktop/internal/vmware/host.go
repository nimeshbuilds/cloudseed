package vmware

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Host describes the local VMware Desktop installation.
type Host struct {
	Product    string // fusion | workstation
	Version    string
	OS         string
	Arch       string // host arch: arm64 | amd64
	GuestArch  string // guests this host can run: arm64 | amd64
	VmrunPath  string
	VdiskPath  string
	VmrestPath string
	LeaseFiles []string
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func first(paths ...string) string {
	for _, p := range paths {
		if p != "" && exists(p) {
			return p
		}
	}
	return ""
}

// Detect finds vmrun & friends. Overrides (from provider config) win; VMWARE_HOME is honoured.
func Detect(vmrunOverride, vdiskOverride string) (*Host, error) {
	h := &Host{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h.Arch == "arm64" {
		h.GuestArch = "arm64"
	} else {
		h.GuestArch = "amd64"
	}
	home := os.Getenv("VMWARE_HOME")
	switch runtime.GOOS {
	case "darwin":
		base := first(home, "/Applications/VMware Fusion.app/Contents/Library") // VMWARE_HOME when that directory exists
		h.Product = "fusion"
		h.VmrunPath = first(vmrunOverride, filepath.Join(base, "vmrun"))
		h.VdiskPath = first(vdiskOverride, filepath.Join(base, "vmware-vdiskmanager"))
		h.VmrestPath = first(filepath.Join(base, "vmrest"))
		h.LeaseFiles = []string{"/var/db/vmware/vmnet-dhcpd-vmnet8.leases", "/var/db/vmware/vmnet-dhcpd-vmnet1.leases"}
		if plist := filepath.Join(filepath.Dir(base), "Info.plist"); exists(plist) { // <app>/Contents/Library -> Contents/Info.plist
			if out, err := exec.Command("defaults", "read", plist, "CFBundleShortVersionString").Output(); err == nil {
				h.Version = strings.TrimSpace(string(out))
			}
		}
	case "linux":
		h.Product = "workstation"
		in := func(name string) string { // never a bare relative name when VMWARE_HOME is unset
			if home == "" {
				return ""
			}
			return filepath.Join(home, name)
		}
		h.VmrunPath = first(vmrunOverride, in("vmrun"), "/usr/bin/vmrun")
		h.VdiskPath = first(vdiskOverride, in("vmware-vdiskmanager"), "/usr/bin/vmware-vdiskmanager")
		h.VmrestPath = first(in("vmrest"), "/usr/bin/vmrest")
		h.LeaseFiles = []string{"/etc/vmware/vmnet8/dhcpd/dhcpd.leases", "/etc/vmware/vmnet1/dhcpd/dhcpd.leases"}
		if out, err := exec.Command("vmware", "-v").Output(); err == nil {
			h.Version = strings.TrimSpace(string(out))
		}
	case "windows":
		h.Product = "workstation"
		base := first(home, `C:\Program Files (x86)\VMware\VMware Workstation`, `C:\Program Files\VMware\VMware Workstation`)
		h.VmrunPath = first(vmrunOverride, filepath.Join(base, "vmrun.exe"))
		h.VdiskPath = first(vdiskOverride, filepath.Join(base, "vmware-vdiskmanager.exe"))
		h.VmrestPath = first(filepath.Join(base, "vmrest.exe"))
		h.LeaseFiles = []string{`C:\ProgramData\VMware\vmnetdhcp.leases`}
		h.Version = windowsWorkstationVersion()
	default:
		return nil, fmt.Errorf("unsupported host OS %s", runtime.GOOS)
	}
	if h.VmrunPath == "" {
		return nil, fmt.Errorf("vmrun not found: install VMware Fusion Pro (macOS) or Workstation Pro (Linux/Windows), or set VMWARE_HOME")
	}
	if h.VdiskPath == "" {
		return nil, fmt.Errorf("vmware-vdiskmanager not found next to vmrun (%s)", h.VmrunPath)
	}
	if h.Version == "" {
		h.Version = "unknown"
	}
	return h, nil
}

// workstationRegKeys is where Workstation's installer records its version on Windows (the 32-bit registry view of a
// 64-bit Windows first, then the native one); cloudseed's CLI (localvm.detect_host) reads the same values.
var workstationRegKeys = []string{`HKLM\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation`, `HKLM\SOFTWARE\VMware, Inc.\VMware Workstation`}

var regProductVersionRe = regexp.MustCompile(`(?m)^[ \t]*ProductVersion[ \t]+REG_\w+[ \t]+(\S[^\r\n]*?)[ \t]*\r?$`)

// parseRegProductVersion reads the ProductVersion value out of `reg query <key> /v ProductVersion` output.
func parseRegProductVersion(out string) string {
	if m := regProductVersionRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// windowsWorkstationVersion is Workstation's version ("17.5.2.23775571"), or "" when the registry does not say.
func windowsWorkstationVersion() string {
	for _, key := range workstationRegKeys {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, "reg", "query", key, "/v", "ProductVersion").Output()
		cancel()
		if err != nil {
			continue
		}
		if v := parseRegProductVersion(string(out)); v != "" {
			return v
		}
	}
	return ""
}

var versionRe = regexp.MustCompile(`(\d+)(?:\.(\d+))?`)

// HWVersion is the virtual hardware version the VMs get: the newest this release runs that the generated vmx needs.
// Fusion 13.5+ / Workstation 17.5+ (and later numbering such as 25H2) run 21, Fusion 13.0-13.4 / Workstation 17.0.x
// only 20; cloudseed refuses anything older before it creates a VM. An unknown version gets 21.
func (h *Host) HWVersion() int {
	m := versionRe.FindStringSubmatch(h.Version)
	if m == nil {
		return 21
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	floor := 13 // Fusion
	if h.Product != "fusion" {
		floor = 17
	}
	if major < floor || (major == floor && minor < 5) {
		return 20
	}
	return 21
}

func (h *Host) hostType() string {
	if h.Product == "fusion" {
		return "fusion"
	}
	return "ws"
}

var errRe = regexp.MustCompile(`(?m)^Error: (.*)$`)

// Vmrun executes vmrun with the right -T flag and returns stdout. Calls are bounded (vmrun can block on a
// guest dialog); a bounded `start` that leaves the VM running is treated as success.
func (h *Host) Vmrun(args ...string) (string, error) {
	timeout := 5 * time.Minute
	if len(args) > 0 && args[0] == "start" {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.VmrunPath, append([]string{"-T", h.hostType()}, args...)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded && len(args) > 1 && args[0] == "start" {
		if running, _ := h.IsRunning(args[1]); running {
			return "", nil
		}
		return string(out), fmt.Errorf("vmrun start: timed out after %s", timeout)
	}
	s := strings.TrimSpace(string(out))
	if err != nil {
		if m := errRe.FindStringSubmatch(s); m != nil {
			return s, fmt.Errorf("vmrun %s: %s", args[0], m[1])
		}
		return s, fmt.Errorf("vmrun %s: %v: %s", args[0], err, s)
	}
	return s, nil
}

// VdiskManager executes vmware-vdiskmanager.
func (h *Host) VdiskManager(args ...string) error {
	out, err := exec.Command(h.VdiskPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("vmware-vdiskmanager %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsRunning reports whether the vmx appears in `vmrun list`. vmrun prints absolute paths, so a relative vmx (states
// written by older versions for a relative `path`) and symlinked directories (/tmp -> /private/tmp) are compared by
// their absolute, resolved form.
func (h *Host) IsRunning(vmx string) (bool, error) {
	out, err := h.Vmrun("list")
	if err != nil {
		return false, err
	}
	want := canonicalPath(vmx)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == vmx || canonicalPath(line) == want {
			return true, nil
		}
	}
	return false, nil
}

func canonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return filepath.Clean(p)
}
