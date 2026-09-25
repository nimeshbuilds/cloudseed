package vmware

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// NIC is one virtual network adapter.
type NIC struct {
	Type  string // nat | hostonly | bridged | custom
	Vmnet string // for custom
	MAC   string
}

// VMSpec is everything needed to write a .vmx.
type VMSpec struct {
	Name          string
	Dir           string // <path>/<name>.vmwarevm
	GuestOSID     string
	Firmware      string
	CPUs          int64
	MemoryMB      int64
	DiskFile      string
	CidataISO     string
	NICs          []NIC
	UserData      string
	MetaData      string
	NetworkConfig string
	HWVersion     int
}

// RandomMAC returns a VMware static MAC (00:50:56:00-3f:xx:xx).
func RandomMAC() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("00:50:56:%02x:%02x:%02x", b[0]&0x3f, b[1], b[2]), nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Render produces the vmx contents.
func (s *VMSpec) Render() string {
	hw := s.HWVersion
	if hw == 0 {
		hw = 21
	}
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s = \"%s\"\n", k, v) }
	w(".encoding", "UTF-8")
	w("config.version", "8")
	w("virtualHW.version", fmt.Sprint(hw))
	w("displayName", s.Name)
	w("guestOS", s.GuestOSID)
	w("firmware", s.Firmware)
	w("memsize", fmt.Sprint(s.MemoryMB))
	w("numvcpus", fmt.Sprint(s.CPUs))
	w("cpuid.coresPerSocket", "1")
	w("nvram", s.Name+".nvram")
	w("extendedConfigFile", s.Name+".vmxf")
	w("svga.present", "TRUE")
	w("vmci0.present", "TRUE")
	w("hpet0.present", "TRUE")
	// PCIe topology exactly as Fusion/Workstation generate it; explicit slot numbers are required for
	// arm64 guests, otherwise power-on fails with "No PCIe slot available for Ethernet0".
	w("pciBridge0.present", "TRUE")
	w("pciBridge0.pciSlotNumber", "17")
	for i, slot := 4, 21; i <= 7; i, slot = i+1, slot+1 {
		w(fmt.Sprintf("pciBridge%d.present", i), "TRUE")
		w(fmt.Sprintf("pciBridge%d.virtualDev", i), "pcieRootPort")
		w(fmt.Sprintf("pciBridge%d.functions", i), "8")
		w(fmt.Sprintf("pciBridge%d.pciSlotNumber", i), fmt.Sprint(slot))
	}
	w("nvme0.present", "TRUE")
	w("nvme0.pciSlotNumber", "224")
	w("nvme0:0.present", "TRUE")
	w("nvme0:0.fileName", filepath.Base(s.DiskFile))
	if s.CidataISO != "" {
		w("sata0.present", "TRUE")
		w("sata0.pciSlotNumber", "32")
		w("sata0:1.present", "TRUE")
		w("sata0:1.deviceType", "cdrom-image")
		w("sata0:1.fileName", filepath.Base(s.CidataISO))
		w("sata0:1.startConnected", "TRUE")
	}
	nicSlots := []string{"160", "192", "256", "1184", "1216", "1248"}
	for i, n := range s.NICs {
		p := fmt.Sprintf("ethernet%d", i)
		w(p+".present", "TRUE")
		w(p+".virtualDev", "vmxnet3")
		if i < len(nicSlots) {
			w(p+".pciSlotNumber", nicSlots[i])
		}
		switch n.Type {
		case "custom":
			w(p+".connectionType", "custom")
			w(p+".vnet", n.Vmnet)
		case "hostonly":
			w(p+".connectionType", "hostonly")
		case "bridged":
			w(p+".connectionType", "bridged")
		default:
			w(p+".connectionType", "nat")
		}
		w(p+".addressType", "static")
		w(p+".address", n.MAC)
		w(p+".startConnected", "TRUE")
	}
	// cloud-init VMware datasource (guestinfo) - works alongside the NoCloud ISO. Its only source of network config is a
	// `network` key inside the metadata, so the static addressing is carried there too (images whose cloud-init picks
	// the VMware datasource would otherwise fall back to DHCP on one NIC).
	if s.UserData != "" {
		w("guestinfo.userdata", b64(s.UserData))
		w("guestinfo.userdata.encoding", "base64")
	}
	if meta := GuestinfoMetadata(s.MetaData, s.NetworkConfig); meta != "" {
		w("guestinfo.metadata", b64(meta))
		w("guestinfo.metadata.encoding", "base64")
	}
	w("tools.syncTime", "TRUE")
	w("tools.upgrade.policy", "manual")
	w("uuid.action", "create")
	w("msg.autoAnswer", "TRUE")
	return b.String()
}

var vmxLine = regexp.MustCompile(`^\s*([^=\s]+)\s*=\s*"(.*)"\s*$`)

// ParseVMX reads key/value pairs. Lines can be long: guestinfo.userdata is the whole base64 user-data on one line.
func ParseVMX(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		if m := vmxLine.FindStringSubmatch(sc.Text()); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out, sc.Err()
}

// SetVMXKeys rewrites selected keys in place.
func SetVMXKeys(path string, kv map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		if m := vmxLine.FindStringSubmatch(line); m != nil {
			if v, ok := kv[m[1]]; ok {
				lines[i] = fmt.Sprintf("%s = \"%s\"", m[1], v)
				seen[m[1]] = true
			}
		}
	}
	for k, v := range kv {
		if !seen[k] {
			lines = append(lines, fmt.Sprintf("%s = \"%s\"", k, v))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

// GuestinfoMetadata is the metadata for the guestinfo transport: the NoCloud meta-data plus, when there is a network
// config, the `network` / `network.encoding` keys cloud-init's VMware datasource reads it from. Metadata that already
// has a top-level network key is left alone; JSON metadata gets the keys added as JSON.
func GuestinfoMetadata(metaData, networkConfig string) string {
	if networkConfig == "" {
		return metaData
	}
	trimmed := strings.TrimSpace(metaData)
	if strings.HasPrefix(trimmed, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
			return metaData
		}
		if _, ok := m["network"]; ok {
			return metaData
		}
		m["network"] = b64(networkConfig)
		m["network.encoding"] = "base64"
		out, err := json.Marshal(m)
		if err != nil {
			return metaData
		}
		return string(out)
	}
	if networkKey.MatchString(metaData) {
		return metaData
	}
	if metaData != "" && !strings.HasSuffix(metaData, "\n") {
		metaData += "\n"
	}
	return metaData + "network: " + b64(networkConfig) + "\nnetwork.encoding: base64\n"
}

var networkKey = regexp.MustCompile(`(?m)^network(\.encoding)?\s*:`)

// MakeCidata builds the NoCloud seed ISO (volume label cidata: user-data, meta-data and network-config) and returns its
// path. The host's ISO tool is used when there is one (hdiutil, genisoimage, mkisofs, xorriso); otherwise the built-in
// ISO 9660 writer, so hosts without any of them (Windows, minimal Linux) still get a seed. The seed matters: images
// without open-vm-tools (Debian) cannot read guestinfo at all.
func MakeCidata(dir, userData, metaData, networkConfig string) (string, error) {
	seed := filepath.Join(dir, "cidata")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		return "", err
	}
	files := map[string]string{"user-data": userData, "meta-data": metaData}
	if networkConfig != "" {
		files["network-config"] = networkConfig
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(content), 0o600); err != nil {
			return "", err
		}
	}
	iso := filepath.Join(dir, "cidata.iso")
	_ = os.Remove(iso)
	var cmd *exec.Cmd
	switch {
	case lookPath("hdiutil"):
		cmd = exec.Command("hdiutil", "makehybrid", "-quiet", "-iso", "-joliet", "-default-volume-name", "cidata", "-o", iso, seed)
	case lookPath("genisoimage"):
		cmd = exec.Command("genisoimage", "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock", seed)
	case lookPath("mkisofs"):
		cmd = exec.Command("mkisofs", "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock", seed)
	case lookPath("xorriso"):
		cmd = exec.Command("xorriso", "-as", "mkisofs", "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock", seed)
	default:
		data := map[string][]byte{}
		for name, content := range files {
			data[name] = []byte(content)
		}
		if err := WriteISO9660(iso, "cidata", data); err != nil {
			return "", fmt.Errorf("building cidata.iso: %v", err)
		}
		return iso, nil
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building cidata.iso: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return iso, nil
}

func lookPath(name string) bool { _, err := exec.LookPath(name); return err == nil }
