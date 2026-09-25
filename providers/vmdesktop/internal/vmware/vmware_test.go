package vmware

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- vmx

func testSpec(dir string) VMSpec {
	return VMSpec{
		Name: "cs-dev-bastion", Dir: dir, GuestOSID: "arm-ubuntu-64", Firmware: "efi", CPUs: 2, MemoryMB: 2048,
		DiskFile: filepath.Join(dir, "disk.vmdk"), CidataISO: filepath.Join(dir, "cidata.iso"),
		NICs:     []NIC{{Type: "nat", MAC: "00:50:56:01:02:03"}, {Type: "custom", Vmnet: "vmnet1", MAC: "00:50:56:0a:0b:0c"}},
		UserData: "#cloud-config\nhostname: b\n", MetaData: "instance-id: b\n", NetworkConfig: "version: 2\n",
	}
}

func TestRenderParsesBack(t *testing.T) {
	dir := t.TempDir()
	spec := testSpec(dir)
	vmx := filepath.Join(dir, "b.vmx")
	if err := os.WriteFile(vmx, []byte(spec.Render()), 0o644); err != nil {
		t.Fatal(err)
	}
	kv, err := ParseVMX(vmx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"displayName": "cs-dev-bastion", "guestOS": "arm-ubuntu-64", "firmware": "efi", "numvcpus": "2", "memsize": "2048",
		"virtualHW.version": "21", "nvme0:0.fileName": "disk.vmdk", "sata0:1.fileName": "cidata.iso",
		"ethernet0.connectionType": "nat", "ethernet0.address": "00:50:56:01:02:03", "ethernet0.addressType": "static",
		"ethernet1.connectionType": "custom", "ethernet1.vnet": "vmnet1", "ethernet1.address": "00:50:56:0a:0b:0c",
		"ethernet0.pciSlotNumber": "160", "ethernet1.pciSlotNumber": "192", "guestinfo.userdata.encoding": "base64",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("%s = %q, want %q", k, kv[k], v)
		}
	}
	if ud, _ := base64.StdEncoding.DecodeString(kv["guestinfo.userdata"]); string(ud) != spec.UserData {
		t.Errorf("guestinfo.userdata decodes to %q", ud)
	}
	meta, _ := base64.StdEncoding.DecodeString(kv["guestinfo.metadata"])
	if !strings.Contains(string(meta), "instance-id: b\n") || !strings.Contains(string(meta), "network.encoding: base64") {
		t.Errorf("guestinfo.metadata lacks the network config: %q", meta)
	}
	// no seed ISO: no SATA controller at all
	spec.CidataISO = ""
	if strings.Contains(spec.Render(), "sata0") {
		t.Error("sata0 rendered without a seed ISO")
	}
}

func TestSetVMXKeysReplacesInPlaceAndAppends(t *testing.T) {
	vmx := filepath.Join(t.TempDir(), "x.vmx")
	orig := ".encoding = \"UTF-8\"\nnumvcpus = \"2\"\nmemsize = \"2048\"\n# a comment\n"
	if err := os.WriteFile(vmx, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetVMXKeys(vmx, map[string]string{"numvcpus": "4", "tools.syncTime": "TRUE"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(vmx)
	text := string(data)
	if strings.Count(text, "numvcpus") != 1 || !strings.Contains(text, `numvcpus = "4"`) {
		t.Errorf("numvcpus not replaced exactly once:\n%s", text)
	}
	if !strings.Contains(text, `memsize = "2048"`) || !strings.Contains(text, "# a comment") {
		t.Errorf("other lines changed:\n%s", text)
	}
	kv, _ := ParseVMX(vmx)
	if kv["tools.syncTime"] != "TRUE" {
		t.Errorf("new key not appended:\n%s", text)
	}
}

// (the YAML, JSON and existing-key cases are in iso_test.go)
func TestGuestinfoMetadataLeavesUnparsableJSONAlone(t *testing.T) {
	if got := GuestinfoMetadata(`{broken`, "version: 2\n"); got != `{broken` {
		t.Errorf("invalid json must be left alone: %q", got)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(GuestinfoMetadata(`{"instance-id": "a", "network": "x"}`, "version: 2\n")), &m); err != nil || m["network"] != "x" {
		t.Errorf("a json network key must be kept: %v %v", m, err)
	}
}

func TestRandomMAC(t *testing.T) {
	re := regexp.MustCompile(`^00:50:56:[0-3][0-9a-f]:[0-9a-f]{2}:[0-9a-f]{2}$`)
	for i := 0; i < 50; i++ {
		mac, err := RandomMAC()
		if err != nil || !re.MatchString(mac) {
			t.Fatalf("RandomMAC() = %q, %v: not in VMware's static range 00:50:56:00-3f", mac, err)
		}
	}
}

// ---------------------------------------------------------------- DHCP leases

func TestLeaseIP(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "vmnet8.leases"), filepath.Join(dir, "vmnet1.leases")
	os.WriteFile(a, []byte(`lease 172.16.5.10 {
	starts 4 2026/09/24 10:00:00;
	hardware ethernet 00:50:56:01:02:03;
}
lease 172.16.5.11 {
	hardware ethernet 00:50:56:aa:bb:cc;
}
lease 172.16.5.12 {
	hardware ethernet 00:50:56:01:02:03;
}
`), 0o644)
	os.WriteFile(b, []byte("lease 192.168.160.130 {\n\thardware ethernet 00:50:56:0a:0b:0c;\n}\n"), 0o644)
	h := &Host{LeaseFiles: []string{filepath.Join(dir, "missing.leases"), a, b}}
	cases := map[string]string{
		"00:50:56:01:02:03": "172.16.5.12", // the file is append-only: the last lease wins
		"00:50:56:AA:BB:CC": "172.16.5.11", // case-insensitive
		"00:50:56:0a:0b:0c": "192.168.160.130",
		"00:50:56:3f:3f:3f": "",
	}
	for mac, want := range cases {
		if got := h.LeaseIP(mac); got != want {
			t.Errorf("LeaseIP(%s) = %q, want %q", mac, got, want)
		}
	}
}

// ---------------------------------------------------------------- host detection and the VMware tools

func TestDetectHonoursVMWAREHOME(t *testing.T) {
	dir := fakeTools(t)
	h, err := Detect("", "")
	if err != nil {
		t.Fatal(err)
	}
	if h.VmrunPath != filepath.Join(dir, "vmrun") || h.VdiskPath != filepath.Join(dir, "vmware-vdiskmanager") {
		t.Errorf("tools not taken from VMWARE_HOME: %+v", h)
	}
	if h.Version == "" {
		t.Error("Version must never be empty")
	}
	want := "amd64" // guests match the host's architecture (Apple silicon runs arm64 guests only)
	if runtime.GOARCH == "arm64" {
		want = "arm64"
	}
	if h.GuestArch != want {
		t.Errorf("GuestArch = %s on %s", h.GuestArch, runtime.GOARCH)
	}
	// an explicit override wins over VMWARE_HOME
	other := filepath.Join(t.TempDir(), "vmrun")
	os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755)
	if h, err := Detect(other, ""); err != nil || h.VmrunPath != other {
		t.Errorf("override ignored: %+v %v", h, err)
	}
	// vmrun without vdiskmanager: a clear error, never a half-detected host
	os.Remove(filepath.Join(dir, "vmware-vdiskmanager"))
	if _, err := Detect("", ""); err == nil || !strings.Contains(err.Error(), "vmware-vdiskmanager") {
		t.Errorf("missing vdiskmanager: %v", err)
	}
	if runtime.GOOS == "darwin" { // an empty VMWARE_HOME must not fall back to the real Fusion
		t.Setenv("VMWARE_HOME", t.TempDir())
		if _, err := Detect("", ""); err == nil || !strings.Contains(err.Error(), "vmrun not found") {
			t.Errorf("empty VMWARE_HOME: %v", err)
		}
	}
}

func TestVmrunReportsVMwareErrors(t *testing.T) {
	dir := fakeTools(t)
	h, err := Detect("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Vmrun("bad", "/x.vmx"); err == nil || err.Error() != "vmrun bad: The file specified is not a virtual machine" {
		t.Errorf("error = %v", err)
	}
	log := fakeLog(t, dir)
	want := "vmrun -T " + map[bool]string{true: "fusion", false: "ws"}[runtime.GOOS == "darwin"] + " bad /x.vmx"
	if len(log) != 1 || log[0] != want {
		t.Errorf("calls = %q, want %q", log, want)
	}
}

func TestIsRunningComparesResolvedPaths(t *testing.T) {
	dir := fakeTools(t)
	h, _ := Detect("", "")
	vms := t.TempDir()
	vmx := filepath.Join(vms, "a.vmwarevm", "a.vmx")
	os.MkdirAll(filepath.Dir(vmx), 0o755)
	os.WriteFile(vmx, []byte(""), 0o644)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(vms, link); err != nil {
		t.Skip(err)
	}
	real, _ := filepath.EvalSymlinks(vmx)
	os.WriteFile(filepath.Join(dir, "running"), []byte(real+"\n"), 0o644)
	for _, p := range []string{vmx, filepath.Join(link, "a.vmwarevm", "a.vmx")} {
		if running, err := h.IsRunning(p); err != nil || !running {
			t.Errorf("IsRunning(%s) = %v, %v", p, running, err)
		}
	}
	if running, _ := h.IsRunning(filepath.Join(vms, "b.vmwarevm", "b.vmx")); running {
		t.Error("another VM reported running")
	}
}

func TestVdiskManagerError(t *testing.T) {
	fakeTools(t)
	t.Setenv("FAKE_VDISK_FAIL", "1")
	h, _ := Detect("", "")
	err := h.VdiskManager("-x", "40GB", "/x/disk.vmdk")
	if err == nil || !strings.Contains(err.Error(), "snapshots") || !strings.Contains(err.Error(), "-x 40GB /x/disk.vmdk") {
		t.Errorf("error = %v", err)
	}
}

// ---------------------------------------------------------------- vmrest client

func TestRestSendsCredentialsAndReadsVmnets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "cloudseed" || pass != "Pw1!pw1!" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Accept") != restMime || r.URL.Path != "/api/vmnet" || r.Method != "GET" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"num": 2, "vmnets": [{"name": "vmnet1", "type": "hostOnly", "dhcp": "true", "subnet": "192.168.160.0",
			"mask": "255.255.255.0"}, {"name": "vmnet8", "type": "nat", "dhcp": "true", "subnet": "172.16.128.0", "mask": "255.255.255.0"}]}`)
	}))
	defer srv.Close()
	nets, err := NewRest(srv.URL+"/", "cloudseed", "Pw1!pw1!").ListVmnets()
	if err != nil || len(nets) != 2 || nets[0] != (Vmnet{Name: "vmnet1", Type: "hostOnly", DHCP: "true", Subnet: "192.168.160.0", Mask: "255.255.255.0"}) {
		t.Fatalf("ListVmnets = %+v, %v", nets, err)
	}
	if _, err := NewRest(srv.URL, "cloudseed", "wrong").ListVmnets(); err == nil || !strings.Contains(err.Error(), "rejected the credentials") {
		t.Errorf("401: %v", err)
	}
}

func TestRestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		io.WriteString(w, "busy\n")
	}))
	url := srv.URL
	_, err := NewRest(url, "u", "p").ListVmnets()
	if err == nil || !strings.Contains(err.Error(), "HTTP 503: busy") {
		t.Errorf("5xx: %v", err)
	}
	srv.Close()
	if _, err := NewRest(url, "u", "p").ListVmnets(); err == nil || !strings.Contains(err.Error(), "is `vmrest` running?") {
		t.Errorf("no answer: %v", err)
	}
	if r := NewRest("", "u", "p"); r.URL != "http://127.0.0.1:8697" {
		t.Errorf("default URL = %s", r.URL)
	}
}

func TestCreateVmnetRequest(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/vmnets" || r.Header.Get("Content-Type") != restMime {
			w.WriteHeader(400)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, "{}") // some vmrest versions answer without the network
	}))
	defer srv.Close()
	n, err := NewRest(srv.URL, "u", "p").CreateVmnet("vmnet2", "hostOnly", "10.123.0.0", "255.255.255.0", false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"name": "vmnet2", "type": "hostOnly", "subnet": "10.123.0.0", "mask": "255.255.255.0", "dhcp": "false"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("request %s = %q, want %q", k, got[k], v)
		}
	}
	if *n != (Vmnet{Name: "vmnet2", Type: "hostOnly", Subnet: "10.123.0.0", Mask: "255.255.255.0", DHCP: "false"}) {
		t.Errorf("result = %+v", *n)
	}
}
