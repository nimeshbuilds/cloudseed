package provider

// Acceptance-style tests without Terraform: the resources' Create/Read/Update/Delete run in process against fake
// VMware tools (shell scripts in VMWARE_HOME that log their calls) and a fake vmrest (httptest). No real VMware,
// vmrest or VM is ever touched.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/cloudseed/terraform-provider-vmdesktop/internal/vmware"
)

const fakeVmrun = `#!/bin/sh
echo "vmrun $*" >> "$FAKE_LOG"
shift 2
case "$1" in
list)
  if [ -n "$FAKE_LIST_FAIL" ]; then echo "Error: Unable to connect to host"; exit 255; fi
  n=0; lines=""
  if [ -f "$FAKE_DIR/running" ]; then
    while IFS= read -r l; do [ -n "$l" ] && { n=$((n+1)); lines="$lines$l
"; }; done < "$FAKE_DIR/running"
  fi
  echo "Total running VMs: $n"; printf '%s' "$lines" ;;
start)
  if [ -n "$FAKE_START_FAIL" ]; then echo "Error: Cannot start VM"; exit 1; fi
  printf '%s\n' "$2" >> "$FAKE_DIR/running" ;;
stop)
  if [ -n "$FAKE_STOP_FAIL" ]; then echo "Error: Cannot stop VM"; exit 1; fi
  if [ -n "$FAKE_STOP_NOOP" ]; then exit 0; fi
  new=""
  if [ -f "$FAKE_DIR/running" ]; then
    while IFS= read -r l; do [ "$l" = "$2" ] || new="$new$l
"; done < "$FAKE_DIR/running"
  fi
  printf '%s' "$new" > "$FAKE_DIR/running" ;;
deleteVM)
  if [ -n "$FAKE_DELETE_FAIL" ]; then echo "Error: Cannot delete VM"; exit 1; fi
  if [ -n "$FAKE_DELETE_REMOVE_VMX" ]; then rm "$2"; fi ;;
getGuestIPAddress) echo "10.0.0.9" ;;
esac
exit 0
`

const fakeVdisk = `#!/bin/sh
echo "vdisk $*" >> "$FAKE_LOG"
case "$1" in
-r) cp "$2" "$5" ;;
-x)
  if [ -n "$FAKE_VDISK_FAIL" ]; then echo "Failed to expand the disk: the virtual disk has snapshots"; exit 1; fi
  capacity=$((${2%GB} * 2097152)); bytes=""
  for shift in 0 8 16 24 32 40 48 56; do
    bytes="$bytes$(printf '\\%03o' $(((capacity >> shift) & 255)))"
  done
  printf '%b' "$bytes" | dd of="$3" bs=1 seek=12 conv=notrunc 2>/dev/null ;;
esac
exit 0
`

// fakeVmrest serves the two endpoints the provider uses; vmnets can be changed between calls.
type fakeVmrest struct {
	mu      sync.Mutex
	vmnets  []vmware.Vmnet
	created []map[string]string
}

func (f *fakeVmrest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "cloudseed" || p != "Pw1!pw1!" {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/vmnet":
		json.NewEncoder(w).Encode(map[string]any{"num": len(f.vmnets), "vmnets": f.vmnets})
	case r.Method == "POST" && r.URL.Path == "/api/vmnets":
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		f.created = append(f.created, body)
		n := vmware.Vmnet{Name: body["name"], Type: body["type"], DHCP: body["dhcp"], Subnet: body["subnet"], Mask: body["mask"]}
		f.vmnets = append(f.vmnets, n)
		json.NewEncoder(w).Encode(n)
	default:
		w.WriteHeader(404)
		io.WriteString(w, "not found")
	}
}

type harness struct {
	dir    string
	client *Client
	rest   *fakeVmrest
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fakes")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"vmrun": fakeVmrun, "vmware-vdiskmanager": fakeVdisk} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VMWARE_HOME", dir)
	t.Setenv("FAKE_DIR", dir)
	t.Setenv("FAKE_LOG", filepath.Join(dir, "calls.log"))
	t.Setenv("FAKE_VDISK_FAIL", "")
	t.Setenv("FAKE_LIST_FAIL", "")
	for _, key := range []string{"FAKE_START_FAIL", "FAKE_STOP_FAIL", "FAKE_STOP_NOOP", "FAKE_DELETE_FAIL", "FAKE_DELETE_REMOVE_VMX"} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/bin") // no ISO tool: the built-in writer makes the seed
	host, err := vmware.Detect("", "")
	if err != nil {
		t.Fatal(err)
	}
	host.LeaseFiles = []string{filepath.Join(dir, "none.leases")} // never the host's real DHCP leases
	rest := &fakeVmrest{vmnets: []vmware.Vmnet{
		{Name: "vmnet1", Type: "hostOnly", DHCP: "true", Subnet: "192.168.160.0", Mask: "255.255.255.0"},
		{Name: "vmnet8", Type: "nat", DHCP: "true", Subnet: "172.16.128.0", Mask: "255.255.255.0"},
	}}
	srv := httptest.NewServer(rest)
	t.Cleanup(srv.Close)
	return &harness{dir: dir, rest: rest, client: &Client{Host: host, Rest: vmware.NewRest(srv.URL, "cloudseed", "Pw1!pw1!")}}
}

func (h *harness) calls(t *testing.T) []string {
	data, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
	os.Remove(filepath.Join(h.dir, "calls.log"))
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func hasCall(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func schemaOf(t *testing.T, r resource.Resource) tfsdk.State {
	t.Helper()
	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	return tfsdk.State{Schema: resp.Schema, Raw: tftypes.NewValue(resp.Schema.Type().TerraformType(context.Background()), nil)}
}

func planFrom(t *testing.T, empty tfsdk.State, model any) tfsdk.Plan {
	t.Helper()
	p := tfsdk.Plan{Schema: empty.Schema, Raw: empty.Raw}
	if d := p.Set(context.Background(), model); d.HasError() {
		t.Fatal(d)
	}
	return p
}

func stateFrom(t *testing.T, empty tfsdk.State, model any) tfsdk.State {
	t.Helper()
	s := empty
	if d := s.Set(context.Background(), model); d.HasError() {
		t.Fatal(d)
	}
	return s
}

func noErrors(t *testing.T, what string, d diag.Diagnostics) {
	t.Helper()
	if d.HasError() {
		t.Fatalf("%s: %v", what, d)
	}
}

func warned(d diag.Diagnostics, summary string) bool {
	for _, w := range d.Warnings() {
		if w.Summary() == summary {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- vmdesktop_network

func netPlan(subnet string) networkModel {
	return networkModel{ID: types.StringUnknown(), Name: types.StringUnknown(), Type: types.StringValue("hostonly"),
		Subnet: types.StringValue(subnet), DHCP: types.BoolUnknown(), Mask: types.StringUnknown(), Adopted: types.BoolUnknown()}
}

func createNetwork(t *testing.T, h *harness, subnet string) (networkModel, *resource.CreateResponse) {
	t.Helper()
	r := &networkResource{client: h.client}
	empty := schemaOf(t, r)
	resp := &resource.CreateResponse{State: empty}
	r.Create(context.Background(), resource.CreateRequest{Plan: planFrom(t, empty, netPlan(subnet))}, resp)
	var got networkModel
	if !resp.Diagnostics.HasError() {
		noErrors(t, "get", resp.State.Get(context.Background(), &got))
	}
	return got, resp
}

func TestNetworkAdoptsTheBuiltinHostOnlyNetwork(t *testing.T) {
	h := newHarness(t)
	got, resp := createNetwork(t, h, "192.168.160.0/24")
	noErrors(t, "create", resp.Diagnostics)
	if got.Name.ValueString() != "vmnet1" || !got.Adopted.ValueBool() || !got.DHCP.ValueBool() || got.Mask.ValueString() != "255.255.255.0" {
		t.Errorf("state = %+v", got)
	}
	if !warned(resp.Diagnostics, "adopted existing vmnet") || len(h.rest.created) != 0 {
		t.Errorf("adopting must warn and create nothing: %v %v", resp.Diagnostics, h.rest.created)
	}
}

func TestNetworkOverlappingTheNATNetworkIsRefused(t *testing.T) {
	h := newHarness(t)
	_, resp := createNetwork(t, h, "172.16.128.0/25")
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "vmnet8") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	if len(h.rest.created) != 0 {
		t.Errorf("created %v", h.rest.created)
	}
}

func TestNetworkCreatesAFreeVmnetAndDestroyKeepsIt(t *testing.T) {
	h := newHarness(t)
	got, resp := createNetwork(t, h, "10.123.0.0/24")
	noErrors(t, "create", resp.Diagnostics)
	if len(h.rest.created) != 1 || h.rest.created[0]["name"] != "vmnet2" || h.rest.created[0]["dhcp"] != "false" ||
		h.rest.created[0]["subnet"] != "10.123.0.0" || h.rest.created[0]["type"] != "hostOnly" {
		t.Fatalf("POST /api/vmnets = %v", h.rest.created)
	}
	if got.Name.ValueString() != "vmnet2" || got.Adopted.ValueBool() || got.DHCP.ValueBool() {
		t.Errorf("state = %+v", got)
	}
	r := &networkResource{client: h.client}
	del := &resource.DeleteResponse{}
	r.Delete(context.Background(), resource.DeleteRequest{State: stateFrom(t, schemaOf(t, r), got)}, del)
	if del.Diagnostics.HasError() || !warned(del.Diagnostics, "vmnet kept") {
		t.Errorf("delete: %v", del.Diagnostics)
	}
}

func TestNetworkReadDropsAVanishedVmnet(t *testing.T) {
	h := newHarness(t)
	got, resp := createNetwork(t, h, "10.123.0.0/24")
	noErrors(t, "create", resp.Diagnostics)
	r := &networkResource{client: h.client}
	empty := schemaOf(t, r)
	read := &resource.ReadResponse{State: stateFrom(t, empty, got)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, got)}, read)
	noErrors(t, "read", read.Diagnostics)
	if read.State.Raw.IsNull() {
		t.Fatal("an existing vmnet was removed from state")
	}
	h.rest.mu.Lock()
	h.rest.vmnets = h.rest.vmnets[:2] // vmnet2 deleted outside Terraform
	h.rest.mu.Unlock()
	read = &resource.ReadResponse{State: stateFrom(t, empty, got)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, got)}, read)
	noErrors(t, "read", read.Diagnostics)
	if !read.State.Raw.IsNull() {
		t.Error("a vanished vmnet must leave the state (Terraform then plans to create it)")
	}
}

// ---------------------------------------------------------------- vmdesktop_vm

func vmPlan(h *harness, base string) vmModel {
	u := types.StringUnknown()
	return vmModel{
		ID: u, Name: types.StringValue("cs-dev-vm1"), Path: types.StringValue(filepath.Join(h.dir, "vms")),
		GuestOSID: types.StringValue("ubuntu-64"), Firmware: types.StringValue("efi"), CPUs: types.Int64Value(2),
		MemoryMB: types.Int64Value(2048), DiskGB: types.Int64Value(20), BaseDisk: types.StringValue(base),
		Running: types.BoolValue(true), WaitForIP: types.Int64Value(5),
		Networks: []nicModel{{Type: types.StringValue("nat"), Vmnet: types.StringNull(), MAC: u, IP: u},
			{Type: types.StringValue("custom"), Vmnet: types.StringValue("vmnet1"), MAC: types.StringValue("00:50:56:0a:0b:0c"), IP: u}},
		CloudInit: &cloudInitModel{UserData: types.StringValue("#cloud-config\n"), MetaData: types.StringNull(),
			NetworkConfig: types.StringValue("version: 2\n")},
		VMXPath: u, IP: u, IPs: types.ListUnknown(types.StringType),
	}
}

func writeDisk(t *testing.T, path string, gib int64) {
	t.Helper()
	var header [512]byte
	binary.LittleEndian.PutUint32(header[:4], 0x564d444b)
	binary.LittleEndian.PutUint32(header[4:8], 1)
	binary.LittleEndian.PutUint64(header[12:20], uint64(gib)*(1<<21))
	if err := os.WriteFile(path, header[:], 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVMLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	r := &vmResource{client: h.client}
	empty := schemaOf(t, r)
	base := filepath.Join(h.dir, "base.vmdk")
	writeDisk(t, base, 3)
	plan := vmPlan(h, base)
	leftover := filepath.Join(h.dir, "vms", "cs-dev-vm1.vmwarevm")
	os.MkdirAll(leftover, 0o755)
	os.WriteFile(filepath.Join(leftover, "junk"), []byte("x"), 0o644) // a failed earlier attempt, not in state
	os.WriteFile(filepath.Join(leftover, incompleteMarker), nil, 0o644)

	// create: clone + grow the disk, seed ISO, vmx, start, and the IP the guest reports
	cr := &resource.CreateResponse{State: empty}
	r.Create(ctx, resource.CreateRequest{Plan: planFrom(t, empty, plan)}, cr)
	noErrors(t, "create", cr.Diagnostics)
	var vm vmModel
	noErrors(t, "get", cr.State.Get(ctx, &vm))
	vmx := vm.VMXPath.ValueString()
	calls := h.calls(t)
	for _, want := range []string{"vdisk -r " + base + " -t 0 ", "vdisk -x 20GB ", "vmrun -T "} {
		if !hasCall(calls, want) {
			t.Errorf("create: no %q in %q", want, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(leftover, "junk")); !os.IsNotExist(err) {
		t.Error("leftovers of an earlier attempt were not cleared")
	}
	if _, err := os.Stat(filepath.Join(leftover, "cidata.iso")); err != nil {
		t.Errorf("no seed ISO: %v", err)
	}
	if _, err := os.Stat(filepath.Join(leftover, incompleteMarker)); !os.IsNotExist(err) {
		t.Error("the in-progress marker is still there after a successful create")
	}
	kv, err := vmware.ParseVMX(vmx)
	if err != nil || kv["numvcpus"] != "2" || kv["ethernet1.address"] != "00:50:56:0a:0b:0c" || kv["ethernet1.vnet"] != "vmnet1" {
		t.Fatalf("vmx = %v, %v", kv, err)
	}
	if mac := vm.Networks[0].MAC.ValueString(); !strings.HasPrefix(mac, "00:50:56:") || kv["ethernet0.address"] != mac {
		t.Errorf("generated MAC %q not recorded (vmx has %q)", mac, kv["ethernet0.address"])
	}
	if vm.IP.ValueString() != "10.0.0.9" || !vm.Running.ValueBool() {
		t.Errorf("ip = %q running = %v", vm.IP.ValueString(), vm.Running)
	}

	// read while powered off (after a host reboot): running=false, the VM stays in state
	os.WriteFile(filepath.Join(h.dir, "running"), nil, 0o644)
	rr := &resource.ReadResponse{State: stateFrom(t, empty, vm)}
	r.Read(ctx, resource.ReadRequest{State: stateFrom(t, empty, vm)}, rr)
	noErrors(t, "read", rr.Diagnostics)
	var off vmModel
	noErrors(t, "get", rr.State.Get(ctx, &off))
	if off.Running.ValueBool() || off.VMXPath.ValueString() != vmx {
		t.Errorf("read: running=%v vmx=%s", off.Running, off.VMXPath)
	}

	// update in place: cpus 2 -> 4 and disk 20 -> 30 on a running VM: soft stop, vmx, grow, start
	os.WriteFile(filepath.Join(h.dir, "running"), []byte(vmx+"\n"), 0o644)
	h.calls(t)
	want := vm
	want.CPUs, want.DiskGB = types.Int64Value(4), types.Int64Value(30)
	want.Networks = append([]nicModel(nil), vm.Networks...)
	for i := range want.Networks {
		want.Networks[i].IP = types.StringUnknown()
	}
	want.IP, want.IPs = types.StringUnknown(), types.ListUnknown(types.StringType)
	ur := &resource.UpdateResponse{State: stateFrom(t, empty, vm)}
	r.Update(ctx, resource.UpdateRequest{Plan: planFrom(t, empty, want), State: stateFrom(t, empty, vm)}, ur)
	noErrors(t, "update", ur.Diagnostics)
	calls = h.calls(t)
	for _, c := range []string{"vmrun -T %s stop " + vmx + " soft", "vdisk -x 30GB ", "vmrun -T %s start " + vmx + " nogui"} {
		c = strings.Replace(c, "%s", hostType(), 1)
		if !hasCall(calls, c) {
			t.Errorf("update: no %q in %q", c, calls)
		}
	}
	if kv, _ := vmware.ParseVMX(vmx); kv["numvcpus"] != "4" || kv["memsize"] != "2048" {
		t.Errorf("vmx after update: numvcpus=%s memsize=%s", kv["numvcpus"], kv["memsize"])
	}
	var updated vmModel
	noErrors(t, "get", ur.State.Get(ctx, &updated))
	if updated.DiskGB.ValueInt64() != 30 || updated.ID.ValueString() != vmx || updated.Networks[0].MAC != vm.Networks[0].MAC {
		t.Errorf("state after update: %+v", updated)
	}

	// a grow that VMware refuses (snapshots): an error, the old size recorded, and the VM powered back on
	t.Setenv("FAKE_VDISK_FAIL", "1")
	want2 := want
	want2.CPUs, want2.DiskGB = types.Int64Value(4), types.Int64Value(50)
	ur = &resource.UpdateResponse{State: stateFrom(t, empty, updated)}
	r.Update(ctx, resource.UpdateRequest{Plan: planFrom(t, empty, want2), State: stateFrom(t, empty, updated)}, ur)
	if !ur.Diagnostics.HasError() || !strings.Contains(ur.Diagnostics.Errors()[0].Detail(), "snapshots") {
		t.Fatalf("failed grow: %v", ur.Diagnostics)
	}
	var kept vmModel
	noErrors(t, "get", ur.State.Get(ctx, &kept))
	if kept.DiskGB.ValueInt64() != 30 || !kept.Running.ValueBool() {
		t.Errorf("after a failed grow: disk=%d running=%v", kept.DiskGB.ValueInt64(), kept.Running)
	}
	if running, _ := h.client.Host.IsRunning(vmx); !running {
		t.Error("a failed grow left the VM powered off")
	}
	t.Setenv("FAKE_VDISK_FAIL", "")

	// delete: hard stop, deleteVM, the bundle is gone
	h.calls(t)
	dr := &resource.DeleteResponse{}
	r.Delete(ctx, resource.DeleteRequest{State: stateFrom(t, empty, kept)}, dr)
	noErrors(t, "delete", dr.Diagnostics)
	calls = h.calls(t)
	if !hasCall(calls, "vmrun -T "+hostType()+" stop "+vmx+" hard") || !hasCall(calls, "vmrun -T "+hostType()+" deleteVM "+vmx) {
		t.Errorf("delete calls = %q", calls)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Error("the VM bundle is still there")
	}

	// read after the VM was deleted outside Terraform: it leaves the state
	rr = &resource.ReadResponse{State: stateFrom(t, empty, kept)}
	r.Read(ctx, resource.ReadRequest{State: stateFrom(t, empty, kept)}, rr)
	noErrors(t, "read", rr.Diagnostics)
	if !rr.State.Raw.IsNull() {
		t.Error("a VM whose vmx is gone must be removed from state")
	}
}

func TestVMCreateWithoutBaseDiskFailsBeforeCloning(t *testing.T) {
	h := newHarness(t)
	r := &vmResource{client: h.client}
	empty := schemaOf(t, r)
	resp := &resource.CreateResponse{State: empty}
	r.Create(context.Background(), resource.CreateRequest{Plan: planFrom(t, empty, vmPlan(h, filepath.Join(h.dir, "missing.vmdk")))}, resp)
	if !resp.Diagnostics.HasError() || resp.Diagnostics.Errors()[0].Summary() != "base disk missing" {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	if hasCall(h.calls(t), "vdisk") {
		t.Error("cloned without a base disk")
	}
}

func hostType() string {
	if runtime.GOOS == "darwin" {
		return "fusion"
	}
	return "ws"
}
