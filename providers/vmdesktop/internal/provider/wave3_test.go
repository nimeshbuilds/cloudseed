package provider

// Existing VM bundles that Terraform does not know are never destroyed by a create, and a VM whose vmx cannot be read
// (as opposed to one that is gone) never leaves the state.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func unknownBundle(t *testing.T, h *harness, marker bool) (string, string) {
	t.Helper()
	dir := filepath.Join(h.dir, "vms", "cs-dev-vm1.vmwarevm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	vmx := filepath.Join(dir, "cs-dev-vm1.vmx")
	os.WriteFile(vmx, []byte("numvcpus = \"2\"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "precious-data.vmdk"), []byte("data"), 0o644)
	if marker {
		os.WriteFile(filepath.Join(dir, incompleteMarker), nil, 0o644)
	}
	return dir, vmx
}

func createVM(t *testing.T, h *harness) *resource.CreateResponse {
	t.Helper()
	r := &vmResource{client: h.client}
	empty := schemaOf(t, r)
	base := filepath.Join(h.dir, "base.vmdk")
	os.WriteFile(base, []byte("base"), 0o644)
	resp := &resource.CreateResponse{State: empty}
	r.Create(context.Background(), resource.CreateRequest{Plan: planFrom(t, empty, vmPlan(h, base))}, resp)
	return resp
}

func TestCreateRefusesARunningVMItDoesNotKnow(t *testing.T) {
	h := newHarness(t)
	dir, vmx := unknownBundle(t, h, false)
	os.WriteFile(filepath.Join(h.dir, "running"), []byte(vmx+"\n"), 0o644)
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "a VM is running") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	calls := h.calls(t)
	if hasCall(calls, "vmrun -T "+hostType()+" stop") || hasCall(calls, "vdisk") {
		t.Errorf("touched the running VM: %q", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); err != nil {
		t.Errorf("the running VM's disk is gone: %v", err)
	}
}

func TestCreateMovesAStoppedVMItDoesNotKnowAside(t *testing.T) {
	h := newHarness(t)
	dir, _ := unknownBundle(t, h, false)
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	if !warned(resp.Diagnostics, "an unknown VM was moved aside") {
		t.Fatalf("no warning: %v", resp.Diagnostics)
	}
	moved, _ := filepath.Glob(filepath.Join(h.dir, "vms", "cs-dev-vm1.replaced-*.vmwarevm"))
	if len(moved) != 1 {
		t.Fatalf("moved aside: %v", moved)
	}
	if data, err := os.ReadFile(filepath.Join(moved[0], "precious-data.vmdk")); err != nil || string(data) != "data" {
		t.Errorf("the old VM's disk was not kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); !os.IsNotExist(err) {
		t.Error("the new VM's bundle still holds the old VM's files")
	}
	if _, err := os.Stat(filepath.Join(dir, "cs-dev-vm1.vmx")); err != nil {
		t.Errorf("the new VM was not created: %v", err)
	}
}

func TestCreateRefusesAnUnknownBundleWithAnyRunningVMX(t *testing.T) {
	h := newHarness(t)
	dir, _ := unknownBundle(t, h, false)
	renamed := filepath.Join(dir, "my-own-vm.vmx") // a VM of the user's own, renamed into this bundle
	os.WriteFile(renamed, []byte("numvcpus = \"2\"\n"), 0o644)
	os.WriteFile(filepath.Join(h.dir, "running"), []byte(renamed+"\n"), 0o644)
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "a VM is running") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); err != nil {
		t.Errorf("the running VM's bundle was moved or changed: %v", err)
	}
}

func TestCreateDoesNotMoveAnUnknownBundleWhenItCannotTellWhetherItRuns(t *testing.T) {
	h := newHarness(t)
	dir, _ := unknownBundle(t, h, false)
	t.Setenv("FAKE_LIST_FAIL", "1")
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "checking the VM") {
		t.Fatalf("diagnostics = %v", resp.Diagnostics)
	}
	if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); err != nil {
		t.Errorf("the bundle was moved or changed: %v", err)
	}
	if moved, _ := filepath.Glob(filepath.Join(h.dir, "vms", "*.replaced-*")); len(moved) != 0 {
		t.Errorf("moved aside although it may be running: %v", moved)
	}
}

func TestCreateClearsItsOwnFailedAttemptEvenWhenRunning(t *testing.T) {
	h := newHarness(t)
	dir, vmx := unknownBundle(t, h, true) // killed after `vmrun start`, before the state was saved
	os.WriteFile(filepath.Join(h.dir, "running"), []byte(vmx+"\n"), 0o644)
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	if !hasCall(h.calls(t), "vmrun -T "+hostType()+" stop "+vmx+" hard") {
		t.Error("the half-created VM was not stopped")
	}
	if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); !os.IsNotExist(err) {
		t.Error("the failed attempt was not cleared")
	}
	if moved, _ := filepath.Glob(filepath.Join(h.dir, "vms", "*.replaced-*")); len(moved) != 0 {
		t.Errorf("a failed attempt must not be kept: %v", moved)
	}
}

func TestReadKeepsAVMWhoseVMXCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	h := newHarness(t)
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	vmx := vm.VMXPath.ValueString()
	os.Chmod(vmx, 0o000)
	t.Cleanup(func() { os.Chmod(vmx, 0o644) })
	r := &vmResource{client: h.client}
	empty := schemaOf(t, r)
	rr := &resource.ReadResponse{State: stateFrom(t, empty, vm)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, vm)}, rr)
	if !rr.Diagnostics.HasError() || rr.State.Raw.IsNull() {
		t.Fatalf("an unreadable vmx must be an error and keep the VM: diags=%v removed=%v", rr.Diagnostics, rr.State.Raw.IsNull())
	}
}

func TestReadKeepsVMsOnAMissingVolume(t *testing.T) {
	h := newHarness(t)
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	gone := vm
	gone.VMXPath = types.StringValue(filepath.Join(h.dir, "detached-volume", "VMs", "cs-dev-vm1.vmwarevm", "cs-dev-vm1.vmx"))
	r := &vmResource{client: h.client}
	empty := schemaOf(t, r)
	rr := &resource.ReadResponse{State: stateFrom(t, empty, gone)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, gone)}, rr)
	if !rr.Diagnostics.HasError() || rr.State.Raw.IsNull() {
		t.Fatalf("VMs on a detached volume must stay in state: diags=%v", rr.Diagnostics)
	}
	// a VM directory that is a volume's root (/Volumes/<disk>): unmounted, it is gone while /Volumes stays
	root := gone
	root.VMXPath = types.StringValue(filepath.Join("/Volumes", "cs-test-unmounted-"+filepath.Base(h.dir), "cs-dev-vm1.vmwarevm", "cs-dev-vm1.vmx"))
	rr = &resource.ReadResponse{State: stateFrom(t, empty, root)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, root)}, rr)
	if !rr.Diagnostics.HasError() || rr.State.Raw.IsNull() {
		t.Fatalf("VMs at the root of an unmounted volume must stay in state: diags=%v", rr.Diagnostics)
	}
	for dir, want := range map[string]bool{"/Volumes": true, "/media/me": true, "/run/media/me": true, "/mnt": true,
		"/Users/me": false, "/home/me/vms": false, "/media": true, "/Volumes/SSD": false} {
		if got := isMountParent(dir); got != want {
			t.Errorf("isMountParent(%q) = %v, want %v", dir, got, want)
		}
	}
	// the VM directory exists but the bundle is gone: deleted outside Terraform, it leaves the state
	deleted := vm
	deleted.VMXPath = types.StringValue(filepath.Join(h.dir, "vms", "cs-dev-vm9.vmwarevm", "cs-dev-vm9.vmx"))
	rr = &resource.ReadResponse{State: stateFrom(t, empty, deleted)}
	r.Read(context.Background(), resource.ReadRequest{State: stateFrom(t, empty, deleted)}, rr)
	noErrors(t, "read", rr.Diagnostics)
	if !rr.State.Raw.IsNull() {
		t.Error("a deleted VM must leave the state")
	}
}

func TestCreateUsesTheHostsHardwareVersion(t *testing.T) {
	h := newHarness(t)
	h.client.Host.Version = "13.0.2"
	h.client.Host.Product = "fusion"
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	data, _ := os.ReadFile(vm.VMXPath.ValueString())
	if !strings.Contains(string(data), "virtualHW.version = \"20\"") {
		t.Errorf("Fusion 13.0 must get hardware version 20:\n%s", data)
	}
}
