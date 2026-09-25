package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func createdVM(t *testing.T, h *harness) vmModel {
	t.Helper()
	resp := createVM(t, h)
	noErrors(t, "create", resp.Diagnostics)
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	return vm
}

func deleteVM(t *testing.T, r *vmResource, vm vmModel) *resource.DeleteResponse {
	t.Helper()
	state := stateFrom(t, schemaOf(t, r), vm)
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	return resp
}

func assertBundlePresent(t *testing.T, vm vmModel) {
	t.Helper()
	for _, path := range []string{vm.VMXPath.ValueString(), filepath.Join(filepath.Dir(vm.VMXPath.ValueString()), "disk.vmdk")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("VM file was removed on failure: %s: %v", path, err)
		}
	}
}

func TestVMDeleteFailuresPreserveFilesAndAllowRetry(t *testing.T) {
	for _, flag := range []string{"FAKE_LIST_FAIL", "FAKE_STOP_FAIL", "FAKE_STOP_NOOP", "FAKE_DELETE_FAIL"} {
		t.Run(flag, func(t *testing.T) {
			h := newHarness(t)
			vm := createdVM(t, h)
			r := &vmResource{client: h.client}
			h.calls(t)
			t.Setenv(flag, "1")
			resp := deleteVM(t, r, vm)
			if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
				t.Fatalf("delete failure lost state: %v", resp.Diagnostics)
			}
			assertBundlePresent(t, vm)
			calls := h.calls(t)
			if flag != "FAKE_DELETE_FAIL" && hasCall(calls, "vmrun -T "+hostType()+" deleteVM") {
				t.Fatalf("deletion ran despite unconfirmed stop: %q", calls)
			}
			t.Setenv(flag, "")
			noErrors(t, "retry delete", deleteVM(t, r, vm).Diagnostics)
			if _, err := os.Stat(filepath.Dir(vm.VMXPath.ValueString())); !os.IsNotExist(err) {
				t.Fatalf("bundle survived successful retry: %v", err)
			}
		})
	}
}

func TestVMDeleteCleanupFailureSurvivesRefreshAndRetries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses folder permissions")
	}
	h := newHarness(t)
	vm := createdVM(t, h)
	r := &vmResource{client: h.client}
	dir := filepath.Dir(vm.VMXPath.ValueString())
	protected := filepath.Join(dir, "locked")
	if err := os.Mkdir(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(protected, "remaining-disk.vmdk"), []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(protected, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(protected, 0o755) })
	t.Setenv("FAKE_DELETE_REMOVE_VMX", "1")
	resp := deleteVM(t, r, vm)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("filesystem error was ignored: %v", resp.Diagnostics)
	}
	if _, err := os.Stat(vm.VMXPath.ValueString()); !os.IsNotExist(err) {
		t.Fatalf("test did not exercise partial deletion: %v", err)
	}
	// Terraform refreshes before a subsequent destroy. It must not forget the
	// residual bundle just because deleteVM already removed the VMX.
	read := &resource.ReadResponse{State: resp.State}
	r.Read(context.Background(), resource.ReadRequest{State: resp.State}, read)
	noErrors(t, "refresh partial delete", read.Diagnostics)
	if read.State.Raw.IsNull() || !warned(read.Diagnostics, "VM configuration missing") {
		t.Fatalf("refresh lost partially deleted bundle: %v", read.Diagnostics)
	}
	if err := os.Chmod(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	h.calls(t)
	noErrors(t, "cleanup retry", deleteVM(t, r, vm).Diagnostics)
	if hasCall(h.calls(t), "vmrun -T "+hostType()+" deleteVM") {
		t.Fatal("retried deleteVM on a missing VMX instead of cleaning residual files")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("residual bundle remains: %v", err)
	}
}

func TestVMDeleteMissingBundleAndUnmountedStorage(t *testing.T) {
	h := newHarness(t)
	vm := createdVM(t, h)
	r := &vmResource{client: h.client}
	if err := os.RemoveAll(filepath.Dir(vm.VMXPath.ValueString())); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_LIST_FAIL", "1")
	noErrors(t, "already absent", deleteVM(t, r, vm).Diagnostics)
	vm.VMXPath = types.StringValue(filepath.Join(h.dir, "unmounted", "vms", "vm.vmwarevm", "vm.vmx"))
	resp := deleteVM(t, r, vm)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("unmounted disk was treated as deleted: %v", resp.Diagnostics)
	}
}

func TestVMDeleteUsesTrackedBundlePath(t *testing.T) {
	h := newHarness(t)
	vm := createdVM(t, h)
	other := filepath.Join(h.dir, "another-working-directory")
	if err := os.MkdirAll(filepath.Join(other, vm.Name.ValueString()+".vmwarevm"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The path attribute can be relative to an earlier Terraform working
	// directory; VMXPath is the absolute identity recorded at create time.
	vm.Path = types.StringValue(other)
	r := &vmResource{client: h.client}
	noErrors(t, "delete", deleteVM(t, r, vm).Diagnostics)
	if _, err := os.Stat(filepath.Join(other, vm.Name.ValueString()+".vmwarevm")); err != nil {
		t.Fatalf("deleted a directory other than the tracked bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(vm.VMXPath.ValueString())); !os.IsNotExist(err) {
		t.Fatalf("tracked bundle survived: %v", err)
	}
}

func TestCreateDoesNotClearFailedAttemptUnlessStopIsConfirmed(t *testing.T) {
	for _, flag := range []string{"FAKE_LIST_FAIL", "FAKE_STOP_FAIL", "FAKE_STOP_NOOP"} {
		t.Run(flag, func(t *testing.T) {
			h := newHarness(t)
			dir, vmx := unknownBundle(t, h, true)
			if err := os.WriteFile(filepath.Join(h.dir, "running"), []byte(vmx+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv(flag, "1")
			resp := createVM(t, h)
			if !resp.Diagnostics.HasError() {
				t.Fatalf("unsafe cleanup succeeded: %v", resp.Diagnostics)
			}
			if _, err := os.Stat(filepath.Join(dir, "precious-data.vmdk")); err != nil {
				t.Fatalf("removed a potentially running failed-create bundle: %v", err)
			}
			if hasCall(h.calls(t), "vdisk") {
				t.Fatal("cloned over potentially running files")
			}
			t.Setenv(flag, "")
			noErrors(t, "create retry", createVM(t, h).Diagnostics)
		})
	}
}

func TestCreateFailedExpansionRecordsCapacityAndCanBeReplaced(t *testing.T) {
	h := newHarness(t)
	t.Setenv("FAKE_VDISK_FAIL", "1")
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("failed expansion must error and preserve VM identity: %v", resp.Diagnostics)
	}
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	if vm.DiskGB.ValueInt64() != 3 || vm.Running.ValueBool() || vm.ID.ValueString() == "" {
		t.Fatalf("failed expansion state: %+v", vm)
	}
	assertBundlePresent(t, vm)
	if _, err := os.Stat(filepath.Join(filepath.Dir(vm.VMXPath.ValueString()), incompleteMarker)); !os.IsNotExist(err) {
		t.Fatalf("tracked VM still marked as untracked debris: %v", err)
	}
	if hasCall(h.calls(t), "vmrun -T "+hostType()+" start") {
		t.Fatal("VM booted after disk expansion failed")
	}
	r := &vmResource{client: h.client}
	read := &resource.ReadResponse{State: resp.State}
	r.Read(context.Background(), resource.ReadRequest{State: resp.State}, read)
	noErrors(t, "refresh failed create", read.Diagnostics)
	// Terraform taints a failed create. The next apply replaces it: both the
	// deletion and second create must work without untracked VM debris.
	noErrors(t, "replace failed create", deleteVM(t, r, vm).Diagnostics)
	t.Setenv("FAKE_VDISK_FAIL", "")
	retried := createdVM(t, h)
	if retried.DiskGB.ValueInt64() != 20 || !retried.Running.ValueBool() {
		t.Fatalf("replacement did not reach requested size and power state: %+v", retried)
	}
}

func TestCreateStartFailureKeepsIdentity(t *testing.T) {
	h := newHarness(t)
	t.Setenv("FAKE_START_FAIL", "1")
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("failed start lost VM identity: %v", resp.Diagnostics)
	}
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	if vm.Running.ValueBool() || vm.DiskGB.ValueInt64() != 20 {
		t.Fatalf("failed start state: %+v", vm)
	}
	assertBundlePresent(t, vm)
	noErrors(t, "delete failed start", deleteVM(t, &vmResource{client: h.client}, vm).Diagnostics)
}

func TestFailedCreateWithDamagedDiskCanRefreshAndReplace(t *testing.T) {
	h := newHarness(t)
	vdisk := h.client.Host.VdiskPath
	badTool := filepath.Join(h.dir, "bad-vdisk")
	if err := os.WriteFile(badTool, []byte("#!/bin/sh\nif [ \"$1\" = -r ]; then printf broken > \"$5\"; fi\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.client.Host.VdiskPath = badTool
	resp := createVM(t, h)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("damaged cloned disk lost identity: %v", resp.Diagnostics)
	}
	var vm vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &vm))
	if !vm.DiskGB.IsNull() || vm.Running.ValueBool() {
		t.Fatalf("unverified capacity or power state claimed: %+v", vm)
	}
	r := &vmResource{client: h.client}
	read := &resource.ReadResponse{State: resp.State}
	r.Read(context.Background(), resource.ReadRequest{State: resp.State}, read)
	noErrors(t, "refresh damaged failed create", read.Diagnostics)
	if !warned(read.Diagnostics, "reading disk capacity") || read.State.Raw.IsNull() {
		t.Fatalf("damaged disk was silently ignored or lost: %v", read.Diagnostics)
	}
	noErrors(t, "destroy damaged failed create", deleteVM(t, r, vm).Diagnostics)
	h.client.Host.VdiskPath = vdisk
	createdVM(t, h)
}

func TestReadRefreshesActualDiskCapacity(t *testing.T) {
	h := newHarness(t)
	vm := createdVM(t, h)
	disk := filepath.Join(filepath.Dir(vm.VMXPath.ValueString()), "disk.vmdk")
	writeDisk(t, disk, 32)
	r := &vmResource{client: h.client}
	state := stateFrom(t, schemaOf(t, r), vm)
	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)
	noErrors(t, "read disk drift", resp.Diagnostics)
	var got vmModel
	noErrors(t, "get", resp.State.Get(context.Background(), &got))
	if got.DiskGB.ValueInt64() != 32 {
		t.Fatalf("disk size was not refreshed: %d", got.DiskGB.ValueInt64())
	}
	if err := os.WriteFile(disk, []byte("broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp = &resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)
	if resp.Diagnostics.HasError() || !warned(resp.Diagnostics, "reading disk capacity") || resp.State.Raw.IsNull() {
		t.Fatalf("unreadable capacity blocks cleanup or lost state: %v", resp.Diagnostics)
	}
	noErrors(t, "destroy damaged disk after refresh", deleteVM(t, r, got).Diagnostics)
}

func TestDeleteRefusesRenamedRunningVMX(t *testing.T) {
	h := newHarness(t)
	vm := createdVM(t, h)
	r := &vmResource{client: h.client}
	old := vm.VMXPath.ValueString()
	renamed := filepath.Join(filepath.Dir(old), "renamed.vmx")
	if err := os.Rename(old, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "running"), []byte(renamed+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := deleteVM(t, r, vm)
	if !resp.Diagnostics.HasError() {
		t.Fatal("delete accepted a bundle containing a renamed running VM")
	}
	if _, err := os.Stat(renamed); err != nil {
		t.Fatalf("running VM files removed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "running"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	noErrors(t, "delete stopped renamed VM", deleteVM(t, r, vm).Diagnostics)
}

func TestUpdateRefusesUnconfirmedPowerState(t *testing.T) {
	for _, flag := range []string{"FAKE_LIST_FAIL", "FAKE_STOP_NOOP"} {
		t.Run(flag, func(t *testing.T) {
			h := newHarness(t)
			vm := createdVM(t, h)
			r := &vmResource{client: h.client}
			state := stateFrom(t, schemaOf(t, r), vm)
			plan := vm
			plan.CPUs, plan.DiskGB = types.Int64Value(4), types.Int64Value(30)
			before, err := os.ReadFile(vm.VMXPath.ValueString())
			if err != nil {
				t.Fatal(err)
			}
			h.calls(t)
			t.Setenv(flag, "1")
			resp := &resource.UpdateResponse{State: state}
			r.Update(context.Background(), resource.UpdateRequest{State: state, Plan: planFrom(t, state, plan)}, resp)
			if !resp.Diagnostics.HasError() {
				t.Fatalf("updated an unconfirmed VM: %v", resp.Diagnostics)
			}
			after, err := os.ReadFile(vm.VMXPath.ValueString())
			if err != nil || string(before) != string(after) || hasCall(h.calls(t), "vdisk") {
				t.Fatalf("changed hardware without confirmed stop: %v", err)
			}
		})
	}
}

func TestUpdateRetriesFailedDiskExpansion(t *testing.T) {
	h := newHarness(t)
	vm := createdVM(t, h)
	r := &vmResource{client: h.client}
	state := stateFrom(t, schemaOf(t, r), vm)
	plan := vm
	plan.DiskGB = types.Int64Value(30)
	update := func(state tfsdk.State) *resource.UpdateResponse {
		resp := &resource.UpdateResponse{State: state}
		r.Update(context.Background(), resource.UpdateRequest{State: state, Plan: planFrom(t, state, plan)}, resp)
		return resp
	}
	t.Setenv("FAKE_VDISK_FAIL", "1")
	failed := update(state)
	if !failed.Diagnostics.HasError() {
		t.Fatal("failed disk expansion was ignored")
	}
	t.Setenv("FAKE_VDISK_FAIL", "")
	succeeded := update(failed.State)
	noErrors(t, "retry expansion", succeeded.Diagnostics)
	var got vmModel
	noErrors(t, "get", succeeded.State.Get(context.Background(), &got))
	if got.DiskGB.ValueInt64() != 30 || !got.Running.ValueBool() || got.ID != vm.ID {
		t.Fatalf("retry did not grow the original VM: %+v", got)
	}
}
