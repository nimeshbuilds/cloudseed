package provider

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cloudseed/terraform-provider-vmdesktop/internal/vmware"
)

type vmResource struct{ client *Client }

type nicModel struct {
	Type  types.String `tfsdk:"type"`
	Vmnet types.String `tfsdk:"vmnet"`
	MAC   types.String `tfsdk:"mac"`
	IP    types.String `tfsdk:"ip"`
}

type cloudInitModel struct {
	UserData      types.String `tfsdk:"user_data"`
	MetaData      types.String `tfsdk:"meta_data"`
	NetworkConfig types.String `tfsdk:"network_config"`
}

type vmModel struct {
	ID        types.String    `tfsdk:"id"`
	Name      types.String    `tfsdk:"name"`
	Path      types.String    `tfsdk:"path"`
	GuestOSID types.String    `tfsdk:"guest_os_id"`
	Firmware  types.String    `tfsdk:"firmware"`
	CPUs      types.Int64     `tfsdk:"cpus"`
	MemoryMB  types.Int64     `tfsdk:"memory_mb"`
	DiskGB    types.Int64     `tfsdk:"disk_gb"`
	BaseDisk  types.String    `tfsdk:"base_disk"`
	Running   types.Bool      `tfsdk:"running"`
	WaitForIP types.Int64     `tfsdk:"wait_for_ip_seconds"`
	Networks  []nicModel      `tfsdk:"networks"`
	CloudInit *cloudInitModel `tfsdk:"cloud_init"`
	VMXPath   types.String    `tfsdk:"vmx_path"`
	IP        types.String    `tfsdk:"ip"`
	IPs       types.List      `tfsdk:"ips"`
}

func NewVMResource() resource.Resource { return &vmResource{} }

func (r *vmResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vm"
}

func replaceStr() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

func (r *vmResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A virtual machine cloned from a base cloud-image VMDK, configured with cloud-init (NoCloud ISO + guestinfo). " +
			"cpus, memory_mb, a larger disk_gb and running change in place; a smaller disk, a NIC's type, vmnet or MAC, the NIC count, " +
			"any change to cloud_init, and name, path, guest_os_id, firmware or base_disk rebuild it (its disk is wiped).",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true, PlanModifiers: replaceStr()},
			"path":        schema.StringAttribute{Required: true, Description: "Directory that will hold <name>.vmwarevm (absolute; a relative path is taken from Terraform's working directory)", PlanModifiers: replaceStr()},
			"guest_os_id": schema.StringAttribute{Required: true, Description: "VMware guestOS id, e.g. ubuntu-64 or arm-ubuntu-64", PlanModifiers: replaceStr()},
			"firmware":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("efi"), PlanModifiers: replaceStr()},
			"cpus":        schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(2)},
			"memory_mb":   schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(2048)},
			"disk_gb": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(20),
				Description: "Disk size. Growing it is applied in place (the VM restarts and cloud-init grows the root filesystem); " +
					"VMware disks cannot shrink, so a smaller value rebuilds the VM.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplaceIf(diskShrinks,
					"A smaller disk rebuilds the VM (VMware disks only grow).", "A smaller disk rebuilds the VM (VMware disks only grow).")}},
			"base_disk": schema.StringAttribute{Required: true, Description: "Base VMDK (cloud image) to clone", PlanModifiers: replaceStr()},
			"running":   schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"wait_for_ip_seconds": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(300),
				Description: "How long to wait for the guest to report an IP after start (0 = don't wait)"},
			"networks": schema.ListNestedAttribute{
				Required: true,
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplaceIf(nicsRequireReplace,
					"A different NIC count, or a NIC whose type, vmnet or MAC changes, rebuilds the VM (the IP a NIC reports never does).",
					"A different NIC count, or a NIC whose `type`, `vmnet` or `mac` changes, rebuilds the VM (the IP a NIC reports never does).")},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"type":  schema.StringAttribute{Required: true, Description: "nat | hostonly | bridged | custom"},
					"vmnet": schema.StringAttribute{Optional: true, Description: "vmnetN for type=custom"},
					"mac": schema.StringAttribute{Optional: true, Computed: true, Description: "static MAC (00:50:56:00-3f:xx:xx); generated when omitted",
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
					"ip": schema.StringAttribute{Computed: true, Description: "DHCP lease / tools-reported IP when known"},
				}},
			},
			"cloud_init": schema.SingleNestedAttribute{
				Optional: true, PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplace()},
				Description: "First-boot configuration (NoCloud seed + guestinfo). cloud-init applies it once, so any change rebuilds the VM.",
				Attributes: map[string]schema.Attribute{
					"user_data":      schema.StringAttribute{Required: true},
					"meta_data":      schema.StringAttribute{Optional: true},
					"network_config": schema.StringAttribute{Optional: true},
				},
			},
			"vmx_path": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ip":       schema.StringAttribute{Computed: true, Description: "Primary IP (first NIC)"},
			"ips":      schema.ListAttribute{ElementType: types.StringType, Computed: true},
		},
	}
}

// nicsRequireReplace decides whether a change of `networks` rebuilds the VM. Only what defines the virtual hardware
// counts: the number of NICs and each NIC's type, vmnet and (configured) MAC. The IP a NIC reports is a runtime value -
// it goes unknown whenever anything else about the VM changes, and it is "" while the VM is powered off - so it must
// never force a replacement (that would wipe every VM on a cpu change or after a host reboot).
func nicsRequireReplace(ctx context.Context, req planmodifier.ListRequest, resp *listplanmodifier.RequiresReplaceIfFuncResponse) {
	replace, diags := nicListsDiffer(ctx, req.ConfigValue, req.PlanValue, req.StateValue)
	resp.Diagnostics.Append(diags...)
	resp.RequiresReplace = replace
}

func nicListsDiffer(ctx context.Context, configList, planList, stateList types.List) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	if planList.IsUnknown() || planList.IsNull() || stateList.IsNull() || stateList.IsUnknown() {
		return !planList.Equal(stateList), diags
	}
	var plan, state, config []nicModel
	diags.Append(planList.ElementsAs(ctx, &plan, false)...)
	diags.Append(stateList.ElementsAs(ctx, &state, false)...)
	if !configList.IsNull() && !configList.IsUnknown() {
		diags.Append(configList.ElementsAs(ctx, &config, false)...)
	}
	if diags.HasError() {
		return false, diags
	}
	if len(plan) != len(state) {
		return true, diags
	}
	for i := range plan {
		p, s := plan[i], state[i]
		if !p.Type.Equal(s.Type) || !p.Vmnet.Equal(s.Vmnet) {
			return true, diags
		}
		// A MAC left out of the configuration keeps the generated one (UseStateForUnknown on the nested attribute runs
		// after this list-level check, so the plan still shows it unknown here); a configured one must match.
		configured := types.StringNull()
		if i < len(config) {
			configured = config[i].MAC
		}
		switch {
		case configured.IsNull():
		case configured.IsUnknown():
			return true, diags
		case !strings.EqualFold(configured.ValueString(), s.MAC.ValueString()):
			return true, diags
		}
	}
	return false, diags
}

// diskShrinks: VMware disks only grow, so a smaller disk_gb can only be had by rebuilding the VM (the plan shows it as
// "forces replacement"). A plan-time error would be friendlier, but Terraform plans every resource again before a
// destroy, and that error would then block destroying the very VM.
func diskShrinks(_ context.Context, req planmodifier.Int64Request, resp *int64planmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.PlanValue.IsUnknown() && !req.StateValue.IsNull() && req.PlanValue.ValueInt64() < req.StateValue.ValueInt64()
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// isMountParent: a directory where macOS or Linux desktops mount external and network volumes (/Volumes/<disk>,
// /media/<user>/<disk>, /run/media/<user>/<disk>, /mnt/<disk>). A VM directory right in one is a volume's root, and it
// vanishes when that volume is unmounted while the directory above it stays.
func isMountParent(dir string) bool {
	d := filepath.Clean(dir)
	switch d {
	case "/Volumes", "/media", "/mnt":
		return true
	}
	return filepath.Dir(d) == "/media" || filepath.Dir(d) == "/run/media"
}

func (r *vmResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (m *vmModel) vmDir() string {
	return filepath.Join(m.Path.ValueString(), m.Name.ValueString()+".vmwarevm")
}

// incompleteMarker sits in a VM's bundle from the moment Create starts until the VM is recorded in state. A bundle that
// has it is the debris of a failed create and is cleared; one without it is a VM Terraform does not know (lost state,
// an earlier environment of the same name) and is never deleted. cloudseed reads the same name (localvm.INCOMPLETE_MARKER).
const incompleteMarker = ".cloudseed-incomplete"

// clearBundlePath makes dir free for a new VM. A running VM there is refused; the leftovers of a failed create are
// removed; anything else is moved aside (<name>.replaced-<time>.vmwarevm, next to it) with a warning - never deleted.
func clearBundlePath(h *vmware.Host, dir, name string, diags *diag.Diagnostics) bool {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return true
	}
	// every .vmx in the bundle counts (a VM of its own may have been renamed), not only the one Create would write
	vmxs, _ := filepath.Glob(filepath.Join(dir, "*.vmx"))
	if vmx := filepath.Join(dir, name+".vmx"); !slices.Contains(vmxs, vmx) {
		vmxs = append(vmxs, vmx)
	}
	var running []string
	var listErr error
	for _, v := range vmxs {
		on, err := h.IsRunning(v)
		if err != nil {
			listErr = err
			break
		}
		if on {
			running = append(running, v)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, incompleteMarker)); err == nil { // our own create that failed (or was killed)
		for _, v := range running {
			_, _ = h.Vmrun("stop", v, "hard")
		}
		if err := os.RemoveAll(dir); err != nil {
			diags.AddError("clearing a failed create", "Could not remove "+dir+", left by a create that failed: "+err.Error())
			return false
		}
		return true
	}
	if listErr != nil { // cannot tell whether that VM runs: never move a running VM's files from under it
		diags.AddError("checking the VM at "+dir,
			"A VM bundle that is not in the Terraform state is in the way, and whether it is running could not be checked ("+
				listErr.Error()+"). Nothing was changed: make sure `vmrun list` works (VMware installed and not updating), "+
				"then apply again.")
		return false
	}
	if len(running) > 0 {
		diags.AddError("a VM is running at "+dir,
			"A VM named "+name+" is running there, but it is not in the Terraform state (the state was lost, or an earlier "+
				"environment of the same name created it). Nothing was changed: stop it, move it out of "+filepath.Dir(dir)+
				" (or delete it), then apply again.")
		return false
	}
	aside := filepath.Join(filepath.Dir(dir), name+".replaced-"+time.Now().Format("20060102-150405")+".vmwarevm")
	if err := os.Rename(dir, aside); err != nil {
		diags.AddError("moving an unknown VM aside", "A VM bundle "+dir+" that is not in the Terraform state is in the way, "+
			"and it could not be moved aside ("+err.Error()+"). Nothing was deleted: move or delete it, then apply again.")
		return false
	}
	diags.AddWarning("an unknown VM was moved aside",
		dir+" held a VM that is not in the Terraform state (the state was lost, or an earlier environment of the same name "+
			"created it). It was moved to "+aside+" instead of being overwritten: open it in VMware if you need it, delete it if not.")
	return true
}

func (r *vmResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan vmModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h := r.client.Host
	dir := plan.vmDir()
	// vmrun reports (and compares) absolute paths: keep the vmx path absolute even when `path` is relative.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if !clearBundlePath(h, dir, plan.Name.ValueString(), &resp.Diagnostics) {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		resp.Diagnostics.AddError("creating VM directory", err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(dir, incompleteMarker), []byte("created by terraform-provider-vmdesktop; removed once the VM is in the Terraform state\n"), 0o644); err != nil {
		resp.Diagnostics.AddError("creating VM directory", err.Error())
		return
	}
	disk := filepath.Join(dir, "disk.vmdk")
	if _, err := os.Stat(plan.BaseDisk.ValueString()); err != nil {
		resp.Diagnostics.AddError("base disk missing", plan.BaseDisk.ValueString())
		return
	}
	// clone (convert to a single growable disk) then grow
	if err := h.VdiskManager("-r", plan.BaseDisk.ValueString(), "-t", "0", disk); err != nil {
		resp.Diagnostics.AddError("cloning base disk", err.Error())
		return
	}
	if err := h.VdiskManager("-x", fmt.Sprintf("%dGB", plan.DiskGB.ValueInt64()), disk); err != nil {
		resp.Diagnostics.AddWarning("disk expand failed", err.Error()+" (continuing with the base size)")
	}

	spec := vmware.VMSpec{
		Name: plan.Name.ValueString(), Dir: dir, GuestOSID: plan.GuestOSID.ValueString(), Firmware: plan.Firmware.ValueString(),
		CPUs: plan.CPUs.ValueInt64(), MemoryMB: plan.MemoryMB.ValueInt64(), DiskFile: disk, HWVersion: h.HWVersion(),
	}
	for i := range plan.Networks {
		n := &plan.Networks[i]
		mac := n.MAC.ValueString()
		if mac == "" {
			m, err := vmware.RandomMAC()
			if err != nil {
				resp.Diagnostics.AddError("generating MAC", err.Error())
				return
			}
			mac = m
			n.MAC = types.StringValue(mac)
		}
		spec.NICs = append(spec.NICs, vmware.NIC{Type: n.Type.ValueString(), Vmnet: n.Vmnet.ValueString(), MAC: mac})
	}
	if plan.CloudInit != nil {
		meta := plan.CloudInit.MetaData.ValueString()
		if meta == "" {
			meta = fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", plan.Name.ValueString(), plan.Name.ValueString())
		}
		spec.UserData = plan.CloudInit.UserData.ValueString()
		spec.MetaData = meta
		spec.NetworkConfig = plan.CloudInit.NetworkConfig.ValueString()
		// Always a NoCloud seed ISO (host ISO tool, else the built-in writer): images without open-vm-tools (Debian)
		// cannot read guestinfo at all, and it is the only place the static network config is guaranteed to reach.
		iso, err := vmware.MakeCidata(dir, spec.UserData, spec.MetaData, spec.NetworkConfig)
		if err != nil {
			resp.Diagnostics.AddError("cloud-init seed", err.Error())
			return
		}
		spec.CidataISO = iso
	}
	vmx := filepath.Join(dir, plan.Name.ValueString()+".vmx")
	if err := os.WriteFile(vmx, []byte(spec.Render()), 0o644); err != nil {
		resp.Diagnostics.AddError("writing vmx", err.Error())
		return
	}
	plan.ID = types.StringValue(vmx)
	plan.VMXPath = types.StringValue(vmx)

	if plan.Running.ValueBool() {
		if _, err := h.Vmrun("start", vmx, "nogui"); err != nil {
			resp.Diagnostics.AddError("starting VM", err.Error())
			return
		}
		r.waitForIP(ctx, &plan, &resp.Diagnostics)
	} else {
		r.fillIPs(&plan)
	}
	// Always record the VM (even when the wait was cut short): it exists now, and leaving it out of state would orphan it.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if !resp.Diagnostics.HasError() {
		_ = os.Remove(filepath.Join(dir, incompleteMarker))
	}
}

// waitForIP waits up to wait_for_ip_seconds for the first NIC's address and warns (never fails: the VM exists and
// runs, and an error would taint it) when none arrives. Ctrl-C (a cancelled context) ends the wait at once.
func (r *vmResource) waitForIP(ctx context.Context, m *vmModel, diags *diag.Diagnostics) {
	secs := m.WaitForIP.ValueInt64()
	if r.waitAndFillIPs(ctx, m, time.Duration(secs)*time.Second) || secs <= 0 || ctx.Err() != nil {
		return
	}
	mac := ""
	if len(m.Networks) > 0 {
		mac = m.Networks[0].MAC.ValueString()
	}
	diags.AddWarning("VM did not report an IP",
		fmt.Sprintf("%s started but did not report an IP within %ds (no DHCP lease for %s and VMware Tools not answering). "+
			"Open it in Fusion/Workstation to check that it booted and cloud-init finished, make sure open-vm-tools is installed "+
			"and the NAT network (vmnet8) has DHCP enabled, then run `cloudseed apply` again to pick up the address.",
			m.Name.ValueString(), secs, mac))
}

// waitAndFillIPs polls for the primary IP until it appears, the timeout passes or ctx is cancelled; true when found.
func (r *vmResource) waitAndFillIPs(ctx context.Context, m *vmModel, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		r.fillIPs(m)
		if m.IP.ValueString() != "" {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
		}
	}
}

func (r *vmResource) fillIPs(m *vmModel) {
	h := r.client.Host
	primary := ""
	var ips []attr.Value
	for i := range m.Networks {
		ip := h.LeaseIP(m.Networks[i].MAC.ValueString())
		if i == 0 && ip == "" && m.Running.ValueBool() {
			if out, err := h.Vmrun("getGuestIPAddress", m.VMXPath.ValueString()); err == nil && strings.Count(out, ".") == 3 {
				ip = strings.TrimSpace(out)
			}
		}
		if i == 0 {
			primary = ip
		}
		if ip != "" {
			m.Networks[i].IP = types.StringValue(ip)
			ips = append(ips, types.StringValue(ip))
		} else {
			m.Networks[i].IP = types.StringValue("")
		}
	}
	m.IP = types.StringValue(primary)
	m.IPs = types.ListValueMust(types.StringType, ips)
}

func (r *vmResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state vmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vmx := state.VMXPath.ValueString()
	kv, err := vmware.ParseVMX(vmx)
	if err != nil {
		// Only a VM that is really gone leaves the state. Anything else - a folder this process may not read (macOS
		// privacy protection), a detached external disk - keeps it: dropping it would turn the next apply into
		// "create", over the very VM that is still there.
		if !errors.Is(err, fs.ErrNotExist) {
			resp.Diagnostics.AddError("reading "+vmx, err.Error()+"\n\nThe VM stays in the Terraform state. Check that this "+
				"program may read the folder (macOS: Privacy & Security > Files and Folders / Full Disk Access for the app "+
				"running cloudseed or Terraform), then retry.")
			return
		}
		vmDir := filepath.Dir(filepath.Dir(vmx)) // <path>/<name>.vmwarevm/<name>.vmx
		if parent := filepath.Dir(vmDir); !exists(vmDir) && (!exists(parent) || isMountParent(parent)) {
			resp.Diagnostics.AddError("VM directory not found",
				vmDir+" is missing (and so is "+parent+", or it is where volumes are mounted): is the disk holding it "+
					"unmounted (an external or network volume)? The VM stays in the Terraform state rather than being created "+
					"again. Mount it and retry; if the VMs are really gone, create the folder (mkdir -p "+vmDir+") and retry - "+
					"they then leave the state.")
			return
		}
		resp.State.RemoveResource(ctx)
		return
	}
	if v, err := strconv.ParseInt(kv["numvcpus"], 10, 64); err == nil {
		state.CPUs = types.Int64Value(v)
	}
	if v, err := strconv.ParseInt(kv["memsize"], 10, 64); err == nil {
		state.MemoryMB = types.Int64Value(v)
	}
	running, err := r.client.Host.IsRunning(vmx)
	if err == nil {
		state.Running = types.BoolValue(running)
	}
	r.fillIPs(&state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *vmResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state vmModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h := r.client.Host
	vmx := state.VMXPath.ValueString()
	plan.ID, plan.VMXPath = state.ID, state.VMXPath
	for i := range plan.Networks {
		if i < len(state.Networks) && (plan.Networks[i].MAC.IsUnknown() || plan.Networks[i].MAC.ValueString() == "") {
			plan.Networks[i].MAC = state.Networks[i].MAC
		}
	}
	running, _ := h.IsRunning(vmx)
	sizeChanged := plan.CPUs.ValueInt64() != state.CPUs.ValueInt64() || plan.MemoryMB.ValueInt64() != state.MemoryMB.ValueInt64()
	diskGrows := plan.DiskGB.ValueInt64() > state.DiskGB.ValueInt64()
	if running && (sizeChanged || diskGrows || !plan.Running.ValueBool()) {
		if _, err := h.Vmrun("stop", vmx, "soft"); err != nil {
			if _, err2 := h.Vmrun("stop", vmx, "hard"); err2 != nil {
				resp.Diagnostics.AddError("stopping VM", err2.Error())
				return
			}
		}
		running = false
	}
	if sizeChanged {
		if err := vmware.SetVMXKeys(vmx, map[string]string{
			"numvcpus": fmt.Sprint(plan.CPUs.ValueInt64()), "memsize": fmt.Sprint(plan.MemoryMB.ValueInt64())}); err != nil {
			resp.Diagnostics.AddError("updating vmx", err.Error())
			return
		}
	}
	if diskGrows {
		disk := filepath.Join(filepath.Dir(vmx), "disk.vmdk")
		if err := h.VdiskManager("-x", fmt.Sprintf("%dGB", plan.DiskGB.ValueInt64()), disk); err != nil {
			// Record what really happened (the disk keeps its size). The VM is still powered back on below when it
			// should run, so a failed grow never leaves it off.
			plan.DiskGB = state.DiskGB
			resp.Diagnostics.AddError("growing the disk",
				err.Error()+"\n\nThe disk keeps its old size. A VM with snapshots cannot be grown: delete its snapshots and apply again.")
		}
	}
	if plan.Running.ValueBool() && !running {
		if _, err := h.Vmrun("start", vmx, "nogui"); err != nil {
			resp.Diagnostics.AddError("starting VM", err.Error())
			r.fillIPs(&plan)
			plan.Running = types.BoolValue(false)
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
			return
		}
		r.waitForIP(ctx, &plan, &resp.Diagnostics)
	} else {
		r.fillIPs(&plan)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *vmResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state vmModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h := r.client.Host
	vmx := state.VMXPath.ValueString()
	if running, _ := h.IsRunning(vmx); running {
		if _, err := h.Vmrun("stop", vmx, "hard"); err != nil {
			resp.Diagnostics.AddWarning("stop failed", err.Error())
		}
	}
	if _, err := h.Vmrun("deleteVM", vmx); err != nil {
		resp.Diagnostics.AddWarning("deleteVM failed", err.Error()+"; removing the directory directly")
	}
	_ = os.RemoveAll(state.vmDir())
}
