package provider

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cloudseed/terraform-provider-vmdesktop/internal/vmware"
)

type networkResource struct{ client *Client }

var _ resource.ResourceWithImportState = &networkResource{}

type networkModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Type    types.String `tfsdk:"type"`
	Subnet  types.String `tfsdk:"subnet"`
	DHCP    types.Bool   `tfsdk:"dhcp"`
	Mask    types.String `tfsdk:"mask"`
	Adopted types.Bool   `tfsdk:"adopted"`
}

func NewNetworkResource() resource.Resource { return &networkResource{} }

func (r *networkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network"
}

func (r *networkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A virtual network (vmnet). Created through vmrest; an existing vmnet of the same type with exactly the same " +
			"subnet and mask is adopted, and a request that overlaps any other vmnet (e.g. the NAT vmnet8) is refused. " +
			"VMware has no API to delete vmnets, so destroy only forgets it. Import with the vmnet name (vmnetN).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Optional: true, Computed: true, Description: "vmnetN (auto-assigned when omitted)",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplace()}},
			"type":   schema.StringAttribute{Required: true, Description: "hostonly | nat", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"subnet": schema.StringAttribute{Required: true, Description: "CIDR, e.g. 10.100.0.0/24", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"dhcp": schema.BoolAttribute{Optional: true, Computed: true,
				Description: "DHCP on the vmnet. Omit it (recommended) to accept whatever the adopted/created network has: VMware " +
					"offers no API to change it afterwards, so a fixed value only produces a diff that can never be applied.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}},
			"mask": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"adopted": schema.BoolAttribute{Computed: true,
				Description:   "true when the vmnet already existed and was adopted (so it must outlive this resource); false when this resource created it",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *networkResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func restType(t string) string {
	if t == "nat" {
		return "nat"
	}
	return "hostOnly"
}

func (r *networkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, ipnet, err := net.ParseCIDR(plan.Subnet.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("invalid subnet", err.Error())
		return
	}
	subnet := ipnet.IP.String()
	mask := net.IP(ipnet.Mask).String()
	want := restType(plan.Type.ValueString())

	existing, err := r.client.Rest.ListVmnets()
	if err != nil {
		resp.Diagnostics.AddError("listing vmnets", err.Error())
		return
	}
	used := map[string]bool{}
	var found *vmware.Vmnet
	var clashes []string
	for i := range existing {
		e := &existing[i]
		used[e.Name] = true
		if e.Subnet == "" { // bridged vmnet0 has no subnet
			continue
		}
		if e.Subnet == subnet && (e.Mask == "" || e.Mask == mask) && strings.EqualFold(e.Type, want) {
			found = e
			continue
		}
		if other := vmnetCIDR(e); other != nil && (other.Contains(ipnet.IP) || ipnet.Contains(other.IP)) {
			clashes = append(clashes, fmt.Sprintf("%s (%s %s)", e.Name, e.Type, other))
		} else if other == nil && e.Subnet == subnet {
			clashes = append(clashes, fmt.Sprintf("%s (%s %s)", e.Name, e.Type, e.Subnet))
		}
	}
	if found == nil && len(clashes) > 0 {
		resp.Diagnostics.AddError("subnet overlaps an existing vmnet",
			fmt.Sprintf("%s overlaps %s. Adopting it would put these VMs on a different network (the NAT vmnet8 gives them "+
				"direct internet access and clashes with its gateway address), and a second vmnet on the same range cannot work. "+
				"Choose another range (cloudseed: --cidr), or leave --cidr out to use VMware's built-in host-only network.",
				ipnet, strings.Join(clashes, ", ")))
		return
	}
	adopted := found != nil
	if found == nil {
		name := plan.Name.ValueString()
		if name == "" {
			for i := 2; i < 20; i++ {
				cand := fmt.Sprintf("vmnet%d", i)
				if i != 8 && !used[cand] {
					name = cand
					break
				}
			}
		}
		if name == "" {
			resp.Diagnostics.AddError("no free vmnet", "all vmnet2..vmnet19 are in use")
			return
		}
		dhcp := false // dedicated vmnets get static addressing unless asked otherwise
		if !plan.DHCP.IsNull() && !plan.DHCP.IsUnknown() {
			dhcp = plan.DHCP.ValueBool()
		}
		found, err = r.client.Rest.CreateVmnet(name, want, subnet, mask, dhcp)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "403") || strings.Contains(msg, "not permitted") {
				msg += "\n\nVMware only lets a privileged vmrest create networks. Either use the built-in host-only network " +
					"(cloudseed does this by default: subnet = vmnet1's), or run `sudo vmrest` and retry."
			}
			resp.Diagnostics.AddError("creating vmnet", msg)
			return
		}
	} else {
		resp.Diagnostics.AddWarning("adopted existing vmnet", fmt.Sprintf("%s already serves %s; reusing it (it is kept on destroy)", found.Name, ipnet))
	}
	plan.ID = types.StringValue(found.Name)
	plan.Name = types.StringValue(found.Name)
	plan.Mask = types.StringValue(mask)
	if found.Mask != "" {
		plan.Mask = types.StringValue(found.Mask)
	}
	plan.DHCP = types.BoolValue(found.DHCP == "true") // what the network really has (adopted or freshly created)
	plan.Adopted = types.BoolValue(adopted)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// vmnetCIDR is the network a vmnet serves, or nil when vmrest did not report a usable subnet/mask.
func vmnetCIDR(v *vmware.Vmnet) *net.IPNet {
	ip := net.ParseIP(v.Subnet).To4()
	if ip == nil || v.Mask == "" {
		return nil
	}
	m4 := net.ParseIP(v.Mask).To4()
	if m4 == nil {
		return nil
	}
	m := net.IPMask(m4)
	if ones, bits := m.Size(); ones == 0 && bits == 0 {
		return nil // not a canonical mask
	}
	return &net.IPNet{IP: ip.Mask(m), Mask: m}
}

// tfType maps vmrest's network type to the resource's `type` value.
func tfType(rest string) string {
	switch strings.ToLower(rest) {
	case "nat":
		return "nat"
	case "bridged":
		return "bridged"
	default:
		return "hostonly"
	}
}

func (r *networkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nets, err := r.client.Rest.ListVmnets()
	if err != nil {
		resp.Diagnostics.AddError("listing vmnets", err.Error())
		return
	}
	for i := range nets {
		n := &nets[i]
		if n.Name != state.Name.ValueString() {
			continue
		}
		if n.Mask != "" {
			state.Mask = types.StringValue(n.Mask)
		}
		state.DHCP = types.BoolValue(n.DHCP == "true")
		// Report a subnet changed outside Terraform (the VMs' static addresses no longer fit it). The configured string is
		// kept when it denotes the same network, so a non-canonical value (10.0.0.5/24) never shows a diff.
		if live := vmnetCIDR(n); live != nil {
			if _, cur, err := net.ParseCIDR(state.Subnet.ValueString()); err != nil || cur.String() != live.String() {
				state.Subnet = types.StringValue(live.String())
			}
		}
		if n.Type != "" && (state.Type.IsNull() || !strings.EqualFold(restType(state.Type.ValueString()), n.Type)) {
			state.Type = types.StringValue(tfType(n.Type))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	resp.State.RemoveResource(ctx)
}

func (r *networkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state networkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Nothing about a vmnet can be changed through vmrest. Keep every known value from state so Terraform never
	// sees an unknown after apply, and tell the user why their dhcp setting did not take.
	if !plan.DHCP.IsNull() && !plan.DHCP.IsUnknown() && plan.DHCP.ValueBool() != state.DHCP.ValueBool() {
		resp.Diagnostics.AddWarning("vmnet settings are immutable",
			fmt.Sprintf("%s has dhcp=%t and VMware's API cannot change it; remove `dhcp` from the configuration (or recreate the network)",
				state.Name.ValueString(), state.DHCP.ValueBool()))
	}
	state.Type = plan.Type
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if !state.Adopted.IsNull() && !state.Adopted.ValueBool() {
		resp.Diagnostics.AddWarning("vmnet kept", fmt.Sprintf("VMware offers no API to delete %s; it stays configured until it is "+
			"removed from VMware's network settings (cloudseed's destroy does this when it may use sudo) and is adopted on the next apply",
			state.Name.ValueString()))
		return
	}
	resp.Diagnostics.AddWarning("vmnet kept", fmt.Sprintf("%s existed before it was adopted, so it is left configured", state.Name.ValueString()))
}

// ImportState adopts an existing vmnet by name (e.g. `terraform import vmdesktop_network.private vmnet2`).
func (r *networkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("adopted"), true)...)
}
