package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type hostDataSource struct{ client *Client }

type hostModel struct {
	ID        types.String `tfsdk:"id"`
	Product   types.String `tfsdk:"product"`
	Version   types.String `tfsdk:"version"`
	OS        types.String `tfsdk:"os"`
	Arch      types.String `tfsdk:"arch"`
	GuestArch types.String `tfsdk:"guest_arch"`
	VmrunPath types.String `tfsdk:"vmrun_path"`
}

func NewHostDataSource() datasource.DataSource { return &hostDataSource{} }

func (d *hostDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (d *hostDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The local VMware Desktop installation (product, version, host and guest architecture).",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true},
			"product":    schema.StringAttribute{Computed: true, Description: "fusion or workstation"},
			"version":    schema.StringAttribute{Computed: true},
			"os":         schema.StringAttribute{Computed: true},
			"arch":       schema.StringAttribute{Computed: true},
			"guest_arch": schema.StringAttribute{Computed: true, Description: "architecture of guests this host can run: arm64 or amd64"},
			"vmrun_path": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *hostDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.client = req.ProviderData.(*Client)
}

func (d *hostDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	h := d.client.Host
	m := hostModel{
		ID:        types.StringValue(h.Product + "-" + h.OS + "-" + h.Arch),
		Product:   types.StringValue(h.Product),
		Version:   types.StringValue(h.Version),
		OS:        types.StringValue(h.OS),
		Arch:      types.StringValue(h.Arch),
		GuestArch: types.StringValue(h.GuestArch),
		VmrunPath: types.StringValue(h.VmrunPath),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
