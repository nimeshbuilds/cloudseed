package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/cloudseed/terraform-provider-vmdesktop/internal/vmware"
)

// Client is shared by resources and data sources.
type Client struct {
	Host *vmware.Host
	Rest *vmware.Rest
}

type vmdesktopProvider struct{ version string }

type providerModel struct {
	VmrunPath      types.String `tfsdk:"vmrun_path"`
	VdiskPath      types.String `tfsdk:"vdiskmanager_path"`
	VmrestURL      types.String `tfsdk:"vmrest_url"`
	VmrestUser     types.String `tfsdk:"vmrest_user"`
	VmrestPassword types.String `tfsdk:"vmrest_password"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &vmdesktopProvider{version: version} }
}

func (p *vmdesktopProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vmdesktop"
	resp.Version = p.version
}

func (p *vmdesktopProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "VMware Fusion Pro / Workstation Pro: virtual networks and VMs via vmrun, vmware-vdiskmanager and vmrest.",
		Attributes: map[string]schema.Attribute{
			"vmrun_path":        schema.StringAttribute{Optional: true, Description: "Path to vmrun (auto-detected)."},
			"vdiskmanager_path": schema.StringAttribute{Optional: true, Description: "Path to vmware-vdiskmanager (auto-detected)."},
			"vmrest_url":        schema.StringAttribute{Optional: true, Description: "vmrest base URL (default http://127.0.0.1:8697)."},
			"vmrest_user":       schema.StringAttribute{Optional: true, Description: "vmrest user (or VMREST_USER)."},
			"vmrest_password":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "vmrest password (or VMREST_PASSWORD)."},
		},
	}
}

func (p *vmdesktopProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	host, err := vmware.Detect(cfg.VmrunPath.ValueString(), cfg.VdiskPath.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("VMware Desktop not found", err.Error())
		return
	}
	user := cfg.VmrestUser.ValueString()
	if user == "" {
		user = os.Getenv("VMREST_USER")
	}
	pass := cfg.VmrestPassword.ValueString()
	if pass == "" {
		pass = os.Getenv("VMREST_PASSWORD")
	}
	url := cfg.VmrestURL.ValueString()
	if url == "" {
		url = os.Getenv("VMREST_URL")
	}
	client := &Client{Host: host, Rest: vmware.NewRest(url, user, pass)}
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *vmdesktopProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewNetworkResource, NewVMResource}
}

func (p *vmdesktopProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewHostDataSource}
}
