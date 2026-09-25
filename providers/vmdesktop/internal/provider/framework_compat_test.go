package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Exercise the Framework's complete planning pipeline, including nested plan modifiers.
// Calling nicListsDiffer alone does not catch changes to the Framework's null-state handling.
func TestFrameworkPlansGeneratedNICAddresses(t *testing.T) {
	ctx := context.Background()
	empty := schemaOf(t, NewVMResource())
	prior := vmPlan(&harness{dir: t.TempDir()}, "/base.vmdk")
	prior.ID = types.StringValue("/vms/test.vmx")
	prior.VMXPath = prior.ID
	prior.IP = types.StringValue("10.0.0.9")
	prior.IPs = types.ListValueMust(types.StringType, nil)
	prior.Networks = []nicModel{{Type: types.StringValue("nat"), Vmnet: types.StringNull(),
		MAC: types.StringValue("00:50:56:01:02:03"), IP: types.StringValue("10.0.0.9")}}

	dynamic := func(value tftypes.Value) *tfprotov6.DynamicValue {
		t.Helper()
		result, err := tfprotov6.NewDynamicValue(value.Type(), value)
		if err != nil {
			t.Fatal(err)
		}
		return &result
	}
	for _, addNIC := range []bool{false, true} {
		name := "cpu update preserves generated MAC"
		if addNIC {
			name = "new NIC MAC stays unknown until replacement"
		}
		t.Run(name, func(t *testing.T) {
			config := prior
			config.ID, config.VMXPath, config.IP = types.StringNull(), types.StringNull(), types.StringNull()
			config.IPs = types.ListNull(types.StringType)
			config.CPUs = types.Int64Value(4)
			config.Networks = []nicModel{{Type: types.StringValue("nat"), Vmnet: types.StringNull(),
				MAC: types.StringNull(), IP: types.StringNull()}}
			proposed := config
			proposed.Networks = append([]nicModel(nil), prior.Networks...)
			if addNIC {
				newNIC := nic(types.StringValue("hostonly"), types.StringNull(), types.StringNull(), types.StringNull())
				config.Networks = append(config.Networks, newNIC)
				proposed.Networks = append(proposed.Networks, newNIC)
			}
			server := providerserver.NewProtocol6(New("test")())()
			response, err := server.PlanResourceChange(ctx, &tfprotov6.PlanResourceChangeRequest{
				TypeName: "vmdesktop_vm", PriorState: dynamic(stateFrom(t, empty, prior).Raw),
				Config:           dynamic(stateFrom(t, empty, config).Raw),
				ProposedNewState: dynamic(stateFrom(t, empty, proposed).Raw),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, diagnostic := range response.Diagnostics {
				if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
					t.Fatalf("plan: %s: %s", diagnostic.Summary, diagnostic.Detail)
				}
			}
			raw, err := response.PlannedState.Unmarshal(empty.Raw.Type())
			if err != nil {
				t.Fatal(err)
			}
			var planned vmModel
			plan := tfsdk.Plan{Schema: empty.Schema, Raw: raw}
			noErrors(t, "planned model", plan.Get(ctx, &planned))
			if !planned.Networks[0].MAC.Equal(prior.Networks[0].MAC) {
				t.Fatalf("existing generated MAC changed: %v", planned.Networks[0].MAC)
			}
			if addNIC {
				if len(response.RequiresReplace) == 0 {
					t.Error("adding a NIC must replace the VM")
				}
				if !planned.Networks[1].MAC.IsUnknown() {
					t.Errorf("new generated MAC must stay unknown, got %v", planned.Networks[1].MAC)
				}
			} else if len(response.RequiresReplace) != 0 {
				t.Errorf("CPU update unexpectedly replaces VM: %v", response.RequiresReplace)
			}
		})
	}
}
