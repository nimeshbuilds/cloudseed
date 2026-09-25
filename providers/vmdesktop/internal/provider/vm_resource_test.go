package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var nicType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"type": types.StringType, "vmnet": types.StringType, "mac": types.StringType, "ip": types.StringType,
}}

func nicList(t *testing.T, nics ...nicModel) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), nicType, nics)
	if d.HasError() {
		t.Fatal(d)
	}
	return l
}

func nic(typ, vmnet, mac, ip types.String) nicModel {
	return nicModel{Type: typ, Vmnet: vmnet, MAC: mac, IP: ip}
}

func TestNicChangesThatDoNotRebuild(t *testing.T) {
	s, n, u := types.StringValue, types.StringNull(), types.StringUnknown()
	state := nicList(t, nic(s("nat"), n, s("00:50:56:01:02:03"), s("172.16.5.10")),
		nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), s("")))
	config := nicList(t, nic(s("nat"), n, s("00:50:56:01:02:03"), n), nic(s("custom"), s("vmnet1"), s("00:50:56:0A:0B:0C"), n))
	cases := map[string]types.List{
		// any other change (cpus, a powered-off VM) marks the computed IPs unknown
		"ip unknown": nicList(t, nic(s("nat"), n, s("00:50:56:01:02:03"), u), nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), u)),
		// the VM was off ("" in state) and now reports an address
		"ip changed": nicList(t, nic(s("nat"), n, s("00:50:56:01:02:03"), s("172.16.5.99")), nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), s(""))),
	}
	for name, plan := range cases {
		differ, d := nicListsDiffer(context.Background(), config, plan, state)
		if d.HasError() || differ {
			t.Errorf("%s: rebuild=%v diags=%v", name, differ, d)
		}
	}
	// a MAC left out of the configuration keeps the generated one
	cfgNoMAC := nicList(t, nic(s("nat"), n, n, n), nic(s("custom"), s("vmnet1"), n, n))
	plan := nicList(t, nic(s("nat"), n, u, u), nic(s("custom"), s("vmnet1"), u, u))
	if differ, d := nicListsDiffer(context.Background(), cfgNoMAC, plan, state); d.HasError() || differ {
		t.Errorf("generated MAC: rebuild=%v diags=%v", differ, d)
	}
}

func TestNicChangesThatRebuild(t *testing.T) {
	s, n, u := types.StringValue, types.StringNull(), types.StringUnknown()
	state := nicList(t, nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), s("10.0.0.10")))
	cases := map[string][2]types.List{
		"mac": {nicList(t, nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0d"), n)),
			nicList(t, nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0d"), u))},
		"mac unknown in config": {nicList(t, nic(s("custom"), s("vmnet1"), u, n)),
			nicList(t, nic(s("custom"), s("vmnet1"), u, u))},
		"vmnet": {nicList(t, nic(s("custom"), s("vmnet2"), s("00:50:56:0a:0b:0c"), n)),
			nicList(t, nic(s("custom"), s("vmnet2"), s("00:50:56:0a:0b:0c"), u))},
		"type": {nicList(t, nic(s("nat"), n, s("00:50:56:0a:0b:0c"), n)),
			nicList(t, nic(s("nat"), n, s("00:50:56:0a:0b:0c"), u))},
		"nic added": {nicList(t, nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), n), nic(s("nat"), n, n, n)),
			nicList(t, nic(s("custom"), s("vmnet1"), s("00:50:56:0a:0b:0c"), u), nic(s("nat"), n, u, u))},
	}
	for name, c := range cases {
		differ, d := nicListsDiffer(context.Background(), c[0], c[1], state)
		if d.HasError() || !differ {
			t.Errorf("%s: rebuild=%v diags=%v", name, differ, d)
		}
	}
}
