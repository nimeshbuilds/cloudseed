// terraform-provider-vmdesktop: manage VMware Fusion Pro / Workstation Pro VMs and virtual networks
// through the tools VMware ships (vmrun, vmware-vdiskmanager, vmrest). Built and installed by cloudseed.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/cloudseed/terraform-provider-vmdesktop/internal/provider"
)

var version = "0.1.0"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with debugger support")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.local/cloudseed/vmdesktop",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
