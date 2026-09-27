---
title: Kubernetes access from your workstation and bastion
description: "Use Cloudseed-managed cluster access from the original controller, or an explicitly authorized local kubeconfig on a bastion, without copying Terraform state or SSH keys."
---

# Kubernetes access

Cloudseed normally runs on the machine that created the environment, called the **controller** here. It keeps the
environment configuration, Terraform state or backend configuration, SSH keys, outputs and cluster connection
files there. A bastion provides a route to the private network and a place to run cluster administration tools.

Provisioning installs `cloudseed` and its `cs` alias on bastions. That installation makes the CLI available; it does
not clone the controller's environment, copy its keys or kubeconfig, or grant a new cloud identity access.

| Where you run the command | Cluster selection | Credentials and connection |
| --- | --- | --- |
| Controller: `cs kubectl aws --env dev get nodes` | The saved Cloudseed environment | Its own kubeconfig, the controller's authorized cloud identity, and an automatic bastion tunnel when needed |
| Controller: plain `kubectl get nodes` | Your current kubeconfig context | Merge the environment with `cs k8s kubeconfig` first, or set `KUBECONFIG` explicitly |
| Bastion: `cs kubectl --local-context get nodes` | The host's existing kubeconfig context | You explicitly authenticate and prepare that kubeconfig on the bastion |
| Bastion: plain `kubectl get nodes` | The same host kubeconfig context | The same authorization and private network route |

## From the controller

```bash
cs k8s info aws --env dev
cs env use aws-dev
cs kubectl get nodes -o wide
cs helm list -A
cs k9s
```

Use `gcp`, `azure` or `vmware` and the corresponding environment name for the other targets. Explicit cloud and
environment arguments select that environment; otherwise the selected environment, the only available cluster, or
an interactive choice determines the target. `cs kubectl`, `cs helm` and `cs k9s` use
`<workdir>/k8s/kubeconfig`, independently of your global current context.

Managed-cloud kubeconfigs come from these provider commands, using saved cluster identifiers:

| Target | Kubeconfig source | Authentication |
| --- | --- | --- |
| AWS EKS | `aws eks update-kubeconfig` with the cluster name, region and configured profile | `aws eks get-token` uses your authorized AWS identity; FIPS environments pin the FIPS token endpoint setting |
| Google Cloud GKE | `gcloud container clusters get-credentials` with project and location; `--internal-ip` for a private endpoint | `gke-gcloud-auth-plugin` must be installed and the selected Google identity authorized |
| Azure AKS | `az aks get-credentials` with resource group and subscription | Your signed-in Azure identity must be allowed to obtain and use the cluster credentials |
| VMware RKE2 / kubeadm | Ansible retrieves the first control plane's kubeconfig and stores it on the controller | The fetched cluster credential; the API uses the control plane's host-only network address |

For a cloud API that the controller cannot reach directly, Cloudseed opens an SSH local forward through the
bastion, sets the kubeconfig server to a loopback port and retains TLS verification against the original API name.
It prepares kubectl before configuring this tunnel and stops if it cannot update the kubeconfig. The controller
still supplies cloud authentication; forwarding through a bastion does not use the bastion's cloud identity.

For plain kubectl or other Kubernetes clients:

```bash
cs k8s kubeconfig aws --env dev
kubectl get nodes
```

This merges the cluster into the first file in `KUBECONFIG`, or `~/.kube/config`, and selects its context. A context
using a loopback tunnel works while that tunnel is running. Reopen with `cs k8s tunnel aws --env dev`; close with
`cs k8s untunnel aws --env dev`. To switch an existing tunnel to a direct VPN route, connect the VPN, close the
tunnel, then rerun `cs k8s kubeconfig aws --env dev`.

Private AKS clusters created by the current stack publish a DNS name that resolves to the private API address;
that does not make the API public. Older environments using only a `privatelink` name may need the bastion tunnel
until their DNS configuration is updated. See [VPN access](vpn.md) and [troubleshooting](troubleshooting.md).

## From a bastion

Connect from the controller with `cs ssh CLOUD --env NAME`. On the bastion, `cs help`, `cs doctor` and `cs install`
are available without recreating the original infrastructure environment. When Kubernetes and tool provisioning
are enabled, bastions receive kubectl, Helm and k9s; cloud bastions also receive their provider CLI, and GCP includes
the GKE authentication plugin. Downloads use checksum verification. Optional tool provisioning can be disabled
with `--no-tools`; the core `cloudseed` and `cs` commands are still installed. `--no-provision` skips configuration,
and `--sync-only` only transfers the payload.

Prepare a kubeconfig using one of the following provider-specific paths. Replace uppercase names with values
shown by `cs k8s info` and `cs output` on the controller. Run login and credential commands as the bastion user who
will run kubectl, so they write that user's credential files.

### AWS

The stack grants the bastion instance role permission to describe its own EKS cluster and an EKS cluster-admin
access entry. With the bastion's instance role as the active AWS identity:

```bash
aws eks update-kubeconfig --name CLUSTER --region REGION
kubectl config current-context
cs kubectl --local-context get nodes
cs helm --local-context list -A
```

An overriding AWS profile or environment credential uses that identity instead; it needs its own cluster access.
Authorized operators on this bastion can use its instance role's cluster administration access. Restrict who can
log in to the bastion and use separate, narrower Kubernetes permissions when full administration is unnecessary.
See the [AWS kubeconfig command reference](https://docs.aws.amazon.com/cli/latest/reference/eks/update-kubeconfig.html).

### Google Cloud

The default bastion service account has logging and monitoring permissions, not GKE administration rights. Sign in
with an identity already authorized for the cluster, following your organization's access policy:

```bash
gcloud auth login --no-launch-browser
gcloud container clusters get-credentials CLUSTER --project PROJECT --location LOCATION --internal-ip
kubectl config current-context
cs kubectl --local-context get nodes
```

The [Google login flow](https://docs.cloud.google.com/sdk/gcloud/reference/auth/login) can use a browser on another
trusted machine. The bastion has the GKE authentication plugin. Signing in selects an identity; it does not grant
that identity missing IAM or Kubernetes permissions.

### Azure

The bastion has a system-assigned managed identity, but the stack does not grant it AKS access. Use an already
authorized Azure user or an explicitly authorized workload identity. For an interactive user:

```bash
az login --use-device-code
az aks get-credentials --resource-group RESOURCE_GROUP --name CLUSTER --subscription SUBSCRIPTION
kubectl config current-context
cs kubectl --local-context get nodes
```

Follow the [Azure interactive login flow](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli-interactively)
and your organization's access policy. The private endpoint is reachable from the bastion's VNet; `az login
--identity` alone does not add the missing AKS permissions. Any credential plugin referenced by an externally
configured cluster's kubeconfig must also be installed on the bastion.

### VMware

The workstation reaches the cluster on the host-only network. Provisioning fetches its admin kubeconfig to that
workstation; it does not put that credential on the bastion. Keep the standard controller commands for this path:

```bash
cs kubectl vmware --env lab get nodes
```

If a cluster owner explicitly issues a separate, appropriately scoped kubeconfig for a bastion user, that user can
select the authorized kubeconfig and use `cs kubectl --local-context`. Kubernetes-enabled bastions provision kubectl,
Helm and k9s unless `--no-tools` was selected; missing tools can be installed with `cs install kubectl helm k9s`.
Cloudseed does not automatically issue that credential or copy the controller's admin kubeconfig.

## What local-context mode changes

`cs kubectl --local-context`, `cs helm --local-context` and `cs k9s --local-context` use the invoking host's
`KUBECONFIG` or default kubeconfig. Verify the target first with `kubectl config current-context`. They do not
select a Cloudseed environment, fetch credentials, create an SSH tunnel, read Terraform state or create Cloudseed
undo points. The kubeconfig's identity and Kubernetes permissions govern the operations.

This mode requires an HTTPS API endpoint and enabled TLS certificate verification. Configure the cluster's CA in
the kubeconfig; insecure HTTP endpoints and certificate-verification bypasses are refused. Select a complete
context with `--context NAME` (`--kube-context NAME` for Helm), rather than a separate `--cluster` override.
Helm's `HELM_KUBECONTEXT` setting is honored when an explicit context is absent. Endpoint and TLS overrides are
checked before executing the command. A saved insecure TLS setting must be repaired in the kubeconfig; a false
command-line override alone is insufficient. Cloudseed displays the selected context; verify that it is the
intended cluster before making changes. Validation happens at launch. Native tools such as k9s can switch contexts
afterward, so check the active cluster when using their interactive interface.

Without `--local-context`, these commands still require a saved Cloudseed environment. A provider-generated
kubeconfig alone does not make `cs env use aws-dev` work on the bastion. Keep infrastructure changes, provisioning,
Cloudseed platform workflows and environment scans on the original controller. Running `cs setup` on a fresh
bastion is not an import or attachment to the controller's environment.

The same explicit local-context selection is available in the kubectl/Helm MCP and console interfaces. It uses the
kubeconfig on the machine hosting that interface; a workstation-hosted console does not switch to the bastion.
The console labels this option **Use this host's kubeconfig** and does not require a saved environment. MCP and
agent operations require explicit approval for this mode, including reads, because the host target is outside a
Cloudseed-managed environment. Agent output redaction and noninteractive restrictions still apply. Interactive
k9s belongs in a terminal.
