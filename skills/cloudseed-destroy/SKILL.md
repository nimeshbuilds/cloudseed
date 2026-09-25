---
name: cloudseed-destroy
description: Safe teardown procedure for cloudseed-managed environments - full clean-slate destroy, partial destroy by module/resource, and removing remote state. Use when the user asks to delete, tear down, remove, or destroy anything cloudseed created.
---

# Destroying with cloudseed

Destruction is irreversible. Follow this order every time.

1. **Identify** the environment: `cloudseed list`, then `cloudseed status <cloud> --env <env>` to see the resource count and outputs.
2. **Decide scope** with the user:
   - *Everything* → `cloudseed destroy <cloud> --env <env>` (add `--auto-approve` only after the user confirmed; interactive runs require typing the env id).
   - *Specific parts* → `cloudseed destroy <cloud> --env <env> --target <address>` (repeatable / comma-separated).
     Typical targets (aws, gcp, azure): `module.stack.module.bastion`, `module.stack.module.security_baseline`,
     `module.stack.module.network`, `module.stack.module.kubernetes`, `module.stack.module.vpn`. Use the module address
     without an index: it covers every instance on every cloud (`security_baseline[0]` only exists on AWS and matches
     nothing on GCP/Azure). vmware has only `module.stack.module.bastion`, `module.stack.module.workloads` and
     `module.stack.module.kubernetes`. When unsure of an address, let the user pick from the numbered list of the
     environment's real modules and resources: `--select`.
3. **Preview first**: without `--auto-approve` (and with `-y` or no terminal) nothing is destroyed: the command prints the
   destroy plan and stops with exit code 3. When the state is already empty it lists what it would still remove
   (leftover VMs, a vmnet, the state storage, the working directory, a GCP OS Login key cloudseed registered) and also
   stops with exit code 3 (exit 0, with nothing touched, when nothing is left at all). Summarize it, then re-run with
   `--auto-approve` when approved.
4. **Remote state**: only add `--purge-state` when the user wants the state bucket / storage account gone too (clean slate). Never delete state while resources still exist.
5. **Local files**: `--purge` removes the working directory - all of the default `~/.cloudseed/envs/<cloud>-<env>`;
   from a new / empty `setup --workdir` only cloudseed's own files, and the directory itself only when nothing else is
   left in it (files the user added since stay). It is not a complete wipe: the audit trail and final
   inventory are kept in `~/.cloudseed/logs/purged/<cloud>-<env>/`, and `config.json` plus the SSH keys (private key
   included) are kept in the undo journal (`~/.cloudseed/undo/`, 0700) so `cloudseed undo` can re-create the environment.
   Those copies are deleted with that undo entry (undone, dropped with `cloudseed undo --id <id> --drop`, or pushed out of
   the history by newer changes). Undoing the purge, deployed or not, puts the environment back into its own working
   directory (a custom `--workdir` is registered again; see Notes). Ask before using `--purge`.
6. **Report** what was removed and what remains:
   - the kept copies from step 5 (and the remote state storage when `--purge-state` was not used - it is billable);
   - AWS: a full destroy deletes CloudTrail (and its bucket), GuardDuty, Access Analyzer, Security Hub and the AWS Config
     recorder, but leaves the S3 account public-access block, EBS encryption by default (in the environment's region),
     the IAM password policy and the AWS Config service-linked role in place, no longer managed (they protect the whole
     account or region);
   - Azure: Microsoft Defender plans and the Ubuntu Pro FIPS image terms stay on for the subscription (the destroy
     prints how to turn them off);
   - GCP: the enabled APIs stay on, and the project-wide logging settings are kept, no longer managed: the `_Default`
     log retention stays at the value cloudseed set (`log_retention_days`, 90 by default; Google never restores an
     earlier value, and retention past 30 days is billed - reset it with `gcloud logging buckets update _Default
     --location=global --retention-days=30 --project <project>`), and with `enable_data_access_audit_logs` the Data
     Access audit config (allServices) stays on for the project. With OS Login, cloudseed removes the environment's
     SSH key from the user's Google account when it registered it and no other environment uses it; a key the user
     had registered before stays (when gcloud is missing or the removal fails, the destroy prints the command:
     `gcloud compute os-login ssh-keys remove --key=<fingerprint>`; list them with
     `gcloud compute os-login ssh-keys list`);
   - vmware: only this environment's VMs are removed; other VMs in the same directory are listed and left alone. The
     built-in vmnet1 is kept; with `--purge`, vmrest is stopped only when cloudseed started it, no other VMware
     environment is left and no VM is running.

Notes
- Partial destroys leave the config intact; `cloudseed apply` recreates the removed parts.
- A `--target` destroy also removes everything that depends on the target: Terraform adds the dependents to the plan.
  `--target module.stack.module.network` (aws/gcp/azure) also deletes the bastion host (VM, security groups / NIC,
  EIP association), the VPN host and the Kubernetes cluster (with the cluster cleanup below); only parts that do not
  reference the network stay (e.g. the bastion's key pair and IAM role). The confirmation count includes those
  dependents. Read the plan, tell the user about every deletion outside the targets, and never assume the cloud will
  refuse. To keep the bastion or the cluster, do not target the network (vmware has no network module).
- On AWS the CloudTrail bucket is emptied and deleted (`force_destroy`) — warn the user that audit logs go with it.
- EKS / GKE: before the cluster is deleted (a full destroy, or a `--target` whose plan deletes the cluster) cloudseed
  removes what Kubernetes created in the cloud: Karpenter NodePools (their instances), Gateways, Ingresses, Services of
  type LoadBalancer, StatefulSets with volume claim templates and volumes with reclaim policy Delete. The cluster must be
  reachable for that (the VPN or the bastion tunnel); if it is not, cloudseed says what to delete by hand - pass that on
  before continuing, or the network deletion can fail and costs keep running. (AKS keeps them in its node resource group.)
- A destroy is itself undoable: `cloudseed undo` re-runs setup with the same settings (new hosts, new addresses).
  Undoing a `--purge` puts the environment back into its own working directory (a custom `--workdir` is registered
  again) and makes it the current environment again when it was.

## Operational workflows across interfaces

Use `cloudseed ops list --json` for the installed contract before selecting parameters. The CLI form is
`cloudseed ops ACTION <cloud> --env <name> --params '{...}' --json`; MCP exposes `cloudseed_ops_ACTION` with
hyphens replaced by underscores and individual JSON fields. The console uses All actions → Operations & readiness.
Preview changes before `--approve` / MCP `confirm:true`, honoring explicit authorization already given by the user.

- `health`/`network` use local evidence by default; `live:true` queries deployed resources. An active network probe
  additionally needs `active:true` and approval, creates a temporary workload and reports its cleanup.
- `profile` previews lab/team/production topology and incomplete costs. `spec-export`, `spec-validate`, `spec-diff`
  and `spec-import` handle a versioned document without credentials/keys/state/runtime paths. Import/profile approval
  saves configuration only; Terraform apply, platform installs and backup schedules are separate approved actions.
- `policy-check` shows budget coverage and destructive plan actions. Never invent a complete estimate or suppress
  an unknown cost to satisfy a budget. `expiry-cleanup` requires saved elapsed expiry, saved opt-in and explicit
  approval for the exact environment; it never schedules future destruction or purges recovery state.
- `drift` is read-only. `upgrade-plan` needs an exact supported version, recent completed backup and operator
  compatibility review; `upgrade-apply` takes the fresh saved plan and repeats identity/readiness gates. It has no
  automatic downgrade guarantee.
- `recovery-plan`/`recovery-test` use a separate restricted namespace; review network isolation and external effects.
  Inspect object/data/volume coverage, measured RTO/RPO and asynchronous cleanup. Do not equate an object restore
  with proven application/database recovery.
- `acceptance` is preview-only without explicitly supplied sandbox identity, region, estimate, deadline and SSH
  source. Live execution additionally needs live + allow_cloud_changes + approval; retain cleanup evidence.
- `release-verify` checks a trusted digest and optional GitHub attestation without executing the artifact. A local
  digest match without verified provenance stays incomplete. `credentials-backend` can migrate storage to an
  available native keychain; never read or print credential values.

Follow scenarios 16–19 and the interface/coverage guide for complete workflows. Reports may remain INCOMPLETE when
live accounts/tools or manual reviews are absent. State the checks actually run and the limits of their evidence.
