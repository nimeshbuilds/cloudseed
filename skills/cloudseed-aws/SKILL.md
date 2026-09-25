---
name: cloudseed-aws
description: AWS specifics for the cloudseed CLI - what `cloudseed setup aws` builds (VPC, bastion, baseline, optional EKS / VPN / FIPS), its variables, outputs and gotchas (CloudTrail/GuardDuty/Access Analyzer singletons, NAT cost, account-wide and regional baseline, adopted resources). Use together with the cloudseed skill when the target cloud is AWS.
---

# cloudseed on AWS

`cloudseed setup aws --env <env>` builds, in one region:

- **VPC** (`<cidr>`, default first free `10.N.0.0/16`), DNS on, default security group stripped of all rules.
- **Subnets per AZ** (default 2 AZs): `public` (bastion, NAT; tagged `kubernetes.io/role/elb` for internet-facing load balancers), `private` (workloads, egress via NAT; tagged `kubernetes.io/role/internal-elb` for internal ones), `data` (no internet route at all, no load balancer tag). The layout is pinned by `subnet_stride` (the AZ count of the first deployment), so `az_count` can change later: new AZs get new subnets and nothing is re-addressed.
- **NAT**: single gateway by default (`single_nat_gateway=true`); set `false` for one per AZ.
- **VPC flow logs** → KMS-encrypted CloudWatch log group (30-day retention by default).
- **Bastion**: Amazon Linux 2023, `t3.micro`, IMDSv2 required, encrypted gp3 root, Elastic IP, SSH (22) only from `allowed_ssh_cidrs`, egress limited to 443/80/NTP and SSH into the VPC. Instance profile has `AmazonSSMManagedInstanceCore`, so Session Manager works as a no-inbound alternative; with EKS it may also run `aws eks update-kubeconfig` (`eks:DescribeCluster` on the environment's cluster), and provisioning installs kubectl of the cluster's minor version (sha256-verified): on the bastion run `aws eks update-kubeconfig --name <cluster> --region <region>`, then kubectl. In FIPS mode its login shells export `AWS_USE_FIPS_ENDPOINT=true`. User: `ec2-user`.
- **Workload security group** (`<name>-<env>-private-workloads`): SSH only from the bastion SG. Attach it to private instances.
- **KMS CMK** with rotation for the flow/CloudWatch logs, CloudTrail and the bastion/VPN disks.
- **Account-wide baseline** (`enable_account_baseline=true`, ONE env per account): S3 account public-access block, IAM password policy, multi-region CloudTrail (log validation, KMS, S3 with TLS-only policy, CloudWatch Logs); EBS encryption by default is switched on in its region with it.
- **Regional baseline** (`enable_regional_baseline`, null = follows `enable_account_baseline`; ONE env per account AND region): EBS encryption by default (AWS-managed `aws/ebs` key, so node groups, Karpenter and the EBS CSI driver can use it), GuardDuty, IAM Access Analyzer, and optional Security Hub FSBP (`enable_security_hub=true`), which also turns on AWS Config recording (delivered to the baseline log bucket - also without CloudTrail -, billed per recorded item; `enable_aws_config=false` where Config already records in the region, e.g. Control Tower).
- **Remote state** (when chosen): S3 bucket, versioned, SSE-KMS, public access blocked, TLS-only, native lockfile locking (no DynamoDB).
- **EKS** (optional, `enable_kubernetes=true`, needs `az_count >= 2`): private cluster in the private subnets (private API endpoint unless `kubernetes_public_endpoint=true`), managed node group (AL2023; Bottlerocket FIPS AMIs in FIPS mode), KMS secret encryption, control-plane logs, core add-ons, an access entry for the bastion role only (VPN users reach the API with their own IAM identity: they need their own access entry), and IRSA roles for the EBS CSI driver, AWS Load Balancer Controller, cluster-autoscaler, external-secrets and external-dns. external-secrets may read only Secrets Manager secrets / SSM parameters under `external_secrets_prefixes` (default `<name>-<env>/`, e.g. secret `acme-dev/db`, parameter `/acme-dev/db`; `["*"]` = the whole account). Velero (bucket + role) and Karpenter (node role, instance profile, access entry, interruption queue, discovery tags; least-privilege controller policy) are added by `cloudseed platform install velero|karpenter`. After creation the node group is resized through the EKS API (`cloudseed node add|remove|scale`).
- **VPN host** (optional, `enable_vpn=true`): Ubuntu 24.04 in the public subnet running OpenVPN (default) or a Tailscale subnet router (`vpn_type=tailscale`, needs `TS_AUTHKEY`).
- **FIPS 140** (optional, `fips_mode=true`, new environments only): FIPS endpoints for the provider and the S3 backend (so us-east-1/2, us-west-1/2 or GovCloud only), Bottlerocket FIPS nodes, `fips-mode-setup` on the AL2023 bastion; the Ubuntu VPN host needs `UBUNTU_PRO_TOKEN` (Ubuntu Pro fips-updates). SSH keys are RSA-4096 (EC2 refuses ECDSA; a key you bring must be RSA-4096). Tailscale, kubeadm and ed25519 keys are refused.

## Variables (`--var name=value`)

Complete list with defaults, generated from the Terraform: `cloudseed help variables aws`.

- Network: `vpc_cidr` (via `--cidr`; default: first free `10.N.0.0/16`), `az_count` (2; may change on a deployed env), `subnet_newbits` (4), `subnet_stride` (null = `az_count`; pinned by cloudseed at the first setup - never set it by hand), `single_nat_gateway` (true), `create_data_subnets` (true), `enable_flow_logs` (true), `flow_log_retention_days` (30).
- Bastion: `bastion_instance_type` (t3.micro; Graviton types pick arm64 AMIs automatically), `bastion_root_volume_size` (10).
- Baseline: `enable_account_baseline` (true), `enable_regional_baseline` (null = same as `enable_account_baseline`), `enable_cloudtrail` (true), `enable_guardduty` (true), `enable_access_analyzer` (true; false when an account analyzer already exists in the region), `enable_security_hub` (false), `enable_aws_config` (null = on together with Security Hub; false when Config already records in the region), `log_retention_days` (365), `kms_deletion_window_in_days` (7), `tags` (map, or `--tag K=V`).
- EKS: `enable_kubernetes` (false), `kubernetes_version` (null = current default), `kubernetes_node_size` (t3.medium), `kubernetes_node_count` (2; a count above `kubernetes_node_max` raises the max automatically), `kubernetes_node_min` (1), `kubernetes_node_max` (4), `kubernetes_public_endpoint` (false), `external_secrets_prefixes` (null = `<name>-<env>/`: the Secrets Manager / SSM prefixes external-secrets may read).
- VPN: `enable_vpn` (false), `vpn_type` (openvpn | tailscale), `vpn_instance_type` (t3.micro), `vpn_port` (1194, OpenVPN UDP, 1-65535; Tailscale always uses 41641, which the `vpn_port` output reports).
- `fips_mode` (false).
- `platform_prereqs`: managed by `cloudseed platform install` - never set it by hand.
- Refused in `--var` (cloudseed sets them): `name` (`--name`), `environment` (`--env`), `vpc_cidr` (`--cidr`), `allowed_ssh_cidrs` (`--allow-ip` / `update-ip`), `ssh_public_key` (`--ssh-public-key`), `tags` (`--tag`).

Shortcut flags: `--profile <aws profile>`.

## Outputs

Complete list with descriptions: `cloudseed help outputs aws`.

- Core: `account_id`, `region`, `vpc_id`, `vpc_cidr`, `public_subnet_ids`, `private_subnet_ids`, `data_subnet_ids`, `nat_public_ips`, `bastion_public_ip`, `bastion_instance_id`, `bastion_security_group_id`, `workload_security_group_id`, `kms_key_arn`, `cloudtrail_bucket`, `ssh_user`, `fips_mode`.
- EKS: `kubernetes_cluster_name`, `kubernetes_endpoint`, `kubernetes_node_group_name`, `kubernetes_node_role_arn`, `kubernetes_oidc_issuer`, `kubernetes_oidc_provider_arn`, `kubernetes_irsa_role_arns`, `kubernetes_cluster_security_group_id`, `kubernetes_velero_bucket`, `kubernetes_karpenter_queue`, `kubernetes_karpenter_node_role`.
- VPN: `vpn_public_ip`, `vpn_instance_id`, `vpn_type`, `vpn_port`.

## Gotchas

- GuardDuty and Security Hub are per-region singletons and are never adopted; IAM Access Analyzer allows one account analyzer per region (not adjustable). When one already exists (not this environment's) and the environment only has it on by default (GuardDuty, Access Analyzer), setup leaves it alone: it saves `enable_guardduty=false` / `enable_access_analyzer=false` with the environment, says so, and plans again. Only when the variable was set true explicitly (Security Hub is always explicit) does setup stop before changing anything and name the fix - `--var enable_guardduty=false` / `--var enable_security_hub=false` / `--var enable_access_analyzer=false`.
- Other "already exists" resources are adopted only when their tags (`CloudseedEnv` + `Owner`) say they are this environment's; another environment's are refused, and an unreadable owner needs the user's yes (or `CLOUDSEED_ADOPT=1`). Adopted resources are deleted by `cloudseed destroy`. After an adoption the new plan is shown for approval again.
- A second environment in the same account AND region uses `--var enable_account_baseline=false` (the regional half follows it). An environment alone in another region of the same account uses `--var enable_account_baseline=false --var enable_regional_baseline=true`, so that region still gets EBS encryption by default, GuardDuty and Access Analyzer.
- `az_count` can change on a deployed environment: the subnet layout is pinned by `subnet_stride`, new AZs get new subnets and nothing is re-addressed (fewer AZs remove the last AZs' subnets, which fails while something still runs in them).
- `--tag` on AWS: keys of 1-128 and values of up to 256 letters, digits, spaces and `_ . : / = + - @` (IAM's set), no key starting with `aws:`. Where the environment creates the GuardDuty detector (the regional baseline with `enable_guardduty` on, the default) keys are narrower: ASCII letters, digits and `_ . : / = + -` only (no space, no `@`), so `Cost Center` needs `Cost-Center` there or `--var enable_guardduty=false`. Setup refuses anything else before Terraform runs.
- AWS China (`cn-*`) and the isolated ISO regions are not supported (setup refuses them).
- IAM role names include `<name>-<env>`: the same env name in two regions of one account would collide with the other environment's roles. Use different env names.
- A full destroy deletes CloudTrail (with its bucket), GuardDuty, Access Analyzer, Security Hub and the Config recorder, but leaves the S3 account public-access block, EBS encryption by default (in its region), the IAM password policy and the AWS Config service-linked role in place (unmanaged).
- With EKS, destroy first deletes what controllers created outside Terraform state (Karpenter NodePools and their instances, Gateway/Ingress/LoadBalancer NLBs, PVC-templated StatefulSets and Delete-policy EBS volumes); the cluster must be reachable (VPN or the bastion tunnel), otherwise it tells you what to delete by hand before the VPC deletion fails.
- Credentials: `aws configure`, `aws sso login`, or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars. Never handle the values yourself.
- Cost drivers: NAT gateway (hourly + per GB), bastion, EKS control plane + nodes, VPN host, CloudTrail/GuardDuty, AWS Config (with Security Hub). Destroying the env removes what Terraform created.

## Well-Architected assessment

Run `cloudseed scan architecture aws --env prod --profile production --max-age-days 30 --json` to assess
saved configuration and local evidence without cloud queries, provisioning or tool installation. The profile
selects assessment policy, not deployment settings. Reports distinguish definite failures from missing, stale
or manual-review evidence: PASS exits 0, FAIL 1, INCOMPLETE 3; invalid arguments exit 2. Read the
cloudseed-architecture skill for evidence limits and next steps. `scan all` excludes this assessment.
AWS findings map to its six Well-Architected pillars; this scoped assessment is not provider certification.
