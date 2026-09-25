---
name: cloudseed-platform
description: Kubernetes day-2 with the cloudseed CLI - choosing the current cluster (cs env), scaling nodes (cs node), installing the platform catalog in groups with cs platform (basek8s, scaling, data, ai, agentic, finops, devsecops, security, resilience, chaos), backups and restore drills (cs dr), chaos experiments (cs chaos), compliance scans (cs scan), and running kubectl/helm/k9s through cloudseed. Use with the cloudseed skill whenever the user wants tools installed on a cluster, nodes added/removed, backups, chaos tests or scans.
---

# cloudseed platform (Kubernetes day-2)

- `cs env` shows environments; `cs env use <cloud>-<env>` sets the one cluster commands act on. With one cluster it is implicit.
- `cs node add [--count N] [--role worker|control-plane]` / `cs node list` / `cs node remove <name>` /
  `cs node scale <cloud> --env X --count N [--min N] [--max N]`: EKS/GKE/AKS scale through the cloud API - add raises the
  pool and its autoscaler minimum, remove drains and deletes exactly that machine, scale sets the pool size and limits;
  vmware creates VMs and joins them automatically (RKE2 or kubeadm; there is no scale on vmware).
- `cs platform list` shows the catalog with what is installed; `--charts` adds each item's upstream source; `cs platform info <item>` shows chart, version, namespace, dependencies and values. `cs platform install <group|item ...>`:
  groups `basek8s` (metrics-server, cert-manager + the cluster CA issuer, Gateway API + Envoy Gateway with a private LB
  (MetalLB on vmware), argocd, kube-prometheus-stack, loki (Loki 3) + alloy (log collection), opentelemetry-operator,
  external-secrets, sealed-secrets; extras ingress-nginx, aws-load-balancer-controller, reloader, kyverno, external-dns),
  `scaling` (keda, vpa + metrics-server, goldilocks, cluster-autoscaler; extra karpenter on aws), `data` (minio,
  cloudnative-pg, strimzi, spark-operator, spark-history-server, trino, starrocks, polaris, airflow; extra
  clickhouse-operator), `ai` (kuberay, kubeflow-trainer, kserve, jupyterhub, mlflow; extras: kubeflow-pipelines,
  vllm-stack, gpu-operator, ollama), `agentic` (kagent - needs ANTHROPIC_API_KEY or OPENAI_API_KEY, skipped until one is
  set -, kmcp, agentgateway, qdrant; extras: langfuse, litellm, open-webui), `devsecops` (gitlab, gitlab-runner - skipped
  until GITLAB_RUNNER_TOKEN is set -, neuvector, trivy-operator, argocd, kyverno; extras harbor, artifactory, nexus,
  sonarqube; `cs platform template gitlab-ci` writes a ready CI pipeline), `security` (istio ambient or
  `--set mode=sidecar`, strict mTLS, falco, kyverno + kyverno-policies, cert-manager + cert-manager-issuer,
  external-secrets; extras istio-gateway, kiali, vault, kubescape-operator), `finops`, `resilience`, `chaos` (below).
  Dependencies are resolved; values adapt to the target/distro; already-installed releases are skipped unless
  `--upgrade` (which re-applies cloudseed's pinned chart version and first refreshes the CRDs a chart keeps in
  `crds/`). `--set key=value` (one item at a time) is remembered for that item and applied again by later installs and
  upgrades; `--set key-` forgets a key, uninstall forgets the item's values (`cs undo` restores them).
  `--set mode=ambient|sidecar` picks Istio's mode only when istio is part of the request (named, in a group such as
  `security`, or a dependency such as kiali); otherwise `mode=...` is an ordinary chart value
  (`cs platform install minio --set mode=distributed`). Items published
  for amd64 only (harbor, litmus, gitlab, kubeflow-pipelines, vllm-stack) are skipped on all-arm64 clusters (Apple
  silicon VMware guests) unless `--force`. `install` exits 1 when nothing asked for can be installed - read the
  reasons it prints.
- VMware RKE2 with `kubernetes_cis_profile=true` enforces the restricted Pod Security Standard: `cs platform install`
  first labels the namespaces of items whose pods need more (privileged: velero, local-path-provisioner, metallb,
  kube-prometheus-stack, falco, neuvector, kured, chaos-mesh, istio ambient, kubescape-operator, trivy-operator;
  baseline: minio, loki, alloy and similar), never lowering an existing label; `cs platform info <item>` shows the level.
  When the profile is off, `cs scan cis` failures on such a cluster come with the next step
  (`cs setup vmware --env NAME --var kubernetes_cis_profile=true`, then `cs provision vmware --env NAME --host k8s`).
- The user sets model keys and tokens themselves: `cs creds set ANTHROPIC_API_KEY` / `cs creds set GITLAB_RUNNER_TOKEN`
  (hidden prompt); you never handle the values.
- Networking is Gateway API first: `basek8s` installs the Gateway API CRDs and Envoy Gateway with a shared Gateway `cloudseed/cloudseed` (HTTPS with a wildcard cert from the cluster CA, private LB per cloud, MetalLB on vmware); apps attach HTTPRoutes. ingress-nginx is a legacy extra (GitLab still needs it).
- `cs platform ui` creates HTTPRoutes (or legacy Ingresses) with TLS for every installed UI and prints URLs, credential
  locations, the private ingress address and the /etc/hosts line; reach them over the VPN or the bastion (on vmware the
  MetalLB address is reachable from the host directly). The certificates come from the cluster CA (valid 10 years;
  the user imports it once). kagent's UI is put behind a password and falco's Falcosidekick UI gets one too. When the
  Gateway API stack is missing it shows the plan and asks before installing it (with -y: `--auto-approve`).
- `cs platform uninstall <group|item>` removes a group's own items only: shared dependencies (cert-manager, gateway-api,
  metallb, local-path) are never removed implicitly, an item another installed item still needs is refused unless
  `--force`, and namespaces left empty are deleted. Data stays: MinIO's volume (PVC minio/minio) and the Polaris
  database are kept, and cloudnative-pg stays while Postgres clusters exist - tell the user what is left.
- `finops` group: `cs platform install finops` (OpenCost + Prometheus + metrics-server + goldilocks; extras kube-green,
  kubecost-cost-analyzer), then `cs finops k8s`.
  Data group includes `spark-history-server` (event logs in MinIO) next to `spark-operator`, and `strimzi` deploys a dev Kafka cluster.
- `cs kubectl ...`, `cs helm ...`, `cs k9s` run against the current cluster with the per-environment kubeconfig
  (SSH tunnel through the bastion for private cloud endpoints). In an agent session their output is redacted and the
  interactive calls (k9s, `kubectl edit`, `kubectl exec/attach/run/debug -i/-t`) and calls that never end (`logs -f`,
  `get -w`, `port-forward`, `proxy`) are refused: use bounded forms (`logs --tail=200`, `kubectl wait --timeout=120s`)
  or give the user those commands. Reading Secrets (`kubectl get secret`, `helm get values`,
  `helm status -o json|yaml`) needs the user's approval. A missing kubectl/helm/cloud CLI is installed only after
  asking; with -y the command stops with exit code 2 and the `cloudseed install <tool>` command - give it to the user.
  GKE also needs `gke-gcloud-auth-plugin` (`gcloud components install gke-gcloud-auth-plugin`).
- Cloud IAM prerequisites for controllers (IRSA on EKS: LB controller, cluster-autoscaler, external-secrets, external-dns, EBS CSI; workload identity on GKE/AKS for external-secrets and external-dns) are created by the Kubernetes stack and wired into the charts; items with extra cloud resources (velero, karpenter) apply them through the stack at install time (`cs explain prereqs`).
- Generated passwords are in `<workdir>/platform/secrets.json`; never print them. So are MinIO's access keys (its root user and the users of velero and the Spark history server get random names; an install from an older version keeps admin/velero/spark until `cs platform install <item> --upgrade` rotates them, which the plan says). kagent needs ANTHROPIC_API_KEY or OPENAI_API_KEY
  in the environment (cloudseed reads it; you do not).
- Always run `cs platform plan <groups/items>` first and show the user the result: it lists installs, already-installed skips, conflicts (same role, e.g. opencost vs kubecost-cost-analyzer - skipped unless `--force`), overlaps (allowed but flagged) and values adjusted because a sibling exists (bundled Prometheus/cert-manager/Ollama/kmcp disabled and the shared one wired in). Groups never install duplicates.
- Prefer `--no-wait` for big installs when the user wants speed; `cs platform status` later.

## Resilience, chaos and assessments

- Groups `resilience` (velero, kured, descheduler - no Prometheus stack) and `chaos` (chaos-mesh; litmus extra); `kubescape-operator` and `external-dns` are extras.
- Items that need cloud resources (velero: bucket + identity; karpenter: roles, queue, tags) declare them; `cloudseed platform install <item>`
  applies the environment's Terraform stack first (plan + approval), then installs with the outputs wired in. On local clusters
  `local-path-provisioner` (default StorageClass) and MinIO are pulled in automatically.
- `cluster-autoscaler` applies to aws (chart + IRSA) and is reported as built into gke/aks (node pools autoscale between kubernetes_node_min/max; GKE never below kubernetes_node_count).
- `cloudseed dr status|backup|restore|backups|schedule|test [name] [<cloud> --env NAME]` (`backup [name] [--namespaces a,b]`, `restore <backup>`, `schedule <name> --cron "0 2 * * *" [--ttl 720h]`) - Velero; the cron schedule is in UTC; `--ttl` is a Go duration (`30d` is taken as `720h`); names are Kubernetes names (lower-case letters, digits, `-`, `.`). `test` = automated drill (a random file on the volume must survive backup + restore) with PASS/FAIL, RTO and exit code 1 on FAIL; `--no-volume` skips the volume, `--volume` forces it (needs a default StorageClass or an unclassed PV); `--keep` leaves the drill namespace and backup, prints what it kept and how to remove it (the backup keeps Velero's default 30-day TTL). A word that is a cloud key is the target; with `--cloud <cloud>` every word is taken as the name. `dr describe|logs backup|restore <name> [--details]` show Velero's own view of one backup or restore (objects, volumes, errors, log). `dr status` and `dr backups` need no velero CLI, and `dr describe|logs` run velero in the velero pod when there is none here; the other commands need the CLI of the server's version, which cloudseed never downloads in an agent session - give the user the same `cs dr` command to run once in their terminal.
- `cloudseed chaos run [basic|network|stress|full|<experiment>...] [--target ns/deploy[:port]] [--duration 45s|2m] [--replicas 2..20] [<cloud> --env NAME]`, `chaos list|status|stop|report` - Chaos Mesh experiments with a verdict table (a fault never injected is an ERROR; the run is PASS, FAIL or INCONCLUSIVE and exits 0 only on PASS); `--target` hits real workloads (get consent). A missing Chaos Mesh is installed only after asking at a terminal or with `--auto-approve` (its daemon runs privileged on every node).
- `cloudseed scan cis|kube|images|host|stig|cloud|fips|all|reports [<cloud> --env NAME] [--host bastion,vpn,k8s] [--profile cis|stig] [--framework ...]` - reports under `<workdir>/scans/` (raw tool output in `scans/raw/`); exits 1 when a verdict is FAIL; an unknown `--host` value exits 2. `cis` runs its RBAC/policies checks with a temporary read-only ClusterRole (removed afterwards), and decides the "default namespace should not be used" checks (EKS 4.5.2, GKE 4.6.4, AKS 4.6.3) by listing that namespace with the environment's credentials; `cloud` in an AWS FIPS environment audits only that region, through the FIPS endpoints. STIG content exists for Ubuntu 24.04, Ubuntu 22.04 (Ubuntu Pro) and RHEL 8/9: the AL2023 AWS bastion and the Debian 12 GCP bastion report n/a. `fips` is N/A (and skipped by `all`) on non-FIPS environments.
- FIPS environments (`fips_mode=true`) install `compatible` items, install `tls-restricted` ones (envoy-gateway, ingress-nginx) with FIPS TLS suites and flag them, install `crypto-restricted` ones (cert-manager, sealed-secrets, velero, cloudnative-pg: their key generation / encryption is not a validated module) and flag them too, and refuse the rest (application stacks with their own crypto) unless `--force`; check with `cloudseed scan fips`, which reports the crypto-restricted items as not FIPS-validated and, in AWS FIPS environments, checks the live cluster too (`AWS_USE_FIPS_ENDPOINT` on the AWS controllers, Velero's `s3-fips` endpoint, Karpenter's EC2NodeClass AMIs, `-fips` Bottlerocket node images).

For a local Well-Architected assessment, use `cloudseed scan architecture <cloud> --env NAME --profile production --json`
(or `--profile lab`). It reads saved configuration/evidence and writes a report, without cluster access, installs or
infrastructure changes. PASS exits 0, FAIL 1, INCOMPLETE 3; missing, stale and manual-review evidence never passes
silently. `scan all` excludes architecture. See the cloudseed-architecture skill and `cloudseed explain architecture`.
