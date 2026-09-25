"""Platform catalog: Helm / kustomize / manifest installs grouped for a full working platform.

Groups: basek8s (management), scaling, data, ai, agentic. Every item is data (see CATALOG) so charts, versions and
values can be tuned without touching code. Installs are idempotent (`helm upgrade --install`, `kubectl apply`).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import audit, deps, paths, secrets, ui

# ------------------------------------------------------------------------------------------------ catalog
# item: {group, desc, method: helm|oci|kustomize|manifest|post-only|meta, repo, chart, ns, release, version, values{ctx: {k: v}},
#        needs[], only[] (contexts), pre[]/post[] (manifests rendered before/after install), probe[], requires{}, notes}
# contexts: "vmware" | "aws" | "gcp" | "azure" (target), "rke2" | "kubeadm" | "eks" | "gke" | "aks" (distro), the istio
#           mode ("ambient" | "sidecar"), "fips" (any FIPS environment) and "<target>+fips" (e.g. "aws+fips")
# Every item that is not a Helm release (manifest, kustomize, post-only, meta) has a `probe`: the object whose presence
# means "installed" (there is no release to look at).
#
# Every chart is pinned ("version" for helm/oci, a tag for manifest URLs, ?ref= for kustomize): the same command installs
# the same stack on every day and machine, and `--upgrade` re-applies the pinned release instead of jumping majors (Helm
# never upgrades the CRDs a chart keeps in crds/: items listing "upgrade_crds" get theirs re-applied first on --upgrade).
# Each pin was rendered (`helm template`) with the values below on every target; bump them deliberately.
# "requires": {"any_env": [...], "hint": "..."} names the credentials an item cannot work without (checked by plan()).
# "arch": [...] the CPU architectures an item's images exist for (amd64-only charts are skipped on arm64-only clusters and
#          pinned to amd64 nodes elsewhere through their "arch-amd64" values); "ready": a custom resource the item's
#          operator must report ready before the item counts as installed (helm --wait cannot see operator-made pods).

# MinIO server and client images (repository, tag): MinIO no longer serves anonymous pulls from quay.io/minio or
# docker.io/minio, so local S3 uses the maintained public pgsty build (see the minio item). Checked multi-arch
# (amd64 + arm64) with /bin/sh and mc in the client image, which the bucket Jobs run.
MINIO_IMAGE = ("docker.io/pgsty/minio", "RELEASE.2026-08-04T00-00-00Z")
MINIO_MC_IMAGE = ("docker.io/pgsty/mc", "RELEASE.2026-09-16T00-00-00Z")
MINIO_MC_REF = ":".join(MINIO_MC_IMAGE)

CATALOG: dict[str, dict] = {
    # ---------------- basek8s: what every cluster needs to be managed properly ----------------
    "metrics-server": {"group": "basek8s", "desc": "Resource metrics API (kubectl top, HPA)", "method": "helm",
                       "repo": "https://kubernetes-sigs.github.io/metrics-server/", "chart": "metrics-server", "version": "3.14.0", "ns": "kube-system",
                       "values": {"vmware": {"args[0]": "--kubelet-insecure-tls"}}},
    "cert-manager": {"group": "basek8s", "desc": "X.509 certificates for in-cluster services (Gateway API aware)", "method": "helm",
                     "repo": "https://charts.jetstack.io", "chart": "cert-manager", "version": "v1.21.2", "ns": "cert-manager", "needs": ["gateway-api"],
                     "fips": "crypto-restricted",   # generates the cluster CA key and signs every UI certificate (upstream Go crypto)
                     "runtime_objects": ["secret/cert-manager-webhook-ca"],
                     "values": {"default": {"crds.enabled": "true", "config.gatewayAPI.enabled": "true"}}},
    # Experimental channel, pinned to the bundle Envoy Gateway ships (its chart carries the same CRDs on first install): the
    # upstream "safe-upgrades" admission policy forbids experimental-over-standard and downgrades, so the two must agree.
    "gateway-api": {"group": "basek8s", "desc": "Kubernetes Gateway API CRDs (experimental channel v1.6.1, matches envoy-gateway)", "method": "manifest",
                    "url": "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/experimental-install.yaml", "ns": "default",
                    "gateway_api": {"channel": "experimental", "version": "v1.6.1"}, "crds_only": True,
                    "probe": ["crd", "gateways.gateway.networking.k8s.io"]},
    "envoy-gateway": {"group": "basek8s", "desc": "Envoy Gateway: the cluster's Gateway API implementation (private LB, TLS via cert-manager)",
                      "method": "oci", "chart": "oci://docker.io/envoyproxy/gateway-helm", "version": "v1.9.1", "ns": "envoy-gateway-system",
                      "release": "eg", "needs": ["gateway-api", "cert-manager", "cert-manager-issuer", "metallb"], "post": ["cloudseed-gateway"], "post_fips": ["envoy-fips-tls"],
                      "fips": "tls-restricted", "upgrade_crds": ["gateway.envoyproxy.io"],
                      # certgen (a Helm hook, never deleted by helm uninstall) and the certificates it generates
                      "runtime_objects": ["secret/envoy-gateway", "secret/envoy", "secret/envoy-rate-limit", "secret/envoy-oidc-hmac",
                                          "job.batch/eg-gateway-helm-certgen", "serviceaccount/eg-gateway-helm-certgen",
                                          "role.rbac.authorization.k8s.io/eg-gateway-helm-certgen",
                                          "rolebinding.rbac.authorization.k8s.io/eg-gateway-helm-certgen"],
                      "notes": "Creates GatewayClass `cloudseed` and a shared Gateway `cloudseed/cloudseed` with HTTP+HTTPS listeners (wildcard cert from the cluster CA). "
                               "Apps attach HTTPRoutes to it; `cs platform ui` does that for every known UI."},
    "ingress-nginx": {"group": "basek8s", "desc": "LEGACY Ingress controller (upstream retired 2026; use Gateway API / envoy-gateway)", "method": "helm", "tier": "extra",
                      "repo": "https://kubernetes.github.io/ingress-nginx", "chart": "ingress-nginx", "version": "4.15.1", "ns": "ingress-nginx",
                      "needs": ["metallb"], "fips": "tls-restricted",
                      "values": {"vmware": {"controller.service.type": "LoadBalancer"},
                                 "fips": {"controller.config.ssl-protocols": "TLSv1.2 TLSv1.3",
                                          "controller.config.ssl-ciphers": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
                                          "controller.config.ssl-ecdh-curve": "secp384r1:prime256v1"},
                                 # the in-tree AWS cloud controller only honours aws-load-balancer-internal; the LB controller prefers -scheme
                                 "aws": {"controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme": "internal",
                                         "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal": "true",
                                         "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type": "nlb"},
                                 "gcp": {"controller.service.annotations.networking\\.gke\\.io/load-balancer-type": "Internal"},
                                 "azure": {"controller.service.annotations.service\\.beta\\.kubernetes\\.io/azure-load-balancer-internal": "true"}},
                      "notes": "The ingress gets a PRIVATE address: on aws/gcp/azure an internal load balancer (reach it over the VPN or the bastion); "
                               "on vmware a MetalLB address on the host-only network, reachable from this machine directly."},
    "metallb": {"group": "basek8s", "desc": "LoadBalancer IPs on the private network (local clusters)", "method": "helm",
                "repo": "https://metallb.github.io/metallb", "chart": "metallb", "version": "0.16.1", "ns": "metallb-system", "only": ["vmware"],
                "post": ["metallb-pool"]},
    # Chart 3.5.0 = controller v3.5.0. Its IRSA policy is vendored from that release's docs/install/iam_policy.json in
    # terraform/aws/modules/kubernetes/lb_controller_iam_policy.json: bump both together (a newer controller may call
    # AWS APIs the old policy does not allow).
    "aws-load-balancer-controller": {"group": "basek8s", "desc": "ALB/NLB provisioning for EKS (needs IRSA role)", "method": "helm",
                                     "repo": "https://aws.github.io/eks-charts", "chart": "aws-load-balancer-controller", "version": "3.5.0", "ns": "kube-system",
                                     "only": ["aws"], "tier": "extra", "upgrade_crds": ["elbv2.k8s.aws", "aga.k8s.aws", "gateway.k8s.aws"],
                                     "values": {"aws": {"clusterName": "{cluster_name}", "region": "{region}", "vpcId": "{vpc_id}",
                                                        "serviceAccount.name": "aws-load-balancer-controller",
                                                        "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn": "{lb_role_arn}"},
                                                "aws+fips": {"env.AWS_USE_FIPS_ENDPOINT": "true"}},
                                     "notes": "IRSA role created by cloudseed's EKS stack (kubernetes_irsa_role_arns.lb-controller) is wired in automatically."},
    "argocd": {"group": "basek8s", "desc": "GitOps continuous delivery", "method": "helm",
               # chart 10.9.2 ships Argo CD v3.5.3; templates/gitlab-ci/.gitlab-ci.yml pins the same CLI image - bump both together
               "repo": "https://argoproj.github.io/argo-helm", "chart": "argo-cd", "version": "10.9.2", "ns": "argocd", "release": "argocd",
               "values": {"default": {"configs.params.server\\.insecure": "true"}}},
    # Control-plane scrapes only where they can work: managed clusters expose no scheduler/controller-manager/etcd, and
    # RKE2/kubeadm bind them (and kube-proxy's metrics) to 127.0.0.1 - opening them up would break the CIS profile - so
    # their ServiceMonitors and the *Down alerts that would fire forever are left out. GKE Dataplane V2 and AKS run no
    # kube-proxy the chart can find; GKE's kube-dns has no CoreDNS metrics port.
    "kube-prometheus-stack": {"group": "basek8s", "desc": "Prometheus, Alertmanager, Grafana, node/kube exporters", "method": "helm",
                              "repo": "https://prometheus-community.github.io/helm-charts", "chart": "kube-prometheus-stack", "version": "91.5.1", "ns": "monitoring",
                              "release": "monitoring", "upgrade_crds": ["monitoring.coreos.com"],
                              "values": {"default": {"grafana.adminPassword": "{grafana_password}"},
                                         "eks": {"kubeControllerManager.enabled": "false", "kubeScheduler.enabled": "false", "kubeEtcd.enabled": "false"},
                                         "gke": {"kubeControllerManager.enabled": "false", "kubeScheduler.enabled": "false", "kubeEtcd.enabled": "false",
                                                 "kubeProxy.enabled": "false", "coreDns.enabled": "false"},
                                         "aks": {"kubeControllerManager.enabled": "false", "kubeScheduler.enabled": "false", "kubeEtcd.enabled": "false",
                                                 "kubeProxy.enabled": "false"},
                                         # RKE2 taints its servers CriticalAddonsOnly=true:NoExecute: node-exporter must tolerate it
                                         "rke2": {"kubeControllerManager.enabled": "false", "kubeScheduler.enabled": "false", "kubeEtcd.enabled": "false",
                                                  "kubeProxy.enabled": "false", "prometheus-node-exporter.tolerations[0].operator": "Exists"},
                                         "kubeadm": {"kubeControllerManager.enabled": "false", "kubeScheduler.enabled": "false", "kubeEtcd.enabled": "false",
                                                     "kubeProxy.enabled": "false"}}},
    # Loki 3 in single-binary mode (grafana/loki; the old loki-stack chart is deprecated and shipped Loki 2.6 + EOL Promtail).
    # Logs are collected by the alloy item (pulled in as a dependency); the Grafana datasource is added as a non-default one.
    "loki": {"group": "basek8s", "desc": "Log aggregation (Loki 3, single binary, persistent) + Alloy log collection", "method": "helm",
             "repo": "https://grafana.github.io/helm-charts", "chart": "loki", "version": "7.3.0", "ns": "monitoring", "release": "loki",
             "needs": ["alloy"], "post": ["loki-datasource"],
             "values": {"default": {"deploymentMode": "SingleBinary", "singleBinary.replicas": "1", "singleBinary.persistence.enabled": "true",
                                    "singleBinary.persistence.size": "10Gi", "loki.auth_enabled": "false", "loki.commonConfig.replication_factor": "1",
                                    "loki.storage.type": "filesystem", "loki.schemaConfig.configs[0].from": "2024-04-01",
                                    "loki.schemaConfig.configs[0].store": "tsdb", "loki.schemaConfig.configs[0].object_store": "filesystem",
                                    "loki.schemaConfig.configs[0].schema": "v13", "loki.schemaConfig.configs[0].index.prefix": "loki_index_",
                                    "loki.schemaConfig.configs[0].index.period": "24h", "loki.limits_config.retention_period": "168h",
                                    "loki.compactor.retention_enabled": "true", "loki.compactor.delete_request_store": "filesystem",
                                    "read.replicas": "0", "write.replicas": "0", "backend.replicas": "0", "gateway.enabled": "false",
                                    "chunksCache.enabled": "false", "resultsCache.enabled": "false", "lokiCanary.enabled": "false",
                                    "test.enabled": "false", "minio.enabled": "false"}},
             "notes": "Query logs in Grafana (datasource `Loki`, 7-day retention) or at http://loki.monitoring.svc:3100. Installed by an older "
                      "cloudseed as the deprecated loki-stack chart? Replace it: helm uninstall loki -n monitoring, then cs platform install loki."},
    "alloy": {"group": "basek8s", "desc": "Grafana Alloy: collects every pod's logs into Loki", "method": "helm",
              "repo": "https://grafana.github.io/helm-charts", "chart": "alloy", "version": "1.12.1", "ns": "monitoring", "release": "alloy-logs",
              "pre": ["alloy-logs-config"],
              "values": {"default": {"alloy.configMap.create": "false", "alloy.configMap.name": "alloy-logs-config", "alloy.configMap.key": "config.alloy",
                                     "alloy.clustering.enabled": "true", "crds.create": "false"}},
              "notes": "Tails pod logs through the Kubernetes API (clustered DaemonSet, each pod shipped once) and pushes them to loki.monitoring:3100."},
    "opentelemetry-operator": {"group": "basek8s", "desc": "OpenTelemetry operator (collectors, auto-instrumentation)", "method": "helm",
                               "repo": "https://open-telemetry.github.io/opentelemetry-helm-charts", "chart": "opentelemetry-operator", "version": "0.123.1",
                               "ns": "opentelemetry-operator-system", "needs": ["cert-manager"],
                               "values": {"default": {"manager.collectorImage.repository": "otel/opentelemetry-collector-k8s"}}},
    "external-secrets": {"group": "basek8s", "desc": "Sync secrets from AWS/GCP/Azure secret managers, Vault, ...", "method": "helm",
                         "repo": "https://charts.external-secrets.io", "chart": "external-secrets", "version": "2.11.0", "ns": "external-secrets",
                         "guard_crds": True,   # its CRDs (ExternalSecret, SecretStore ...) go with the chart
                         "values": {"default": {"installCRDs": "true", "serviceAccount.name": "external-secrets"},
                                    "aws": {"serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn": "{external_secrets_role_arn}"},
                                    "gcp": {"serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account": "{external_secrets_gsa}"},
                                    "azure": {"serviceAccount.annotations.azure\\.workload\\.identity/client-id": "{external_secrets_client_id}",
                                              "podLabels.azure\\.workload\\.identity/use": "true"},
                                    # FIPS environments: Secrets Manager / SSM / STS through their FIPS endpoints, like every other AWS call
                                    "aws+fips": {"extraEnv[0].name": "AWS_USE_FIPS_ENDPOINT", "extraEnv[0].value": "true"}},
                         "notes": "Cloud identity (IRSA / GKE Workload Identity / Azure workload identity) is created by the cloudseed stack and wired in; create ClusterSecretStores next. "
                                  "AWS: the role reads only Secrets Manager names / SSM parameter paths that start with <name>-<env>/ (e.g. acme-dev/db, "
                                  "/acme-dev/db); widen it with cs setup aws --env <env> --var 'external_secrets_prefixes=[\"shared/\"]' ([\"*\"] = the whole account)."},
    # fullnameOverride: the Service kubeseal looks for by default (sealed-secrets-controller in kube-system); the release
    # keeps its name, so existing installs are still recognised and their sealing keys (sealed-secrets-key*) stay in use
    "sealed-secrets": {"group": "basek8s", "desc": "Encrypt secrets so they can live in git", "method": "oci",
                       "chart": "oci://registry-1.docker.io/bitnamicharts/sealed-secrets", "version": "2.20.0", "ns": "kube-system",
                       "upgrade_crds": ["bitnami.com"], "fips": "crypto-restricted",
                       "values": {"default": {"fullnameOverride": "sealed-secrets-controller"}},
                       "notes": "kubeseal works with its defaults (controller sealed-secrets-controller in kube-system): kubeseal -o yaml < secret.yaml > sealed.yaml. "
                                "Installed by an older cloudseed (Service sealed-secrets)? Re-apply it (cs platform install sealed-secrets --upgrade; the sealing "
                                "keys are kept) or pass kubeseal --controller-name sealed-secrets."},
    # runtime_objects: what an item's own controllers (or Helm hooks) leave in its namespace - not the user's data, so
    # they do not keep the namespace alive after an uninstall
    "reloader": {"group": "basek8s", "desc": "Restart workloads when ConfigMaps/Secrets change", "method": "helm",
                 "repo": "https://stakater.github.io/stakater-charts", "chart": "reloader", "version": "2.2.17", "ns": "reloader", "tier": "extra",
                 "runtime_objects": ["configmap/reloader-meta-info"]},
    "kyverno": {"group": "basek8s", "desc": "Policy engine (admission control, mutation, generation)", "method": "helm",
                "repo": "https://kyverno.github.io/kyverno/", "chart": "kyverno", "version": "3.9.1", "ns": "kyverno", "tier": "extra",
                "runtime_objects": [f"secret/{svc}.kyverno.svc.kyverno-tls-{part}" for svc in ("kyverno-svc", "kyverno-cleanup-controller")
                                    for part in ("ca", "pair")]},

    # ---------------- scaling ----------------
    # guard_crds: its CRDs are deleted with the chart - refuse while the user's ScaledObjects/TriggerAuthentications exist
    "keda": {"group": "scaling", "desc": "Event-driven autoscaling (queues, metrics, cron, ...)", "method": "helm",
             "repo": "https://kedacore.github.io/charts", "chart": "keda", "version": "2.21.0", "ns": "keda", "guard_crds": True,
             "runtime_objects": ["secret/kedaorg-certs"]},
    # the VPA recommender reads the metrics API: metrics-server is pulled in (skipped where the distro ships it)
    "vpa": {"group": "scaling", "desc": "Vertical Pod Autoscaler", "method": "helm",
            "repo": "https://charts.fairwinds.com/stable", "chart": "vpa", "version": "5.1.0", "ns": "vpa", "needs": ["metrics-server"],
            "upgrade_crds": ["autoscaling.k8s.io"]},
    "goldilocks": {"group": "scaling", "desc": "Right-sizing recommendations dashboard (uses VPA)", "method": "helm",
                   "repo": "https://charts.fairwinds.com/stable", "chart": "goldilocks", "version": "11.1.1", "ns": "goldilocks", "needs": ["vpa"]},
    # GKE's pool floor is max(kubernetes_node_min, kubernetes_node_count) (terraform/gcp/modules/kubernetes); AKS and EKS
    # scale down to kubernetes_node_min
    "cluster-autoscaler": {"group": "scaling", "desc": "Scale node pools on demand within kubernetes_node_min/_max (EKS chart; GKE/AKS: built-in autoscaler, GKE never below kubernetes_node_count)", "method": "helm",
                           "repo": "https://kubernetes.github.io/autoscaler", "chart": "cluster-autoscaler", "version": "9.59.0", "ns": "kube-system", "only": ["aws", "gcp", "azure"],
                           "values": {"aws": {"autoDiscovery.clusterName": "{cluster_name}", "awsRegion": "{region}",
                                              "rbac.serviceAccount.name": "cluster-autoscaler-aws-cluster-autoscaler",
                                              "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn": "{autoscaler_role_arn}"},
                                      "aws+fips": {"extraEnv.AWS_USE_FIPS_ENDPOINT": "true"}},
                           "fips": "compatible",
                           "notes": "Node pools scale from kubernetes_node_min (GKE: max(kubernetes_node_min, kubernetes_node_count) - it never scales below "
                                    "kubernetes_node_count) up to kubernetes_node_max (GKE/AKS raise it to kubernetes_node_count when that is larger; "
                                    "AWS refuses a count outside min..max). AWS: this chart, "
                                    "with the IRSA role and ASG discovery tags from cloudseed's EKS stack. GKE and AKS pools are created with autoscaling, so "
                                    "nothing is installed there. VMware: scale with `cs node add|remove`."},
    "karpenter": {"group": "scaling", "desc": "Just-in-time nodes for EKS (controller + a default NodePool/EC2NodeClass)", "method": "oci",
                  "chart": "oci://public.ecr.aws/karpenter/karpenter", "version": "1.14.1", "ns": "kube-system", "only": ["aws"], "tier": "extra",
                  "cloud_prereqs": ["karpenter"], "post": ["karpenter-default"], "fips": "compatible",
                  "upgrade_crds": ["karpenter.sh", "karpenter.k8s.aws"],
                  "values": {"aws": {"settings.clusterName": "{cluster_name}", "settings.interruptionQueue": "{karpenter_queue}",
                                     "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn": "{karpenter_role_arn}",
                                     "controller.resources.requests.cpu": "500m", "controller.resources.requests.memory": "512Mi"},
                             # FIPS: EC2/SQS/SSM/IAM/STS through FIPS endpoints; the Pricing API has none, so on-demand prices come
                             # from Karpenter's built-in table (isolatedVPC turns the pricing lookups off instead of failing them)
                             "aws+fips": {"controller.env[0].name": "AWS_USE_FIPS_ENDPOINT", "controller.env[0].value": "true",
                                          "settings.isolatedVPC": "true"}},
                  "notes": "cloudseed's EKS stack creates the controller IRSA role, node role + instance profile, interruption queue and discovery tags "
                           "(`cs platform install karpenter` applies them first); a default NodePool/EC2NodeClass (Bottlerocket, private subnets) is created. "
                           "FIPS environments get Bottlerocket FIPS AMIs for the cluster's Kubernetes version: after a control-plane upgrade re-apply "
                           "them with cs platform install karpenter --upgrade. Running it next to cluster-autoscaler? Both react to the same pending "
                           "pods: scale the managed node group's autoscaler down or keep it for a tainted system group only."},

    # ---------------- data ----------------
    "minio": {"group": "data", "desc": "S3-compatible object storage (lakehouse storage for local clusters)", "method": "helm",
              "repo": "https://charts.min.io/", "chart": "minio", "version": "5.4.0", "ns": "minio",
              # users=null: the chart otherwise creates a consoleAdmin user console/console123. Consumers (spark-history-server,
              # velero) get their own least-privilege users from their manifests; the root login stays in the minio namespace.
              # image: MinIO stopped publishing community images - quay.io/minio/* and docker.io/minio/* answer 401 to
              # anonymous pulls for every tag, so the chart's defaults can never start. docker.io/pgsty/{minio,mc} is a
              # maintained public build of the same AGPL sources (multi-arch; the server carries the 2025 fixes such as
              # CVE-2025-31489 and CVE-2025-27414; its console is the object browser only). MINIO_MC_IMAGE is also the
              # image of the bucket Jobs below (spark-logs-bucket, velero-bucket): they need /bin/sh and mc.
              # The data volume survives `cs platform uninstall minio` (resource-policy keep): a re-install adopts it.
              # rootUser: generated per environment (minio_root_user), like the consumers' access keys: a well-known
              # access key is all some MinIO flaws need (CVE-2025-62506 ...); an install made before keeps 'admin'
              # until it is re-applied (cs platform install minio --upgrade), see MINIO_USERS
              "values": {"default": {"mode": "standalone", "replicas": "1", "persistence.size": "20Gi", "resources.requests.memory": "512Mi",
                                     "rootUser": "{minio_root_user}", "rootPassword": "{minio_password}", "users": "null",
                                     "image.repository": MINIO_IMAGE[0], "image.tag": MINIO_IMAGE[1],
                                     "mcImage.repository": MINIO_MC_IMAGE[0], "mcImage.tag": MINIO_MC_IMAGE[1],
                                     "persistence.annotations.helm\\.sh/resource-policy": "keep"}},
              "notes": "Its data volume (PVC minio/minio) is kept when minio is uninstalled; delete it yourself (cs kubectl delete pvc minio -n minio) "
                       "to start empty. Console: object browser (minio_root_user / minio_password in platform/secrets.json)."},
    # generates each Postgres cluster's CA and server certificates, and Postgres serves client TLS with its own OpenSSL
    "cloudnative-pg": {"group": "data", "desc": "PostgreSQL operator (CloudNativePG): Postgres clusters as CRDs (backs the Polaris catalog)", "method": "helm",
                       "repo": "https://cloudnative-pg.github.io/charts", "chart": "cloudnative-pg", "version": "0.29.1", "ns": "cnpg-system",
                       "fips": "crypto-restricted",
                       "notes": "Kept while any Postgres cluster (clusters.postgresql.cnpg.io) exists - e.g. the Polaris catalog database, which "
                                "outlives `cs platform uninstall polaris`: without the operator nothing would run or clean them up."},
    "strimzi": {"group": "data", "desc": "Apache Kafka operator (Strimzi) + a dev Kafka cluster (KRaft, 1 broker)", "method": "helm",
                # 1.x serves only the kafka.strimzi.io/v1 API the kafka-cluster manifest uses (v1beta2 was removed in 1.0)
                "repo": "https://strimzi.io/charts/", "chart": "strimzi-kafka-operator", "version": "1.2.0", "ns": "kafka",
                "values": {"default": {"watchAnyNamespace": "true"}}, "post": ["kafka-cluster"],
                "upgrade_crds": ["kafka.strimzi.io", "core.strimzi.io"],
                "notes": "--upgrade re-applies the chart's CRDs first (helm itself never upgrades crds/). Clusters that ran Strimzi < 0.49 still "
                         "use the removed v1beta2 API: convert them with Strimzi's API conversion tool before upgrading."},
    "spark-operator": {"group": "data", "desc": "Kubeflow Spark operator (SparkApplication CRD)", "method": "helm",
                       "repo": "https://kubeflow.github.io/spark-operator", "chart": "spark-operator", "version": "2.5.2", "ns": "spark-operator",
                       "upgrade_crds": ["sparkoperator.k8s.io"],
                       "values": {"default": {"spark.jobNamespaces[0]": "{spark}"}}},   # a list: a plain string breaks the webhook template
    # Sized for the default 4 GiB nodes (the chart's -Xmx8G heaps and BestEffort pods would be OOM-killed under load):
    # heaps with their limits around them, per-node query memory as a share of the heap (Trino needs it below heap minus
    # its 30% headroom). process-forwarded: `cs platform ui` serves it behind the Gateway, which sends X-Forwarded-*
    # headers Trino otherwise answers with HTTP 406.
    "trino": {"group": "data", "desc": "Distributed SQL query engine", "method": "helm",
              "repo": "https://trinodb.github.io/charts", "chart": "trino", "version": "1.42.2", "ns": "trino",
              "values": {"default": {"server.workers": "1", "additionalConfigProperties[0]": "http-server.process-forwarded=true",
                                     "server.config.query.maxMemory": "1GB",
                                     "coordinator.jvm.maxHeapSize": "1G", "coordinator.config.query.maxMemoryPerNode": "30%",
                                     "coordinator.resources.requests.memory": "1Gi", "coordinator.resources.limits.memory": "2Gi",
                                     "worker.jvm.maxHeapSize": "1536M", "worker.config.query.maxMemoryPerNode": "30%",
                                     "worker.resources.requests.memory": "1Gi", "worker.resources.limits.memory": "2560Mi"}},
              "notes": "Sized for 4 GiB nodes (coordinator heap 1G, worker 1.5G). Bigger nodes: cs platform install trino --upgrade "
                       "--set worker.jvm.maxHeapSize=6G --set worker.resources.limits.memory=8Gi (and server.workers=N). Own config "
                       "properties go to additionalConfigProperties[1] and up ([0] keeps the Gateway's forwarded headers working)."},
    # The chart's defaults request 4 CPU / 4Gi per FE and BE (unschedulable on the default 2-vCPU nodes) and keep FE
    # metadata and BE data on emptyDir: dev sizing, persistent volumes (sizes set explicitly - the BE default is 1Ti), a
    # FE heap that fits its limit (configyaml replaces the chart's fe.conf, whose -Xmx8192m would outgrow it), pinned
    # multi-arch images and UTC instead of the chart's Asia/Shanghai. helm --wait cannot see the FE/BE pods (the operator
    # makes them), so the StarRocksCluster must report "running" before the item counts as installed.
    "starrocks": {"group": "data", "desc": "StarRocks analytical database (operator + cluster CRD)", "method": "helm",
                  "repo": "https://starrocks.github.io/starrocks-kubernetes-operator", "chart": "kube-starrocks", "version": "1.11.7", "ns": "starrocks",
                  "upgrade_crds": ["starrocks.com"],
                  "ready": {"kind": "starrocksclusters.starrocks.com", "name": "kube-starrocks", "jsonpath": "{.status.phase}", "value": "running"},
                  "values": {"default": {"operator.timeZone": "UTC", "starrocks.timeZone": "UTC",
                                         "starrocks.starrocksFESpec.replicas": "1", "starrocks.starrocksFESpec.image.tag": "4.1.4",
                                         "starrocks.starrocksFESpec.resources.requests.cpu": "500m", "starrocks.starrocksFESpec.resources.requests.memory": "1Gi",
                                         "starrocks.starrocksFESpec.resources.limits.cpu": "2", "starrocks.starrocksFESpec.resources.limits.memory": "3Gi",
                                         "starrocks.starrocksFESpec.storageSpec.name": "fe", "starrocks.starrocksFESpec.storageSpec.storageSize": "10Gi",
                                         "starrocks.starrocksFESpec.storageSpec.logStorageSize": "1Gi",
                                         "starrocks.starrocksFESpec.configyaml.JAVA_OPTS": "-Dlog4j2.formatMsgNoLookups=true -Xmx1536m -XX:+UseG1GC",
                                         "starrocks.starrocksFESpec.configyaml.http_port": "8030", "starrocks.starrocksFESpec.configyaml.rpc_port": "9020",
                                         "starrocks.starrocksFESpec.configyaml.query_port": "9030", "starrocks.starrocksFESpec.configyaml.edit_log_port": "9010",
                                         "starrocks.starrocksFESpec.configyaml.mysql_service_nio_enabled": "true",
                                         "starrocks.starrocksFESpec.configyaml.sys_log_level": "INFO",
                                         "starrocks.starrocksFESpec.configyaml.min_graceful_exit_time_second": "25",
                                         "starrocks.starrocksBeSpec.replicas": "1", "starrocks.starrocksBeSpec.image.tag": "4.1.4",
                                         "starrocks.starrocksBeSpec.resources.requests.cpu": "500m", "starrocks.starrocksBeSpec.resources.requests.memory": "1Gi",
                                         "starrocks.starrocksBeSpec.resources.limits.cpu": "2", "starrocks.starrocksBeSpec.resources.limits.memory": "3Gi",
                                         "starrocks.starrocksBeSpec.storageSpec.name": "be", "starrocks.starrocksBeSpec.storageSpec.storageSize": "20Gi",
                                         "starrocks.starrocksBeSpec.storageSpec.logStorageSize": "1Gi"}},
                  "notes": "Dev-sized (FE and BE: 0.5 CPU / 1Gi requested, 2 CPU / 3Gi limit) with persistent FE metadata (10Gi) and BE data (20Gi). "
                           "Volumes cannot be added to an existing StarRocksCluster: an install from an older cloudseed (no volumes) must be "
                           "removed (cs platform uninstall starrocks) and installed again rather than upgraded. SQL: mysql -h kube-starrocks-fe-service.starrocks -P 9030 -u root."},
    # Released Apache chart (apache/polaris:1.7.0) with its catalog in a CloudNativePG Postgres cluster (pre manifest polaris-db);
    # the realm is bootstrapped by an init container (idempotent), so the catalog and root credentials survive restarts.
    "polaris": {"group": "data", "desc": "Apache Polaris - Iceberg REST catalog (Postgres-backed via CloudNativePG)", "method": "helm",
                "repo": "https://downloads.apache.org/polaris/helm-chart", "chart": "polaris", "version": "1.7.0", "ns": "polaris",
                "needs": ["cloudnative-pg"], "pre": ["polaris-db"],
                # the catalog database outlives an uninstall: deleting the CNPG Cluster would garbage-collect its volume, and a
                # re-install (or `cs undo`) picks it up again (kubectl apply leaves an existing Cluster as it is)
                "keep_on_uninstall": [("Cluster", "polaris-db")],
                "values": {"default": {"persistence.type": "relational-jdbc", "persistence.relationalJdbc.secret.name": "polaris-db-app",
                                       "persistence.relationalJdbc.secret.username": "username", "persistence.relationalJdbc.secret.password": "password",
                                       "persistence.relationalJdbc.secret.jdbcUrl": "jdbc-uri",
                                       "extraInitContainers[0].name": "bootstrap-realm", "extraInitContainers[0].image": "apache/polaris-admin-tool:1.7.0",
                                       "extraInitContainers[0].args[0]": "bootstrap", "extraInitContainers[0].args[1]": "--realm",
                                       "extraInitContainers[0].args[2]": "POLARIS", "extraInitContainers[0].args[3]": "--credential",
                                       "extraInitContainers[0].args[4]": "$(POLARIS_ROOT_CREDENTIALS)",
                                       "extraInitContainers[0].env[0].name": "POLARIS_PERSISTENCE_TYPE", "extraInitContainers[0].env[0].value": "relational-jdbc",
                                       "extraInitContainers[0].env[1].name": "QUARKUS_DATASOURCE_USERNAME",
                                       "extraInitContainers[0].env[1].valueFrom.secretKeyRef.name": "polaris-db-app",
                                       "extraInitContainers[0].env[1].valueFrom.secretKeyRef.key": "username",
                                       "extraInitContainers[0].env[2].name": "QUARKUS_DATASOURCE_PASSWORD",
                                       "extraInitContainers[0].env[2].valueFrom.secretKeyRef.name": "polaris-db-app",
                                       "extraInitContainers[0].env[2].valueFrom.secretKeyRef.key": "password",
                                       "extraInitContainers[0].env[3].name": "QUARKUS_DATASOURCE_JDBC_URL",
                                       "extraInitContainers[0].env[3].valueFrom.secretKeyRef.name": "polaris-db-app",
                                       "extraInitContainers[0].env[3].valueFrom.secretKeyRef.key": "jdbc-uri",
                                       "extraInitContainers[0].env[4].name": "POLARIS_ROOT_CREDENTIALS",
                                       "extraInitContainers[0].env[4].valueFrom.secretKeyRef.name": "polaris-root",
                                       "extraInitContainers[0].env[4].valueFrom.secretKeyRef.key": "credentials"}},
                "notes": "Catalog stored in the CloudNativePG cluster polaris/polaris-db. Root principal: client id `root`, secret polaris_password "
                         "(platform/secrets.json), realm POLARIS; REST endpoint http://polaris.polaris.svc:8181/api/catalog. Uninstall keeps the "
                         "database (a re-install finds the catalog again); drop it with cs kubectl delete clusters.postgresql.cnpg.io polaris-db -n polaris."},
    "spark-history-server": {"group": "data", "desc": "Spark History Server (event logs in MinIO s3a://spark-logs)", "method": "post-only",
                             "ns": "spark-operator", "needs": ["minio", "spark-operator"], "post": ["spark-history-server"],
                             "probe": ["deployment", "spark-history-server", "spark-operator"],
                             "notes": "Event logs go to s3a://spark-logs/ in MinIO as a least-privilege user of its own (Secret spark-operator/spark-s3: "
                                      "AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). SparkApplications need the S3A jars and endpoint: "
                                      "spark.jars.packages=org.apache.hadoop:hadoop-aws:3.3.4, spark.eventLog.enabled=true, spark.eventLog.dir=s3a://spark-logs/, "
                                      "spark.hadoop.fs.s3a.endpoint=http://minio.minio.svc:9000, spark.hadoop.fs.s3a.path.style.access=true, "
                                      "and envFrom the spark-s3 Secret on driver and executors."},
    "airflow": {"group": "data", "desc": "Apache Airflow (official chart)", "method": "helm",
                # createUserJob.defaultUser replaced webserver.defaultUser (setting the old key disables the create-user Job).
                # useHelmHooks=false (the chart docs: required with helm --wait): as post-install hooks the migration and
                # create-user Jobs would only run after --wait saw every pod ready, while each pod waits for the migrations -
                # a deadlock that fails the install after 15 minutes. As ordinary Jobs they run alongside the pods.
                "repo": "https://airflow.apache.org", "chart": "airflow", "version": "1.22.0", "ns": "airflow",
                "values": {"default": {"createUserJob.defaultUser.username": "admin", "createUserJob.defaultUser.password": "{airflow_password}",
                                       "migrateDatabaseJob.useHelmHooks": "false", "migrateDatabaseJob.applyCustomEnv": "false",
                                       "createUserJob.useHelmHooks": "false", "createUserJob.applyCustomEnv": "false"}},
                "notes": "The database migration and admin-user Jobs run with the release (deleted 5 minutes after they finish). An --upgrade "
                         "that changes them within those 5 minutes fails with 'field is immutable': wait and re-run it."},
    "clickhouse-operator": {"group": "data", "desc": "Altinity ClickHouse operator", "method": "helm",
                            "repo": "https://docs.altinity.com/clickhouse-operator/", "chart": "altinity-clickhouse-operator", "version": "0.27.3",
                            "ns": "clickhouse", "tier": "extra",
                            # its CRD-install hook runs bitnami/kubectl:latest (no version tags exist): a pinned kubectl with a shell
                            "values": {"default": {"crdHook.image.repository": "alpine/kubectl", "crdHook.image.tag": "1.37.0"}}},
    # ClickHouse Inc.'s operator (clickhouse.com API group, not Altinity's): Langfuse 2.x creates its ClickHouseCluster/KeeperCluster through it
    "clickhouse-operator-official": {"group": "data", "desc": "ClickHouse Inc. operator (clickhouse.com ClickHouseCluster/KeeperCluster CRDs)", "method": "oci",
                                     "chart": "oci://ghcr.io/clickhouse/clickhouse-operator-helm", "version": "0.0.7", "ns": "clickhouse-operator-system",
                                     "needs": ["cert-manager"], "hidden": True},

    # ---------------- ai / ml ----------------
    "kuberay": {"group": "ai", "desc": "Ray operator (distributed Python, RayJob/RayService/RayCluster)", "method": "helm",
                "repo": "https://ray-project.github.io/kuberay-helm/", "chart": "kuberay-operator", "version": "1.7.1", "ns": "ray",
                "upgrade_crds": ["ray.io"]},
    "kubeflow-trainer": {"group": "ai", "desc": "Kubeflow training operator (PyTorchJob, TFJob, ...)", "method": "kustomize",
                         "url": "github.com/kubeflow/training-operator/manifests/overlays/standalone?ref=v1.9.0", "ns": "kubeflow",
                         "probe": ["deployment", "training-operator", "kubeflow"]},
    # 2.17.x: the 2.4/2.5 manifests reference a MinIO image gcr.io deleted; both refs must match (CRDs + the platform)
    "kubeflow-pipelines": {"group": "ai", "desc": "Kubeflow Pipelines (standalone, platform-agnostic)", "method": "kustomize",
                           "url": "github.com/kubeflow/pipelines/manifests/kustomize/cluster-scoped-resources?ref=2.17.2",
                           "then": "github.com/kubeflow/pipelines/manifests/kustomize/env/platform-agnostic?ref=2.17.2", "ns": "kubeflow",
                           "probe": ["deployment", "ml-pipeline", "kubeflow"],
                           # ML Metadata's gRPC server and the metadata writer exist for amd64 only: pinned to amd64 nodes
                           "arch": ["amd64"], "arch_pin": ["metadata-grpc-deployment", "metadata-writer"],
                           "tier": "extra", "notes": "Heavy: bundles its own MySQL, SeaweedFS (S3 API) object store and Argo Workflows v4 in namespace kubeflow "
                                                     "(separate from the data group's MinIO). Wait a few minutes for all pods. Needs an amd64 node "
                                                     "(its metadata server has no arm64 image)."},
    "kserve": {"group": "ai", "desc": "Model serving (KServe, standard (raw) deployment mode - no Knative needed)", "method": "oci",
               "chart": "oci://ghcr.io/kserve/charts/kserve-resources", "version": "v0.20.0", "ns": "kserve", "needs": ["cert-manager", "kserve-crd"],
               "values": {"default": {"kserve.controller.deploymentMode": "Standard"}}},   # "RawDeployment" is the deprecated name
    "kserve-crd": {"group": "ai", "desc": "KServe CRDs", "method": "oci", "chart": "oci://ghcr.io/kserve/charts/kserve-crd", "version": "v0.20.0",
                   "ns": "kserve", "hidden": True, "crds_only": True},
    "jupyterhub": {"group": "ai", "desc": "Multi-user notebooks", "method": "helm",
                   "repo": "https://hub.jupyter.org/helm-chart/", "chart": "jupyterhub", "version": "4.4.2", "ns": "jupyterhub",
                   # SharedPasswordAuthenticator replaced DummyAuthenticator.password (deprecated in JupyterHub 5.3; without the
                   # trait a dummy authenticator would accept any password). allow_all: any user name may sign in with it.
                   "values": {"default": {"proxy.service.type": "ClusterIP", "hub.config.JupyterHub.authenticator_class": "shared-password",
                                          "hub.config.SharedPasswordAuthenticator.user_password": "{jupyter_password}",
                                          "hub.config.SharedPasswordAuthenticator.allow_all": "true"}}},
    "mlflow": {"group": "ai", "desc": "Experiment tracking and model registry", "method": "helm",
               "repo": "https://community-charts.github.io/helm-charts", "chart": "mlflow", "version": "1.11.7", "ns": "mlflow"},
    "vllm-stack": {"group": "ai", "desc": "vLLM production stack (router + model servers)", "method": "helm",
                   "repo": "https://vllm-project.github.io/production-stack", "chart": "vllm-stack", "version": "0.1.12", "ns": "vllm", "tier": "extra",
                   # the router image matching the chart (its default `latest` is a moving dev build); amd64 only
                   "arch": ["amd64"],
                   "values": {"default": {"routerSpec.tag": "v0.1.12", "routerSpec.imagePullPolicy": "IfNotPresent"},
                              "arch-amd64": {"routerSpec.nodeSelectorTerms[0].matchExpressions[0].key": "kubernetes.io/arch",
                                             "routerSpec.nodeSelectorTerms[0].matchExpressions[0].operator": "In",
                                             "routerSpec.nodeSelectorTerms[0].matchExpressions[0].values[0]": "amd64"}},
                   "notes": "Needs GPU nodes (or a CPU-only model + values override). Its router image exists for amd64 only."},
    # llm-d was removed: its only chart (llm-d/llm-d-deployer) is archived and needs a pre-release Istio build, the Inference
    # Extension CRDs and a gated HF model; upstream now ships it as kustomize/helmfile guides with no stable chart to pin.
    # vllm-stack (extra) and kserve (core) cover model serving.
    "gpu-operator": {"group": "ai", "desc": "NVIDIA GPU operator (drivers, device plugin, DCGM)", "method": "helm",
                     "repo": "https://helm.ngc.nvidia.com/nvidia", "chart": "gpu-operator", "version": "v26.7.1", "ns": "gpu-operator", "tier": "extra",
                     "only": ["aws", "gcp", "azure"]},
    "ollama": {"group": "ai", "desc": "Local LLM runtime (CPU-friendly for dev)", "method": "helm",
               "repo": "https://otwld.github.io/ollama-helm/", "chart": "ollama", "version": "1.83.0", "ns": "ollama", "tier": "extra"},

    # ---------------- agentic ----------------
    # agentgateway ships on its own now (kgateway 2.x no longer contains it): data plane + GatewayClass `agentgateway`
    "agentgateway": {"group": "agentic", "desc": "agentgateway: gateway for agents, MCP and LLM traffic (GatewayClass agentgateway)", "method": "oci",
                     "chart": "oci://cr.agentgateway.dev/charts/agentgateway", "version": "1.5.0", "ns": "agentgateway-system",
                     "needs": ["gateway-api", "agentgateway-crds"],
                     "notes": "Create a Gateway with gatewayClassName: agentgateway and route MCP/LLM traffic with HTTPRoutes and Agentgateway* policies. "
                              "Installed by an older cloudseed (kgateway 2.4.5 in kgateway-system)? Remove it: helm uninstall agentgateway kgateway-crds -n kgateway-system."},
    "agentgateway-crds": {"group": "agentic", "desc": "agentgateway CRDs", "method": "oci", "chart": "oci://cr.agentgateway.dev/charts/agentgateway-crds",
                          "version": "1.5.0", "ns": "agentgateway-system", "hidden": True, "crds_only": True},
    "kagent": {"group": "agentic", "desc": "kagent: agentic AI framework for Kubernetes (agents as CRDs)", "method": "oci",
               "chart": "oci://ghcr.io/kagent-dev/kagent/helm/kagent", "version": "0.10.1", "ns": "kagent", "needs": ["kagent-crds"],
               # {llm_provider} is anthropic when ANTHROPIC_API_KEY is set, else openAI when OPENAI_API_KEY is set
               # grafana-mcp (the observability agent's tool server) only publishes a moving `latest`: pinned to its digest
               "values": {"default": {"providers.default": "{llm_provider}", "providers.anthropic.apiKey": "{anthropic_api_key}",
                                      "providers.openAI.apiKey": "{openai_api_key}",
                                      "grafana-mcp.image.tag": "latest@sha256:9362bcf6aa0e44e61f645b905cec03fb346a946a34a4dafecd7f3e28d3724014",
                                      "grafana-mcp.image.pullPolicy": "IfNotPresent"}},
               "requires": {"any_env": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
                            "hint": "set a model key first: cs creds set ANTHROPIC_API_KEY (or OPENAI_API_KEY), then cs platform install kagent"},
               "notes": "Agents use Anthropic when ANTHROPIC_API_KEY is set, otherwise OpenAI (OPENAI_API_KEY). Changed the key later? "
                        "cs platform install kagent --upgrade. Its UI has no login of its own and its tools hold cluster-admin: `cs platform ui` "
                        "puts it behind a password (admin / kagent_password in platform/secrets.json)."},
    "kagent-crds": {"group": "agentic", "desc": "kagent CRDs (incl. kmcp's MCPServer)", "method": "oci", "chart": "oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds",
                    "version": "0.10.1", "ns": "kagent", "hidden": True, "crds_only": True},
    # the MCPServer CRD comes from kagent-crds (identical to kmcp-crds 0.4.0); a second CRD release would fight over ownership
    "kmcp": {"group": "agentic", "desc": "kmcp: build and run MCP servers on Kubernetes", "method": "oci",
             "chart": "oci://ghcr.io/kagent-dev/kmcp/helm/kmcp", "version": "0.4.0", "ns": "kmcp-system", "needs": ["kagent-crds"],
             "notes": "kagent bundles an older kmcp controller; cloudseed turns it off when this item is installed. Installed kagent before kmcp? "
                      "Run cs platform install kagent --upgrade so only one controller reconciles MCPServers."},
    "qdrant": {"group": "agentic", "desc": "Vector database", "method": "helm",
               "repo": "https://qdrant.github.io/qdrant-helm", "chart": "qdrant", "version": "1.19.1", "ns": "qdrant"},
    # Langfuse 2.x runs ClickHouse through ClickHouse Inc.'s operator (checked against the live API at install time)
    "langfuse": {"group": "agentic", "desc": "LLM observability, tracing and evals", "method": "helm",
                 "repo": "https://langfuse.github.io/langfuse-k8s", "chart": "langfuse", "version": "2.1.2", "ns": "langfuse", "tier": "extra",
                 "needs": ["clickhouse-operator-official"],
                 # NEXTAUTH_URL must be the URL `cs platform ui` serves it at, or sign-in/sign-up redirect to localhost:3000
                 "values": {"default": {"langfuse.nextauth.url": "https://langfuse.{platform_domain}"}},
                 "notes": "Bundles its own Postgres, Valkey and SeaweedFS; ClickHouse (about 1 CPU / 2 GiB plus Keeper) runs through the ClickHouse operator. "
                          "Sign-in works at https://langfuse.<domain> (cs platform ui)."},
    "litellm": {"group": "agentic", "desc": "LLM proxy / model router (OpenAI-compatible)", "method": "oci",
                "chart": "oci://ghcr.io/berriai/litellm-helm", "version": "1.102.1", "ns": "litellm", "tier": "extra",
                "values": {"default": {"postgresql.auth.password": "{litellm_db_password}", "postgresql.auth.postgres-password": "{litellm_db_password}"}}},
    "open-webui": {"group": "agentic", "desc": "Chat UI for local/remote models", "method": "helm",
                   "repo": "https://helm.openwebui.com/", "chart": "open-webui", "version": "16.6.0", "ns": "open-webui", "tier": "extra",
                   # the Pipelines subchart only publishes moving tags (main, git-<sha>): pinned to the digest it was tested with
                   "values": {"default": {"pipelines.image.tag": "main@sha256:b48e9bc338ce2be0acfbeff01810db72408a12f07739f9e3879c1f2b00952d6e",
                                          "pipelines.image.pullPolicy": "IfNotPresent"}}},

    # ---------------- finops ----------------
    "opencost": {"group": "finops", "desc": "OpenCost: real-time Kubernetes cost allocation (namespace, workload, label)", "method": "helm",
                 "repo": "https://opencost.github.io/opencost-helm-chart", "chart": "opencost", "version": "2.5.32", "ns": "opencost", "needs": ["kube-prometheus-stack"],
                 "values": {"default": {"opencost.prometheus.internal.serviceName": "monitoring-kube-prometheus-prometheus",
                                        "opencost.prometheus.internal.namespaceName": "monitoring",
                                        "opencost.prometheus.internal.port": "9090", "opencost.ui.enabled": "true",
                                        "opencost.exporter.defaultClusterId": "{cluster_name}"},
                            "aws": {"opencost.exporter.cloudProviderApiKey": ""},
                            "vmware": {"opencost.customPricing.enabled": "true", "opencost.customPricing.costModel.CPU": "0.02",
                                       "opencost.customPricing.costModel.RAM": "0.005", "opencost.customPricing.costModel.storage": "0.0001"}},
                 "notes": "Cloud billing integration (AWS CUR / GCP BigQuery export / Azure exports) can be added with opencost.cloudIntegrationSecret."},
    "kube-green": {"group": "finops", "desc": "Sleep dev workloads on a schedule (kube-green)", "method": "manifest", "tier": "extra",
                   # a release tag, not releases/latest: uninstall deletes from the same URL, so it must not move under the install
                   "url": "https://github.com/kube-green/kube-green/releases/download/v0.7.1/kube-green.yaml", "ns": "kube-green", "needs": ["cert-manager"],
                   "probe": ["deployment", "kube-green-controller-manager", "kube-green"]},
    # 2.8.x is the last standalone 2.x line: 2.9 only prepares agents for Kubecost 3 (needs clusterId + a federated store)
    "kubecost-cost-analyzer": {"group": "finops", "desc": "Kubecost (free tier; richer UI on top of OpenCost)", "method": "helm", "tier": "extra",
                               "repo": "https://kubecost.github.io/cost-analyzer/", "chart": "cost-analyzer", "version": "2.8.7", "ns": "kubecost",
                               "values": {"default": {"kubecostProductConfigs.clusterName": "{cluster_name}",
                                                      "prometheus.server.global.external_labels.cluster_id": "{cluster_name}"}}},

    # ---------------- devsecops ----------------
    # Chart 9.11.x (GitLab 18.11): 10.x needs external PostgreSQL, Redis and object storage and bundles its own Envoy Gateway.
    # certmanager.install was replaced by the top-level installCertmanager (the schema rejects the old key).
    # Its bundled object store (MinIO 2017) is amd64-only and served at its own host (gitlab-minio.<domain>, clear of the
    # data group's MinIO console at minio.<domain>).
    "gitlab": {"group": "devsecops", "desc": "GitLab (git, CI, registry) - dev-sized, self-signed ingress", "method": "helm",
               "repo": "https://charts.gitlab.io/", "chart": "gitlab", "version": "9.11.13", "ns": "gitlab", "arch": ["amd64"],
               "values": {"default": {"global.hosts.domain": "{platform_domain}", "global.edition": "ce",
                                      "certmanager-issuer.email": "admin@{platform_domain}", "installCertmanager": "false",
                                      "global.ingress.configureCertmanager": "false", "global.ingress.tls.enabled": "false",
                                      "gitlab-runner.install": "false", "prometheus.install": "false",
                                      "global.kas.enabled": "true", "postgresql.image.tag": "16",
                                      "global.hosts.minio.name": "gitlab-minio.{platform_domain}"},
                          "arch-amd64": {"minio.nodeSelector.kubernetes\\.io/arch": "amd64"},
                          "vmware": {"global.ingress.class": "nginx", "nginx-ingress.enabled": "false"},
                          "aws": {"global.ingress.class": "nginx", "nginx-ingress.enabled": "false"},
                          "gcp": {"global.ingress.class": "nginx", "nginx-ingress.enabled": "false"},
                          "azure": {"global.ingress.class": "nginx", "nginx-ingress.enabled": "false"}},
               "needs": ["ingress-nginx", "cert-manager"],
               "notes": "Pinned to chart 9.x (GitLab 18.11). Uses the legacy ingress-nginx (GitLab's chart is Ingress-based). Heavy (several GB); "
                        "its bundled MinIO needs an amd64 node. Initial root password: kubectl -n gitlab get secret gitlab-gitlab-initial-root-password "
                        "-o jsonpath='{.data.password}' | base64 -d. Its hosts (gitlab./registry.<domain>) are not in any DNS: CI jobs clone "
                        "through the in-cluster service (the runner's CLONE_URL), but pushing images to registry.<domain> needs that name to "
                        "resolve from pods and nodes and its certificate trusted (see the CI template's REGISTRY_INSECURE)."},
    # runner 18.11 to match GitLab 18.11. Its token can only be created in the GitLab this group installs, so a group install
    # skips the runner (requires) and says how to add it afterwards.
    "gitlab-runner": {"group": "devsecops", "desc": "GitLab CI runner (Kubernetes executor)", "method": "helm",
                      "repo": "https://charts.gitlab.io/", "chart": "gitlab-runner", "version": "0.88.4", "ns": "gitlab", "needs": ["gitlab"],
                      # CLONE_URL: jobs fetch the repository through the in-cluster service; the project URL GitLab hands out
                      # (https://gitlab.<domain>) resolves nowhere inside the cluster
                      "values": {"default": {"gitlabUrl": "http://gitlab-webservice-default.gitlab.svc:8181",
                                             "runnerToken": "{gitlab_runner_token}", "rbac.create": "true",
                                             "extraEnv.CLONE_URL": "http://gitlab-webservice-default.gitlab.svc:8181"}},
                      "requires": {"any_env": ["GITLAB_RUNNER_TOKEN"],
                                   "hint": "create a runner in this GitLab (Admin > CI/CD > Runners > New instance runner), then "
                                           "cs creds set GITLAB_RUNNER_TOKEN and cs platform install gitlab-runner"},
                      "notes": "Needs GITLAB_RUNNER_TOKEN from this GitLab (Admin > CI/CD > Runners > New instance runner): cs creds set GITLAB_RUNNER_TOKEN. "
                               "Jobs clone through http://gitlab-webservice-default.gitlab.svc:8181 (CLONE_URL)."},
    # manager.env.ssl=false: the Gateway terminates TLS; the manager's own cert is a self-signed CN=neuvector that no backend
    # TLS policy can validate
    "neuvector": {"group": "devsecops", "desc": "NeuVector container security platform (runtime, scanning, WAF)", "method": "helm",
                  "repo": "https://neuvector.github.io/neuvector-helm/", "chart": "core", "version": "2.11.2", "ns": "neuvector",
                  # rke2: the enforcer also runs on the servers, which cloudseed taints CriticalAddonsOnly=true:NoExecute
                  "values": {"default": {"controller.replicas": "1", "cve.scanner.replicas": "1", "manager.svc.type": "ClusterIP", "manager.env.ssl": "false"},
                             "rke2": {"k3s.enabled": "true", "enforcer.tolerations[0].operator": "Exists"}, "kubeadm": {"containerd.enabled": "true"},
                             "eks": {"containerd.enabled": "true"}, "gke": {"containerd.enabled": "true"}, "aks": {"containerd.enabled": "true"}}},
    "trivy-operator": {"group": "devsecops", "desc": "Continuous vulnerability/misconfiguration scanning of workloads", "method": "helm",
                       "repo": "https://aquasecurity.github.io/helm-charts/", "chart": "trivy-operator", "version": "0.36.0", "ns": "trivy-system",
                       "upgrade_crds": ["aquasecurity.github.io"],
                       "values": {"default": {"trivy.ignoreUnfixed": "true"}}},
    # master/join keys (hex, generated once per env in platform/secrets.json) come from a pre-created Secret, never the command line
    "artifactory": {"group": "devsecops", "desc": "JFrog Artifactory OSS - universal artifact repository (Maven, npm, PyPI, generic)", "method": "helm", "tier": "extra",
                    "repo": "https://charts.jfrog.io", "chart": "artifactory-oss", "version": "107.161.26", "ns": "artifactory",
                    "pre": ["artifactory-keys"],
                    "values": {"default": {"artifactory.nginx.enabled": "false", "artifactory.postgresql.enabled": "true",
                                           "artifactory.artifactory.service.type": "ClusterIP",
                                           "artifactory.artifactory.admin.password": "{artifactory_password}",
                                           "global.masterKeySecretName": "artifactory-mandatory-keys",
                                           "global.joinKeySecretName": "artifactory-mandatory-keys"}},
                    "notes": "Needs ~4 GB RAM. UI: cs platform ui (artifactory.<domain>), admin / artifactory_password. Master/join keys: "
                             "artifactory_master_key / artifactory_join_key in platform/secrets.json (Secret artifactory/artifactory-mandatory-keys)."},
    # the chart has no rootPassword.value: the admin password is read from a Secret (pre manifest nexus-root-password)
    "nexus": {"group": "devsecops", "desc": "Sonatype Nexus Repository 3 - artifact + container registry", "method": "helm", "tier": "extra",
              "repo": "https://stevehipwell.github.io/helm-charts/", "chart": "nexus3", "version": "5.26.0", "ns": "nexus",
              "pre": ["nexus-root-password"],
              "values": {"default": {"rootPassword.secret": "nexus-root-password", "rootPassword.key": "password", "persistence.enabled": "true"}},
              "notes": "Community chart (stevehipwell/nexus3). admin / nexus_password (platform/secrets.json). The password is applied on the first start "
                       "of an empty data volume only; an older install keeps its random one: kubectl -n nexus exec nexus-nexus3-0 -- cat /nexus-data/admin.password"},
    # externalURL is the https address `cs platform ui` serves (TLS ends at the Gateway): Harbor builds its registry token
    # realm, push commands and redirects from it. Every Harbor image is amd64-only.
    "harbor": {"group": "devsecops", "desc": "Container registry with scanning and signing", "method": "helm", "tier": "extra",
               "repo": "https://helm.goharbor.io", "chart": "harbor", "version": "1.19.2", "ns": "harbor", "arch": ["amd64"],
               "values": {"default": {"expose.type": "clusterIP", "expose.tls.enabled": "false", "externalURL": "https://harbor.{platform_domain}",
                                      "harborAdminPassword": "{harbor_password}"},
                          "arch-amd64": {f"{c}.nodeSelector.kubernetes\\.io/arch": "amd64"
                                         for c in ("nginx", "portal", "core", "jobservice", "registry", "trivy", "database.internal",
                                                   "redis.internal", "exporter")}},
               "notes": "Reach it through `cs platform ui` (https://harbor.<domain>): logins and registry tokens follow that URL. Needs amd64 nodes."},
    # chart 2025.1+ rejects edition=community: the Community Build is community.enabled=true with no edition
    "sonarqube": {"group": "devsecops", "desc": "Code quality and SAST", "method": "helm", "tier": "extra",
                  "repo": "https://SonarSource.github.io/helm-chart-sonarqube", "chart": "sonarqube", "version": "2026.4.1", "ns": "sonarqube",
                  "values": {"default": {"community.enabled": "true", "monitoringPasscode": "{sonar_passcode}", "persistence.enabled": "true"}}},

    # ---------------- security / zero trust ----------------
    # all Istio charts move together (one release, 1.30.5)
    "istio-base": {"group": "security", "desc": "Istio CRDs", "method": "helm", "hidden": True,
                   "repo": "https://istio-release.storage.googleapis.com/charts", "chart": "base", "version": "1.30.5", "ns": "istio-system"},
    "istiod": {"group": "security", "desc": "Istio control plane", "method": "helm", "hidden": True,
               "repo": "https://istio-release.storage.googleapis.com/charts", "chart": "istiod", "version": "1.30.5", "ns": "istio-system", "needs": ["istio-base"],
               "values": {"ambient": {"profile": "ambient"}}},
    # RKE2 on Linux keeps CNI in the chart defaults (/opt/cni/bin, /etc/cni/net.d); global.platform=k3s points at k3s-only paths
    "istio-cni": {"group": "security", "desc": "Istio CNI node agent (ambient)", "method": "helm", "hidden": True,
                  "repo": "https://istio-release.storage.googleapis.com/charts", "chart": "cni", "version": "1.30.5", "ns": "istio-system", "needs": ["istiod"],
                  "values": {"ambient": {"profile": "ambient"}, "rke2": {"cni.cniBinDir": "/opt/cni/bin", "cni.cniConfDir": "/etc/cni/net.d"},
                             "gke": {"global.platform": "gke"}}},
    "ztunnel": {"group": "security", "desc": "Istio ambient zero-trust tunnel (per node L4 mTLS)", "method": "helm", "hidden": True,
                "repo": "https://istio-release.storage.googleapis.com/charts", "chart": "ztunnel", "version": "1.30.5", "ns": "istio-system", "needs": ["istio-cni"]},
    "istio": {"group": "security", "desc": "Istio service mesh (mode: ambient [default] or sidecar) with strict mTLS", "method": "meta",
              "ns": "istio-system", "modes": {"ambient": ["istio-base", "istiod", "istio-cni", "ztunnel"], "sidecar": ["istio-base", "istiod"]},
              "post": ["istio-strict-mtls"], "probe": ["peerauthentication", "default", "istio-system"],
              "notes": "Choose with --set mode=sidecar (default ambient). Label namespaces: istio.io/dataplane-mode=ambient or istio-injection=enabled."},
    # no fips key on purpose: it needs the Istio mesh, whose images are not FIPS-validated, so FIPS environments refuse both
    "istio-gateway": {"group": "security", "desc": "Istio ingress gateway (private LB address: VPN/bastion on clouds, host-only network on vmware)", "method": "helm", "tier": "extra",
                      "repo": "https://istio-release.storage.googleapis.com/charts", "chart": "gateway", "version": "1.30.5", "ns": "istio-ingress", "needs": ["istio"],
                      "values": {"aws": {"service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme": "internal",
                                         "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal": "true",
                                         "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type": "nlb"},
                                 "gcp": {"service.annotations.networking\\.gke\\.io/load-balancer-type": "Internal"},
                                 "azure": {"service.annotations.service\\.beta\\.kubernetes\\.io/azure-load-balancer-internal": "true"}}},
    "kiali": {"group": "security", "desc": "Mesh observability console", "method": "helm", "tier": "extra",
              "repo": "https://kiali.org/helm-charts", "chart": "kiali-server", "version": "2.32.0", "ns": "istio-system", "needs": ["istio"],
              "values": {"default": {"auth.strategy": "anonymous"}}},
    # syscall rules only (the container plugin): Kubernetes audit events would need the k8saudit plugin plus an API-server
    # audit webhook (or the EKS/GKE/AKS log plugins). The Falcosidekick UI gets a generated password (the chart default is
    # admin:admin) and is exposed by `cs platform ui`; rke2 servers carry CriticalAddonsOnly=true:NoExecute, tolerated so
    # the control-plane nodes are watched too.
    "falco": {"group": "security", "desc": "Runtime threat detection (syscalls) + Falcosidekick UI", "method": "helm",
              "repo": "https://falcosecurity.github.io/charts", "chart": "falco", "version": "9.2.0", "ns": "falco",
              "values": {"default": {"driver.kind": "modern_ebpf", "falcosidekick.enabled": "true", "falcosidekick.webui.enabled": "true",
                                     "falcosidekick.webui.user": "admin:{falco_ui_password}"},
                         "rke2": {"tolerations[0].operator": "Exists"}},
              "notes": "Detects suspicious syscalls in every container (Kubernetes API audit events are not collected). Events: "
                       "cs platform ui (falco.<domain>, admin / falco_ui_password in platform/secrets.json)."},
    "kyverno-policies": {"group": "security", "desc": "Kyverno pod-security baseline policies (audit mode)", "method": "helm",
                         "repo": "https://kyverno.github.io/kyverno/", "chart": "kyverno-policies", "version": "3.9.1", "ns": "kyverno", "needs": ["kyverno"],
                         "values": {"default": {"podSecurityStandard": "baseline", "validationFailureAction": "Audit"}}},
    "cert-manager-issuer": {"group": "basek8s", "desc": "Cluster CA issuer (cert-manager) for TLS on every UI", "method": "post-only",
                            "ns": "cert-manager", "needs": ["cert-manager"], "post": ["selfsigned-issuer"],
                            "probe": ["clusterissuer", "cloudseed-ca"],
                            "notes": "The cluster CA (Secret cert-manager/cloudseed-root-ca) is valid for 10 years and keeps its key when renewed: "
                                     "import it once. Created by an older cloudseed (90-day CA)? cs platform install cert-manager-issuer --upgrade, "
                                     "then export and import it one more time."},
    "vault": {"group": "security", "desc": "HashiCorp Vault (dev mode - not for production secrets)", "method": "helm", "tier": "extra",
              "repo": "https://helm.releases.hashicorp.com", "chart": "vault", "version": "0.34.1", "ns": "vault",
              "values": {"default": {"server.dev.enabled": "true", "injector.enabled": "true"}}},
}

CATALOG.update({
    # ---------------- local clusters: a default StorageClass (RKE2/kubeadm ship none) ----------------
    "local-path-provisioner": {"group": "basek8s", "desc": "Default StorageClass for local clusters (Rancher local-path, node disks)", "method": "manifest", "only": ["vmware"],
                               "url": "https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.37/deploy/local-path-storage.yaml", "ns": "local-path-storage",
                               "probe": ["storageclass", "local-path"], "post": ["local-path-default"], "fips": "compatible",
                               "notes": "Every item that claims a PersistentVolume on a local cluster pulls this in first. Managed clusters already have a default "
                                        "StorageClass: cloudseed's EKS stack enables the EBS CSI add-on's gp3 class (ebs-csi-default-sc); GKE and AKS ship their own."},
    # ---------------- resilience / disaster recovery ----------------
    "velero": {"group": "resilience", "desc": "Backup and restore of cluster state and volumes (Velero + node agent, cloud bucket or MinIO)", "method": "helm",
               "repo": "https://vmware-tanzu.github.io/helm-charts", "chart": "velero", "ns": "velero", "version": "12.2.0",
               "cloud_prereqs": ["velero"], "needs_by_target": {"vmware": ["local-path-provisioner", "minio"]}, "pre_by_target": {"azure": ["velero-azure-credentials"], "vmware": ["velero-minio-credentials"]},
               "post_by_target": {"vmware": ["velero-minio-bucket"]}, "fips": "crypto-restricted",   # kopia encrypts the backup repository
               "values": {"default": {"deployNodeAgent": "true", "snapshotsEnabled": "false", "configuration.defaultVolumesToFsBackup": "true",
                                      "configuration.backupStorageLocation[0].name": "default", "configuration.backupStorageLocation[0].default": "true",
                                      "initContainers[0].volumeMounts[0].mountPath": "/target", "initContainers[0].volumeMounts[0].name": "plugins",
                                      "metrics.enabled": "true",
                                      # the IRSA role / GKE WI binding / Azure federated credential all trust velero/velero
                                      "serviceAccount.server.name": "velero"},
                          # plugin v1.14.x is the line built for Velero 1.18 (chart 12.2.0)
                          "aws": {"initContainers[0].name": "velero-plugin-for-aws", "initContainers[0].image": "velero/velero-plugin-for-aws:v1.14.3",
                                  "credentials.useSecret": "false", "serviceAccount.server.annotations.eks\\.amazonaws\\.com/role-arn": "{velero_role_arn}",
                                  "podSecurityContext.fsGroup": "1337",
                                  "configuration.backupStorageLocation[0].provider": "aws", "configuration.backupStorageLocation[0].bucket": "{velero_bucket}",
                                  "configuration.backupStorageLocation[0].config.region": "{region}"},
                          # FIPS: the bucket through the S3 FIPS endpoint (the plugin and kopia both use s3Url; AWS_USE_FIPS_ENDPOINT
                          # cannot be combined with a custom endpoint) and the IRSA token exchange through STS FIPS (server and node agent)
                          "aws+fips": {"configuration.backupStorageLocation[0].config.s3Url": "https://s3-fips.{region}.amazonaws.com",
                                       "configuration.extraEnvVars[0].name": "AWS_ENDPOINT_URL_STS",
                                       "configuration.extraEnvVars[0].value": "https://sts-fips.{region}.amazonaws.com"},
                          "gcp": {"initContainers[0].name": "velero-plugin-for-gcp", "initContainers[0].image": "velero/velero-plugin-for-gcp:v1.14.3",
                                  "credentials.useSecret": "false", "serviceAccount.server.annotations.iam\\.gke\\.io/gcp-service-account": "{velero_gsa}",
                                  "configuration.backupStorageLocation[0].config.serviceAccount": "{velero_gsa}",   # Workload Identity: the plugin needs it
                                  "configuration.backupStorageLocation[0].provider": "gcp", "configuration.backupStorageLocation[0].bucket": "{velero_bucket}"},
                          "azure": {"initContainers[0].name": "velero-plugin-for-microsoft-azure", "initContainers[0].image": "velero/velero-plugin-for-microsoft-azure:v1.14.3",
                                    "credentials.useSecret": "true", "credentials.existingSecret": "velero-credentials",
                                    "serviceAccount.server.annotations.azure\\.workload\\.identity/client-id": "{velero_client_id}",
                                    "podLabels.azure\\.workload\\.identity/use": "true",
                                    "nodeAgent.podLabels.azure\\.workload\\.identity/use": "true",   # kopia uploads run in the node agent
                                    "configuration.backupStorageLocation[0].provider": "azure", "configuration.backupStorageLocation[0].bucket": "{velero_container}",
                                    "configuration.backupStorageLocation[0].config.resourceGroup": "{resource_group}",
                                    "configuration.backupStorageLocation[0].config.storageAccount": "{velero_storage_account}",
                                    "configuration.backupStorageLocation[0].config.useAAD": "true"},
                          "vmware": {"initContainers[0].name": "velero-plugin-for-aws", "initContainers[0].image": "velero/velero-plugin-for-aws:v1.14.3",
                                     "credentials.useSecret": "true", "credentials.existingSecret": "velero-credentials",
                                     "configuration.backupStorageLocation[0].provider": "aws", "configuration.backupStorageLocation[0].bucket": "velero",
                                     "configuration.backupStorageLocation[0].config.region": "minio",
                                     "configuration.backupStorageLocation[0].config.s3ForcePathStyle": "true",
                                     "configuration.backupStorageLocation[0].config.s3Url": "http://minio.minio.svc:9000",
                                     # the credentials Secret is not the chart's: a new MinIO key restarts the pods this way
                                     "podAnnotations.cloudseed\\.io/minio-credentials": "{minio_velero_checksum}"}},
               "notes": "Backups go to a hardened bucket the cloudseed stack creates on demand (S3 / GCS / Azure Blob, identity via IRSA / Workload Identity) or to "
                        "MinIO on local clusters. Volumes are backed up with the node agent (file-system backup). Drive it with `cs dr backup|restore|schedule|test` (`cs dr describe|logs` show one backup or restore)."},
    "kured": {"group": "resilience", "desc": "Safe rolling node reboots when the OS asks for one (kured)", "method": "helm",
              "repo": "https://kubereboot.github.io/charts", "chart": "kured", "version": "6.1.0", "ns": "kured", "fips": "compatible",
              # reboot window Mon-Fri 09:00-17:00 (UTC unless configuration.timeZone is set); indexed keys, not a {a,b} literal
              "values": {"default": {"configuration.period": "1h", "configuration.rebootDays[0]": "mon", "configuration.rebootDays[1]": "tue",
                                     "configuration.rebootDays[2]": "wed", "configuration.rebootDays[3]": "thu", "configuration.rebootDays[4]": "fri",
                                     "configuration.startTime": "9am", "configuration.endTime": "5pm"},
                         "rke2": {"tolerations[0].operator": "Exists"}},
              # rke2 servers carry CriticalAddonsOnly=true:NoExecute: tolerated, so the control-plane nodes get their reboots too
              "notes": "Nodes reboot only Mon-Fri 09:00-17:00 UTC, one at a time; use your zone with --set configuration.timeZone=Europe/Berlin "
                       "(kept for later upgrades). Control-plane nodes are rebooted too: with a single one the API is briefly unavailable."},
    "descheduler": {"group": "resilience", "desc": "Rebalance pods across nodes (duplicates, node utilisation, affinity violations)", "method": "helm",
                    "repo": "https://kubernetes-sigs.github.io/descheduler/", "chart": "descheduler", "version": "0.36.0", "ns": "kube-system", "fips": "compatible",
                    # as a Deployment the chart runs every deschedulingInterval (`schedule` is only read in CronJob mode)
                    "values": {"default": {"kind": "Deployment", "deschedulingInterval": "30m"}}},
    # ---------------- chaos engineering ----------------
    "chaos-mesh": {"group": "chaos", "desc": "Chaos Mesh: pod, network, DNS, stress, time and IO faults with a dashboard (`cs chaos run` drives it)", "method": "helm",
                   "repo": "https://charts.chaos-mesh.org", "chart": "chaos-mesh", "version": "2.8.4", "ns": "chaos-mesh", "fips": "compatible",
                   "upgrade_crds": ["chaos-mesh.org"],
                   "values": {"default": {"chaosDaemon.runtime": "containerd", "chaosDaemon.socketPath": "{containerd_socket}",
                                          "dashboard.create": "true", "dashboard.securityMode": "true", "dashboard.service.type": "ClusterIP",
                                          "dnsServer.create": "true"}},
                   "post": ["chaos-dashboard-admin"],
                   "notes": "The dashboard is exposed by `cs platform ui` (chaos-mesh.<domain>) and asks for a token: "
                            "cs kubectl create token cloudseed-chaos-admin -n chaos-mesh --duration=24h (`cs platform ui` prints it)."},
    # its MongoDB (bitnamilegacy/mongodb 8.0.13) exists for amd64 only
    "litmus": {"group": "chaos", "desc": "LitmusChaos ChaosCenter (portal + experiments hub)", "method": "helm", "tier": "extra",
               "repo": "https://litmuschaos.github.io/litmus-helm/", "chart": "litmus", "version": "3.30.0", "ns": "litmus", "arch": ["amd64"],
               "values": {"default": {"portal.frontend.service.type": "ClusterIP"},
                          "arch-amd64": {"mongodb.nodeSelector.kubernetes\\.io/arch": "amd64", "mongodb.arbiter.nodeSelector.kubernetes\\.io/arch": "amd64"}},
               "notes": "UI via `cs platform ui` (litmus.<domain>): admin / litmus (change it). Its MongoDB needs amd64 nodes."},
    # ---------------- more security / compliance ----------------
    "kubescape-operator": {"group": "security", "desc": "Continuous configuration, vulnerability and node scanning (NSA / MITRE / CIS reports as CRDs)", "method": "helm", "tier": "extra",
                           "repo": "https://kubescape.github.io/helm-charts/", "chart": "kubescape-operator", "version": "1.40.4", "ns": "kubescape", "fips": "compatible",
                           "upgrade_crds": ["kubescape.io"],
                           # the node agent tolerates nothing by default: rke2 servers (NoExecute) and kubeadm control planes
                           # (NoSchedule) would go unscanned
                           "values": {"default": {"clusterName": "{cluster_name}", "capabilities.continuousScan": "enable"},
                                      "rke2": {"nodeAgent.tolerations[0].operator": "Exists"},
                                      "kubeadm": {"nodeAgent.tolerations[0].operator": "Exists"}},
                           "notes": "One-off scans without the operator: `cs scan kube`."},
    # sources: all three indices (a list is replaced, not merged); gateway-httproute makes the chart add the Gateway API RBAC
    # and needs the Gateway API CRDs to exist
    "external-dns": {"group": "basek8s", "desc": "Publish Services/Ingresses/HTTPRoutes in Route53 / Cloud DNS / Azure DNS (cloud identity wired in)", "method": "helm", "tier": "extra",
                     "repo": "https://kubernetes-sigs.github.io/external-dns/", "chart": "external-dns", "version": "1.22.0", "ns": "external-dns", "only": ["aws", "gcp", "azure"],
                     "needs": ["gateway-api"], "upgrade_crds": ["externaldns.k8s.io"],
                     "pre_by_target": {"azure": ["external-dns-azure-config"]}, "fips": "compatible",
                     "values": {"default": {"serviceAccount.name": "external-dns", "policy": "upsert-only", "txtOwnerId": "{cluster_name}",
                                            "sources[0]": "service", "sources[1]": "ingress", "sources[2]": "gateway-httproute"},
                                "aws+fips": {"env[0].name": "AWS_USE_FIPS_ENDPOINT", "env[0].value": "true"},
                                "aws": {"provider.name": "aws", "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn": "{external_dns_role_arn}"},
                                "gcp": {"provider.name": "google", "serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account": "{external_dns_gsa}",
                                        "extraArgs[0]": "--google-project={project_id}"},
                                "azure": {"provider.name": "azure", "serviceAccount.annotations.azure\\.workload\\.identity/client-id": "{external_dns_client_id}",
                                          "podLabels.azure\\.workload\\.identity/use": "true",
                                          "extraVolumes[0].name": "azure-config-file", "extraVolumes[0].secret.secretName": "azure-config-file",
                                          "extraVolumeMounts[0].name": "azure-config-file", "extraVolumeMounts[0].mountPath": "/etc/kubernetes", "extraVolumeMounts[0].readOnly": "true"}},
                     "notes": "Identity (IRSA route53 policy / GSA dns.admin / UAMI DNS Zone Contributor) is created by the cloudseed Kubernetes stack. "
                              "Publishes the hostnames of Services, Ingresses and HTTPRoutes (the shared Gateway's private address). "
                              "Restrict zones with --set domainFilters[0]=example.com."},
})

# Items that claim PersistentVolumes: on local clusters they need the local-path StorageClass first.
for _n in ("minio", "cloudnative-pg", "strimzi", "starrocks", "airflow", "jupyterhub", "qdrant", "gitlab", "harbor", "artifactory", "nexus", "sonarqube", "langfuse",
           "clickhouse-operator", "kubeflow-pipelines", "mlflow", "open-webui", "ollama", "litmus", "kubecost-cost-analyzer", "loki", "polaris"):
    CATALOG[_n].setdefault("needs_by_target", {}).setdefault("vmware", []).insert(0, "local-path-provisioner")

# FIPS capability of catalog items when the environment runs in FIPS mode:
#   "compatible"      controllers and services that run fine on FIPS kernels and terminate no user-facing TLS with their own
#                     crypto (UIs are served over plain HTTP behind the shared Gateway, which terminates TLS);
#   "tls-restricted"  the user-facing TLS terminators (envoy-gateway, ingress-nginx): installed, with TLS pinned to 1.2+/FIPS
#                     suites (envoy-fips-tls, the ingress-nginx fips values), but their proxy crypto (Envoy BoringSSL,
#                     OpenSSL) is not a validated module - `cs scan fips` must report them as such, not as a PASS;
#   "crypto-restricted" items whose job IS cryptography - key generation, signing, encryption - done in a non-validated
#                     module (upstream Go crypto / OpenSSL builds): cert-manager (the cluster CA and every UI certificate),
#                     sealed-secrets, velero (kopia repository encryption), cloudnative-pg (Postgres CA and client TLS).
#                     Installed (the platform needs them), but `cs scan fips` must flag them like tls-restricted;
#   no key            application stacks whose images ship their own (non-validated) crypto libraries: installing them into
#                     a FIPS environment is refused unless --force is given, and `cs scan fips` reports them.
FIPS_CLASSES = ("compatible", "tls-restricted", "crypto-restricted")
for _n in ("metrics-server", "cert-manager-issuer", "gateway-api", "envoy-gateway", "ingress-nginx", "metallb", "aws-load-balancer-controller",
           "argocd", "kube-prometheus-stack", "loki", "alloy", "opentelemetry-operator", "external-secrets", "reloader", "kyverno", "kyverno-policies",
           "keda", "vpa", "goldilocks", "opencost", "kube-green", "trivy-operator", "falco", "minio", "gpu-operator"):
    CATALOG[_n].setdefault("fips", "compatible")

# Pod Security Standard level an item's pods need. RKE2's CIS profile (kubernetes_cis_profile=true) enforces
# "restricted" in every namespace but kube-system, so under it install_one labels the item's namespaces with the level
# first (never lowering a label that is already there). Taken from `helm template` of every chart with its catalog
# values (vmware/rke2) plus what the operators start at runtime: local-path's helper pods and trivy's node collector
# mount host paths; Strimzi's brokers, JupyterHub's notebooks, Kubeflow's pipeline steps and kagent's agents (the
# controller creates their Deployments without any securityContext) meet baseline only.
# Untagged items meet restricted (or only run on managed clouds). A dict names every namespace the item runs pods in.
POD_SECURITY_LEVELS = ("restricted", "baseline", "privileged")
for _n in ("metallb", "kube-prometheus-stack", "local-path-provisioner", "istio-cni", "ztunnel", "falco", "neuvector", "kured",
           "chaos-mesh", "kubescape-operator", "trivy-operator", "sonarqube"):   # host network/PID/paths, privileged, extra caps
    CATALOG[_n].setdefault("pod_security", "privileged")
for _n in ("loki", "alloy", "reloader", "minio", "strimzi", "trino", "starrocks", "polaris", "airflow", "clickhouse-operator",
           "kubeflow-trainer", "kubeflow-pipelines", "jupyterhub", "mlflow", "vllm-stack", "ollama", "agentgateway", "qdrant",
           "langfuse", "litellm", "open-webui", "opencost", "gitlab", "gitlab-runner", "nexus", "istiod", "istio-gateway",
           "vault", "litmus", "kagent"):                                       # root, no seccomp profile, capabilities kept
    CATALOG[_n].setdefault("pod_security", "baseline")
CATALOG["velero"]["pod_security"] = {"velero": "privileged", "minio": "baseline"}   # node agent: host paths; bucket Job
CATALOG["spark-history-server"]["pod_security"] = {"spark-operator": "baseline", "minio": "baseline"}

GROUPS = {
    "basek8s": "Cluster management: metrics, certs, Gateway API + Envoy Gateway (private LB), GitOps, observability (Prometheus, Loki), OTel, secrets",
    "scaling": "Autoscaling: KEDA, VPA + Goldilocks (+ metrics-server), cluster-autoscaler / Karpenter (cloud)",
    "data": "Data platform: MinIO, Postgres operator, Kafka, Spark, Trino, StarRocks, Polaris, Airflow, ClickHouse",
    "ai": "AI/ML: Ray, Kubeflow trainer/pipelines, KServe, JupyterHub, MLflow, vLLM, GPU operator, Ollama",
    "agentic": "Agentic: kagent, kmcp, agentgateway, Qdrant, Langfuse, LiteLLM, Open WebUI",
    "finops": "FinOps: OpenCost (+ Prometheus), kube-green, Kubecost; pairs with `cs finops` for cloud bills and estimates",
    "devsecops": "DevSecOps: GitLab + runner (once GITLAB_RUNNER_TOKEN is set) + CI template, NeuVector, Trivy operator, ArgoCD; registries: Harbor, Artifactory, Nexus; SonarQube",
    "security": "Security / zero trust: Istio (ambient or sidecar, strict mTLS), Falco, Kyverno policies, cert-manager + cluster CA issuer, External Secrets; extras: gateway, Kiali, Vault, Kubescape operator",
    "resilience": "Resilience / DR: Velero backups (cloud bucket + identity created on demand), kured reboots, descheduler; `cs dr` runs backups, restores and drills",
    "chaos": "Chaos engineering: Chaos Mesh (+ LitmusChaos extra); `cs chaos run` executes automated experiments with a PASS/FAIL report",
}

GROUP_EXTRA_MEMBERS = {"devsecops": ["argocd", "kyverno"], "security": ["kyverno", "cert-manager", "cert-manager-issuer", "external-secrets"],
                       "finops": ["metrics-server", "goldilocks"]}

POST_MANIFESTS = {
    "cloudseed-gateway": """apiVersion: v1
kind: Namespace
metadata: {name: cloudseed}
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata: {name: cloudseed, namespace: envoy-gateway-system}
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyService:
        type: LoadBalancer
        annotations:
{lb_annotations}
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: cloudseed}
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
  parametersRef: {group: gateway.envoyproxy.io, kind: EnvoyProxy, name: cloudseed, namespace: envoy-gateway-system}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: cloudseed-wildcard, namespace: cloudseed}
spec:
  secretName: cloudseed-wildcard-tls
  dnsNames: ["*.{platform_domain}", "{platform_domain}"]
  issuerRef: {name: cloudseed-ca, kind: ClusterIssuer}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: cloudseed, namespace: cloudseed}
spec:
  gatewayClassName: cloudseed
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
    - name: https
      protocol: HTTPS
      port: 443
      hostname: "*.{platform_domain}"
      tls:
        mode: Terminate
        certificateRefs: [{kind: Secret, name: cloudseed-wildcard-tls}]
      allowedRoutes:
        namespaces:
          from: All
""",
    # The bucket, a least-privilege MinIO user (generated name, minio_spark_user) and its policy are created by a Job in
    # the minio namespace with the root login from the chart's own Secret there (it never leaves that namespace); the
    # Job removes the well-known user `spark` of older installs once the new one exists. The history server authenticates
    # from Secret spark-s3 (its pods roll when that key changes); apache/spark ships no S3A jars, an init container fetches
    # the ones matching Hadoop 3.3.4.
    "spark-history-server": """apiVersion: v1
kind: Secret
metadata:
  name: minio-user-spark
  namespace: minio
type: Opaque
stringData:
  user: "{minio_spark_user}"
  password: "{minio_spark_password}"
---
apiVersion: batch/v1
kind: Job
metadata: {name: spark-logs-bucket, namespace: minio}
spec:
  ttlSecondsAfterFinished: 600
  backoffLimit: 10
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: mc
          image: """ + MINIO_MC_REF + """
          command: ["/bin/sh", "-ec"]
          args:
            - |
              mc alias set m http://minio.minio.svc:9000 "$ROOT_USER" "$ROOT_PASSWORD" >/dev/null
              mc mb --ignore-existing m/spark-logs
              printf '%s' "$POLICY" > /tmp/policy.json
              mc admin policy create m spark-logs-rw /tmp/policy.json
              mc admin user add m "$USER_NAME" "$USER_PASSWORD"
              mc admin policy attach m spark-logs-rw --user "$USER_NAME" >/dev/null 2>&1 || true
              if [ "$USER_NAME" != spark ]; then mc admin user remove m spark >/dev/null 2>&1 || true; fi
          env:
            - name: ROOT_USER
              valueFrom:
                secretKeyRef:
                  name: minio
                  key: rootUser
            - name: ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: minio
                  key: rootPassword
            - name: USER_NAME
              valueFrom:
                secretKeyRef:
                  name: minio-user-spark
                  key: user
            - name: USER_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: minio-user-spark
                  key: password
            - name: POLICY
              value: '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"], "Resource": ["arn:aws:s3:::spark-logs"]}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"], "Resource": ["arn:aws:s3:::spark-logs/*"]}]}'
---
apiVersion: v1
kind: Secret
metadata:
  name: spark-s3
  namespace: spark-operator
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: "{minio_spark_user}"
  AWS_SECRET_ACCESS_KEY: "{minio_spark_password}"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spark-history-conf
  namespace: spark-operator
data:
  spark-defaults.conf: |
    spark.eventLog.enabled true
    spark.eventLog.dir s3a://spark-logs/
    spark.history.fs.logDirectory s3a://spark-logs/
    spark.history.fs.update.interval 30s
    spark.hadoop.fs.s3a.endpoint http://minio.minio.svc:9000
    spark.hadoop.fs.s3a.path.style.access true
    spark.hadoop.fs.s3a.connection.ssl.enabled false
    spark.hadoop.fs.s3a.impl org.apache.hadoop.fs.s3a.S3AFileSystem
    spark.hadoop.fs.s3a.aws.credentials.provider com.amazonaws.auth.EnvironmentVariableCredentialsProvider
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spark-history-server
  namespace: spark-operator
  labels:
    app: spark-history-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: spark-history-server
  template:
    metadata:
      labels:
        app: spark-history-server
      annotations:
        cloudseed.io/s3-credentials: "{minio_spark_checksum}"
    spec:
      initContainers:
        - name: s3a-jars
          image: apache/spark:3.5.3
          command: ["/bin/sh", "-ec"]
          args:
            - |
              cd /extra-jars
              wget -q -O hadoop-aws-3.3.4.jar https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-aws/3.3.4/hadoop-aws-3.3.4.jar
              wget -q -O aws-java-sdk-bundle-1.12.262.jar https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-bundle/1.12.262/aws-java-sdk-bundle-1.12.262.jar
          volumeMounts:
            - name: extra-jars
              mountPath: /extra-jars
      containers:
        - name: history
          image: apache/spark:3.5.3
          command: ["/opt/spark/bin/spark-class", "org.apache.spark.deploy.history.HistoryServer"]
          env:
            - name: SPARK_NO_DAEMONIZE
              value: "true"
            - name: SPARK_CONF_DIR
              value: /opt/spark/conf
            - name: SPARK_DAEMON_CLASSPATH
              value: "/extra-jars/*"
          envFrom:
            - secretRef:
                name: spark-s3
          ports:
            - containerPort: 18080
              name: http
          readinessProbe:
            httpGet:
              path: /
              port: 18080
            initialDelaySeconds: 10
            periodSeconds: 10
          volumeMounts:
            - name: conf
              mountPath: /opt/spark/conf
            - name: extra-jars
              mountPath: /extra-jars
          resources:
            requests:
              cpu: 100m
              memory: 512Mi
      volumes:
        - name: conf
          configMap:
            name: spark-history-conf
        - name: extra-jars
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: spark-history-server
  namespace: spark-operator
spec:
  selector:
    app: spark-history-server
  ports:
    - name: http
      port: 18080
      targetPort: 18080
""",
    "kafka-cluster": """apiVersion: kafka.strimzi.io/v1
kind: KafkaNodePool
metadata:
  name: dual-role
  namespace: kafka
  labels: {strimzi.io/cluster: cloudseed}
spec:
  replicas: 1
  roles: [controller, broker]
  storage:
    type: jbod
    volumes:
      - {id: 0, type: persistent-claim, size: 20Gi, deleteClaim: false, kraftMetadata: shared}
---
apiVersion: kafka.strimzi.io/v1
kind: Kafka
metadata:
  name: cloudseed
  namespace: kafka
spec:
  kafka:
    listeners:
      - {name: plain, port: 9092, type: internal, tls: false}
      - {name: tls, port: 9093, type: internal, tls: true}
    config:
      offsets.topic.replication.factor: 1
      transaction.state.log.replication.factor: 1
      transaction.state.log.min.isr: 1
      default.replication.factor: 1
      min.insync.replicas: 1
  entityOperator:
    topicOperator: {}
    userOperator: {}
""",
    "istio-strict-mtls": """apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: default, namespace: istio-system}
spec:
  mtls: {mode: STRICT}
""",
    # The cluster CA users import once (`cs platform ui` prints how): 10 years, and never a new key on renewal - with
    # cert-manager's defaults (90 days, rotationPolicy Always since 1.18) it would change every ~60 days and every UI
    # would stop being trusted. The certificates it signs keep the 90-day default.
    "selfsigned-issuer": """apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: selfsigned}
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: cloudseed-root-ca, namespace: cert-manager}
spec:
  isCA: true
  commonName: cloudseed-root-ca
  secretName: cloudseed-root-ca
  duration: 87600h
  renewBefore: 720h
  privateKey: {algorithm: ECDSA, size: 256, rotationPolicy: Never}
  issuerRef: {name: selfsigned, kind: ClusterIssuer}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: cloudseed-ca}
spec:
  ca: {secretName: cloudseed-root-ca}
""",
    "local-path-default": """apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-path
  annotations: {storageclass.kubernetes.io/is-default-class: "true", defaultVolumeType: local}
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
""",
    "velero-minio-credentials": """apiVersion: v1
kind: Namespace
metadata: {name: velero}
---
apiVersion: v1
kind: Secret
metadata: {name: velero-credentials, namespace: velero}
type: Opaque
stringData:
  cloud: |
    [default]
    aws_access_key_id = {minio_velero_user}
    aws_secret_access_key = {minio_velero_password}
""",
    # bucket + a user of its own (generated name, minio_velero_user; policy limited to the velero bucket) created in the
    # minio namespace with the chart's root Secret; the well-known user `velero` of older installs goes once it exists
    "velero-minio-bucket": """apiVersion: v1
kind: Secret
metadata:
  name: minio-user-velero
  namespace: minio
type: Opaque
stringData:
  user: "{minio_velero_user}"
  password: "{minio_velero_password}"
---
apiVersion: batch/v1
kind: Job
metadata: {name: velero-bucket, namespace: minio}
spec:
  ttlSecondsAfterFinished: 600
  backoffLimit: 10
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: mc
          image: """ + MINIO_MC_REF + """
          command: ["/bin/sh", "-ec"]
          args:
            - |
              mc alias set m http://minio.minio.svc:9000 "$ROOT_USER" "$ROOT_PASSWORD" >/dev/null
              mc mb --ignore-existing m/velero
              printf '%s' "$POLICY" > /tmp/policy.json
              mc admin policy create m velero-rw /tmp/policy.json
              mc admin user add m "$USER_NAME" "$USER_PASSWORD"
              mc admin policy attach m velero-rw --user "$USER_NAME" >/dev/null 2>&1 || true
              if [ "$USER_NAME" != velero ]; then mc admin user remove m velero >/dev/null 2>&1 || true; fi
          env:
            - name: ROOT_USER
              valueFrom:
                secretKeyRef:
                  name: minio
                  key: rootUser
            - name: ROOT_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: minio
                  key: rootPassword
            - name: USER_NAME
              valueFrom:
                secretKeyRef:
                  name: minio-user-velero
                  key: user
            - name: USER_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: minio-user-velero
                  key: password
            - name: POLICY
              value: '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"], "Resource": ["arn:aws:s3:::velero"]}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"], "Resource": ["arn:aws:s3:::velero/*"]}]}'
""",
    "velero-azure-credentials": """apiVersion: v1
kind: Namespace
metadata: {name: velero}
---
apiVersion: v1
kind: Secret
metadata: {name: velero-credentials, namespace: velero}
type: Opaque
stringData:
  cloud: |
    AZURE_SUBSCRIPTION_ID={subscription_id}
    AZURE_TENANT_ID={tenant_id}
    AZURE_RESOURCE_GROUP={node_resource_group}
    AZURE_CLOUD_NAME=AzurePublicCloud
""",
    "external-dns-azure-config": """apiVersion: v1
kind: Namespace
metadata: {name: external-dns}
---
apiVersion: v1
kind: Secret
metadata: {name: azure-config-file, namespace: external-dns}
type: Opaque
stringData:
  azure.json: |
    {"tenantId": "{tenant_id}", "subscriptionId": "{subscription_id}", "resourceGroup": "{resource_group}", "useWorkloadIdentityExtension": true}
""",
    "karpenter-default": """apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata: {name: default}
spec:
  amiSelectorTerms: [{alias: bottlerocket@latest}]
  role: "{karpenter_node_role}"
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "{cluster_name}"
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "{cluster_name}"
  metadataOptions: {httpTokens: required, httpPutResponseHopLimit: 1}
  # both Bottlerocket volumes encrypted explicitly (never left to the region's EBS default): /dev/xvda the OS, /dev/xvdb
  # images, logs and ephemeral storage. A custom list replaces Karpenter's defaults, so the root volume must be listed too.
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs: {volumeSize: 4Gi, volumeType: gp3, encrypted: true}
    - deviceName: /dev/xvdb
      ebs: {volumeSize: 50Gi, volumeType: gp3, encrypted: true}
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata: {name: default}
spec:
  template:
    spec:
      nodeClassRef: {group: karpenter.k8s.aws, kind: EC2NodeClass, name: default}
      requirements:
        - {key: kubernetes.io/arch, operator: In, values: [amd64, arm64]}
        - {key: karpenter.sh/capacity-type, operator: In, values: [on-demand]}
        - {key: karpenter.k8s.aws/instance-category, operator: In, values: [c, m, r, t]}
        - {key: karpenter.k8s.aws/instance-generation, operator: Gt, values: ["4"]}
      expireAfter: 720h
  limits: {cpu: "64", memory: 256Gi}
  disruption: {consolidationPolicy: WhenEmptyOrUnderutilized, consolidateAfter: 5m}
""",
    "envoy-fips-tls": """apiVersion: gateway.envoyproxy.io/v1alpha1
kind: ClientTrafficPolicy
metadata: {name: cloudseed-fips-tls, namespace: cloudseed}
spec:
  targetRefs: [{group: gateway.networking.k8s.io, kind: Gateway, name: cloudseed}]
  tls:
    minVersion: "1.2"
    maxVersion: "1.3"
    ciphers: [ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256]
    ecdhCurves: [P-256, P-384]
""",
    "chaos-dashboard-admin": """apiVersion: v1
kind: ServiceAccount
metadata: {name: cloudseed-chaos-admin, namespace: chaos-mesh}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: cloudseed-chaos-manager}
rules:
  - apiGroups: [""]
    resources: [pods, namespaces, events]
    verbs: [get, list, watch]
  - apiGroups: [chaos-mesh.org]
    resources: ["*"]
    verbs: [get, list, watch, create, delete, patch, update]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: cloudseed-chaos-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cloudseed-chaos-manager}
subjects: [{kind: ServiceAccount, name: cloudseed-chaos-admin, namespace: chaos-mesh}]
""",
    "metallb-pool": """apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata: {name: cloudseed, namespace: metallb-system}
spec:
  addresses: ["{lb_range}"]
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata: {name: cloudseed, namespace: metallb-system}
""",
    # Grafana (kube-prometheus-stack's datasource sidecar watches this label in `monitoring`): Loki, never the default one -
    # Prometheus is, and Grafana refuses to start with two defaults
    "loki-datasource": """apiVersion: v1
kind: ConfigMap
metadata:
  name: loki-datasource
  namespace: monitoring
  labels:
    grafana_datasource: "1"
data:
  loki-datasource.yaml: |
    apiVersion: 1
    datasources:
      - name: Loki
        type: loki
        uid: loki
        access: proxy
        url: http://loki.monitoring.svc:3100
        isDefault: false
""",
    # Alloy pipeline: every pod's logs through the Kubernetes API (no host mounts), sharded across the clustered DaemonSet
    "alloy-logs-config": """apiVersion: v1
kind: Namespace
metadata: {name: monitoring}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: alloy-logs-config
  namespace: monitoring
data:
  config.alloy: |
    discovery.kubernetes "pods" {
      role = "pod"
    }

    discovery.relabel "pods" {
      targets = discovery.kubernetes.pods.targets

      rule {
        source_labels = ["__meta_kubernetes_namespace"]
        target_label  = "namespace"
      }
      rule {
        source_labels = ["__meta_kubernetes_pod_name"]
        target_label  = "pod"
      }
      rule {
        source_labels = ["__meta_kubernetes_pod_container_name"]
        target_label  = "container"
      }
      rule {
        source_labels = ["__meta_kubernetes_namespace", "__meta_kubernetes_pod_container_name"]
        separator     = "/"
        target_label  = "job"
      }
      rule {
        source_labels = ["__meta_kubernetes_pod_label_app_kubernetes_io_name"]
        target_label  = "app"
      }
      rule {
        source_labels = ["__meta_kubernetes_pod_node_name"]
        target_label  = "node"
      }
    }

    loki.source.kubernetes "pods" {
      targets    = discovery.relabel.pods.output
      forward_to = [loki.write.default.receiver]

      clustering {
        enabled = true
      }
    }

    loki.write "default" {
      endpoint {
        url = "http://loki.monitoring.svc:3100/loki/api/v1/push"
      }
    }
""",
    # Polaris catalog database (CloudNativePG creates Secret polaris-db-app with username/password/jdbc-uri) and the root
    # credentials the bootstrap init container registers (realm POLARIS, client id root)
    "polaris-db": """apiVersion: v1
kind: Namespace
metadata: {name: polaris}
---
apiVersion: v1
kind: Secret
metadata:
  name: polaris-root
  namespace: polaris
type: Opaque
stringData:
  credentials: "POLARIS,root,{polaris_password}"
---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: polaris-db
  namespace: polaris
spec:
  instances: 1
  storage:
    size: 5Gi
  bootstrap:
    initdb:
      database: polaris
      owner: polaris
""",
    # Artifactory master/join keys (hex, generated once per env) - read by the chart from this Secret
    "artifactory-keys": """apiVersion: v1
kind: Namespace
metadata: {name: artifactory}
---
apiVersion: v1
kind: Secret
metadata:
  name: artifactory-mandatory-keys
  namespace: artifactory
type: Opaque
stringData:
  master-key: "{artifactory_master_key}"
  join-key: "{artifactory_join_key}"
""",
    # Nexus admin password (the chart reads it from rootPassword.secret on first start)
    "nexus-root-password": """apiVersion: v1
kind: Namespace
metadata: {name: nexus}
---
apiVersion: v1
kind: Secret
metadata:
  name: nexus-root-password
  namespace: nexus
type: Opaque
stringData:
  password: "{nexus_password}"
""",
}


# UIs cloudseed knows how to expose: item -> (namespace, service, port, scheme, credential hint)
UIS = {
    "argocd": ("argocd", "argocd-server", 80, "http", "admin / kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"),
    "kube-prometheus-stack": ("monitoring", "monitoring-grafana", 80, "http", "admin / grafana_password (platform/secrets.json)"),
    "opencost": ("opencost", "opencost", 9090, "http", ""),
    "minio": ("minio", "minio-console", 9001, "http", "minio_root_user / minio_password (platform/secrets.json; admin when "
                                                      "minio_root_user is not there: an install from before cloudseed generated it)"),
    "airflow": ("airflow", "airflow-api-server", 8080, "http", "admin / airflow_password (platform/secrets.json)"),
    "jupyterhub": ("jupyterhub", "proxy-public", 80, "http", "any user / jupyter_password (platform/secrets.json)"),
    "mlflow": ("mlflow", "mlflow", 80, "http", ""),                         # chart 1.x Service port (targetPort 5000)
    "kubeflow-pipelines": ("kubeflow", "ml-pipeline-ui", 80, "http", ""),
    "spark-history-server": ("spark-operator", "spark-history-server", 18080, "http", ""),
    "kiali": ("istio-system", "kiali", 20001, "http", "anonymous"),
    "langfuse": ("langfuse", "langfuse-web", 3000, "http", "sign up on first visit"),
    "open-webui": ("open-webui", "open-webui", 80, "http", "sign up on first visit"),
    "neuvector": ("neuvector", "neuvector-service-webui", 8443, "http", "admin / admin (change it)"),   # manager.env.ssl=false
    "harbor": ("harbor", "harbor", 80, "http", "admin / harbor_password (platform/secrets.json)"),
    "artifactory": ("artifactory", "artifactory", 8082, "http", "admin / artifactory_password (platform/secrets.json)"),   # router, serves /ui
    "nexus": ("nexus", "nexus-nexus3", 8081, "http", "admin / nexus_password (platform/secrets.json)"),
    "sonarqube": ("sonarqube", "sonarqube-sonarqube", 9000, "http", "admin / admin (change it)"),
    "kubecost-cost-analyzer": ("kubecost", "kubecost-cost-analyzer", 9090, "http", ""),
    "trino": ("trino", "trino", 8080, "http", "any user, no password"),
    "gitlab": ("gitlab", "gitlab-webservice-default", 8181, "http", "root / kubectl -n gitlab get secret gitlab-gitlab-initial-root-password -o jsonpath='{.data.password}' | base64 -d"),
    "kagent": ("kagent", "kagent-ui", 8080, "http", "admin / kagent_password (platform/secrets.json)"),   # login added by cloudseed
    "chaos-mesh": ("chaos-mesh", "chaos-dashboard", 2333, "http", "token: cs kubectl create token cloudseed-chaos-admin -n chaos-mesh --duration=24h"),
    "litmus": ("litmus", "litmus-frontend-service", 9091, "http", "admin / litmus (change it)"),
    "falco": ("falco", "falco-falcosidekick-ui", 2802, "http", "admin / falco_ui_password (platform/secrets.json)"),
}

# UIs with no login of their own whose backend is too powerful to publish without one (kagent's tool server holds
# cluster-admin): the route gets HTTP basic auth (an Envoy Gateway SecurityPolicy, or ingress-nginx's auth annotations)
# with a generated password. item -> its secrets.json key.
UI_BASIC_AUTH = {"kagent": "kagent_password"}

# UIs whose chart publishes its own Ingress for the same host: in Ingress mode cloudseed's would be refused as a duplicate
# (GitLab's gitlab-webservice-default owns gitlab.<domain>), so it is listed but not created.
UI_OWN_INGRESS = {"gitlab"}

INGRESS_TEMPLATE = """apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cloudseed-{name}
  namespace: {ns}
  annotations:
    cert-manager.io/cluster-issuer: cloudseed-ca
    nginx.ingress.kubernetes.io/backend-protocol: "{backend}"
    nginx.ingress.kubernetes.io/proxy-body-size: "0"{auth}
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["{host}"]
      secretName: cloudseed-{name}-tls
  rules:
    - host: "{host}"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {{service: {{name: {svc}, port: {{number: {port}}}}}}}
"""


# UI routes attach to the HTTPS listener only; a second route on the HTTP listener redirects the same host to https,
# so logins never travel in clear text even though the shared Gateway also listens on :80 for apps.
HTTPROUTE_TEMPLATE = """apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: cloudseed-{name}
  namespace: {ns}
spec:
  parentRefs: [{{name: cloudseed, namespace: cloudseed, sectionName: https}}]
  hostnames: ["{host}"]
  rules:
    - backendRefs: [{{name: {svc}, port: {port}}}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: cloudseed-{name}-redirect
  namespace: {ns}
spec:
  parentRefs: [{{name: cloudseed, namespace: cloudseed, sectionName: http}}]
  hostnames: ["{host}"]
  rules:
    - filters: [{{type: RequestRedirect, requestRedirect: {{scheme: https, statusCode: 301}}}}]
"""
# basic auth in front of a UI (UI_BASIC_AUTH): one Secret serves both routings (.htpasswd for Envoy Gateway, auth for
# ingress-nginx); Envoy accepts only SHA-1 htpasswd entries ({SHA}), which is fine for a random 24-character password
BASIC_AUTH_SECRET_TEMPLATE = """apiVersion: v1
kind: Secret
metadata: {{name: cloudseed-{name}-basic-auth, namespace: {ns}}}
type: Opaque
stringData:
  .htpasswd: "{htpasswd}"
  auth: "{htpasswd}"
"""
SECURITY_POLICY_TEMPLATE = """apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata: {{name: cloudseed-{name}, namespace: {ns}}}
spec:
  targetRefs: [{{group: gateway.networking.k8s.io, kind: HTTPRoute, name: cloudseed-{name}}}]
  basicAuth:
    users: {{name: cloudseed-{name}-basic-auth}}
"""
INGRESS_AUTH_ANNOTATIONS = ("\n    nginx.ingress.kubernetes.io/auth-type: basic"
                            "\n    nginx.ingress.kubernetes.io/auth-secret: cloudseed-{name}-basic-auth"
                            '\n    nginx.ingress.kubernetes.io/auth-realm: "cloudseed {name}"')
BACKEND_TLS_TEMPLATE = """apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: cloudseed-{name}
  namespace: {ns}
spec:
  targetRefs: [{{group: "", kind: Service, name: {svc}}}]
  validation:
    wellKnownCACertificates: System
    hostname: {svc}
"""


def gateway_present(ctx: "Cluster") -> bool:
    kubectl = deps.find("kubectl")
    return subprocess.run([kubectl, "get", "gateway", "cloudseed", "-n", "cloudseed"], env=ctx.procenv(), capture_output=True).returncode == 0


def _consent(question: str, auto_approve: bool) -> None:
    """Same contract as the CLI's approval: --auto-approve proceeds, a terminal asks, anything else stops with the flag to use."""
    if auto_approve:
        return
    if not ui.interactive():
        raise ui.Abort("Nothing installed. Re-run with --auto-approve to install it without a prompt.", code=3)
    if not ui.confirm(question, default=False):
        raise ui.Abort("Cancelled. Nothing was changed.", code=0)


def expose_uis(ctx: "Cluster", auto_approve: bool = False, installed: list[str] | None = None) -> list[tuple[str, str, str]]:
    """Expose every installed UI at https://<item>.<domain>: HTTPRoutes on the shared Gateway (default) or legacy Ingress
    when only ingress-nginx is present. TLS from the cluster CA. Returns (item, url, credentials).

    When the routing stack is missing it is installed only after approval (the plan is shown first); the items installed
    that way are appended to `installed` so the caller can record them for undo."""
    ensure_tools()
    kubectl = deps.find("kubectl")
    releases = _releases_or_abort(ctx)
    domain = ctx.placeholders()["platform_domain"]
    candidates = []
    for item, (ns, svc, port, scheme, cred) in UIS.items():
        spec = CATALOG.get(item)
        if not spec:
            continue
        known = _release_state(spec, item, releases) is not None   # every non-helm item has a probe
        if known:
            candidates.append((item, known, ns, svc, port, scheme, cred))
    if not candidates:
        ui.info("None of the items with a web UI is installed yet (they are marked in `cs platform list`); nothing to expose.")
        return []
    have_gateway = gateway_present(ctx)
    use_gateway = have_gateway or not _already_installed(CATALOG["ingress-nginx"], "ingress-nginx", releases)
    stack = []
    if use_gateway and not have_gateway:
        stack = ["envoy-gateway"]
    elif not use_gateway and not _already_installed(CATALOG["cert-manager-issuer"], "cert-manager-issuer", releases):
        stack = ["cert-manager-issuer"]   # install() resolves cert-manager (+ Gateway API CRDs) when they are missing
    if stack:
        entries = plan(stack, ctx, releases)
        blocked = [e for e in entries if e["action"] == "blocked-pending"]
        if blocked:
            raise ui.Abort("Cannot expose the UIs yet. " + " ".join(f"{e['item']}: {e['reasons'][0]}" for e in blocked))
        needed = [e["item"] for e in entries if e["action"] == "install"]
        if needed:
            ui.info("Exposing UIs needs " + ("the Gateway API stack" if stack == ["envoy-gateway"] else "the cluster CA issuer")
                    + ": " + ", ".join(needed))
            _consent(f"Install {', '.join(needed)} on {ctx.env.id}?", auto_approve)
            ctx.done = []
            try:
                install(stack, ctx, wait=True, summary=False)
            finally:                      # also what completed before a failure, so it can be undone
                if installed is not None:
                    installed.extend(ctx.done)
        if use_gateway and not gateway_present(ctx):
            # envoy-gateway is installed but its shared Gateway is missing (an earlier post-manifest failure): re-create it
            eg = CATALOG["envoy-gateway"]
            ui.info("envoy-gateway is installed but the shared Gateway cloudseed/cloudseed is missing: re-creating it")
            for post in _posts_of(eg, ctx):
                _apply_manifest(ctx, kubectl, post, eg["ns"], wait_ns=True)
    if use_gateway:
        _drop_stale_backend_tls(ctx, kubectl)
    done_uis = []
    for item, known, ns, svc, port, scheme, cred in candidates:
        exists = subprocess.run([kubectl, "get", "svc", svc, "-n", ns], env=ctx.procenv(), capture_output=True).returncode == 0
        if not exists:
            if known:
                ui.warn(f"{item}: installed, but Service {ns}/{svc} was not found - not exposed")
            continue
        host = f"{item}.{domain}"
        if not use_gateway and item in UI_OWN_INGRESS:
            done_uis.append((item, f"https://{host}", cred + ("  " if cred else "") + "(served by its own Ingress)"))
            continue
        auth = ""
        if item in UI_BASIC_AUTH:
            auth = BASIC_AUTH_SECRET_TEMPLATE.format(name=item, ns=ns, htpasswd=_htpasswd("admin", ctx.secret(UI_BASIC_AUTH[item])))
        if use_gateway:
            manifest = HTTPROUTE_TEMPLATE.format(name=item, ns=ns, host=host, svc=svc, port=port)
            if scheme == "https":
                manifest += "---\n" + BACKEND_TLS_TEMPLATE.format(name=item, ns=ns, svc=svc)
            if auth:
                manifest += "---\n" + auth + "---\n" + SECURITY_POLICY_TEMPLATE.format(name=item, ns=ns)
            path = ctx.workdir / f"httproute-{item}.yaml"
        else:
            manifest = INGRESS_TEMPLATE.format(name=item, ns=ns, host=host, svc=svc, port=port, backend=scheme.upper(),
                                               auth=INGRESS_AUTH_ANNOTATIONS.format(name=item) if auth else "")
            if auth:
                manifest = auth + "---\n" + manifest
            path = ctx.workdir / f"ingress-{item}.yaml"
        _write_private(path, manifest)      # a basic-auth route carries a password hash
        if _run([kubectl, "apply", "-f", str(path)], ctx, check=False) != 0:
            ui.warn(f"{item}: could not apply {path.name} (see above) - not exposed")
            continue
        done_uis.append((item, f"https://{host}", cred))
    return done_uis


def _htpasswd(user: str, password: str) -> str:
    """An htpasswd line in the {SHA} scheme - the one format Envoy's basic auth reads (ingress-nginx reads it too)."""
    import base64
    import hashlib
    return f"{user}:{{SHA}}" + base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()


_BACKEND_TLS = "backendtlspolicies.gateway.networking.k8s.io"


def _drop_stale_backend_tls(ctx: "Cluster", kubectl: str) -> list[str]:
    """Delete the BackendTLSPolicy an earlier `cs platform ui` made for a UI that is now served over plain HTTP behind
    the Gateway (NeuVector moved to http): left in place, Envoy keeps speaking TLS to an HTTP backend and the UI stays
    broken. Only cloudseed's own policies (cloudseed-<item> in the item's namespace) are touched. Returns the items."""
    proc = subprocess.run([kubectl, "get", _BACKEND_TLS, "-A", "--ignore-not-found", "-o",
                           'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{"\\n"}{end}'],
                          env=ctx.procenv(), capture_output=True, text=True)
    dropped = []
    for line in proc.stdout.split() if proc.returncode == 0 else []:   # no such kind (older CRDs): nothing to drop
        ns, _, name = line.partition("/")
        item = name[len("cloudseed-"):] if name.startswith("cloudseed-") else ""
        spec = UIS.get(item)
        if not spec or spec[0] != ns or spec[3] != "http":
            continue
        if _run([kubectl, "-n", ns, "delete", _BACKEND_TLS, name, "--ignore-not-found", "--timeout=60s"], ctx, check=False) == 0:
            ui.info(f"{item}: removed its old BackendTLSPolicy {ns}/{name} (the UI is now plain HTTP behind the Gateway, which terminates TLS)")
            dropped.append(item)
    return dropped


def ingress_address(ctx: "Cluster") -> str:
    """Address of the shared Gateway (preferred) or the legacy ingress controller."""
    kubectl = deps.find("kubectl")
    out = subprocess.run([kubectl, "-n", "cloudseed", "get", "gateway", "cloudseed", "-o", "jsonpath={.status.addresses[0].value}"],
                         env=ctx.procenv(), capture_output=True, text=True).stdout.strip()
    if out:
        return out
    for jp in ("{.status.loadBalancer.ingress[0].ip}", "{.status.loadBalancer.ingress[0].hostname}"):
        out = subprocess.run([kubectl, "-n", "ingress-nginx", "get", "svc", "ingress-nginx-controller", "-o", f"jsonpath={jp}"],
                             env=ctx.procenv(), capture_output=True, text=True).stdout.strip()
        if out:
            return out
    return ""


# Step-over rules. `conflicts`: same role, cannot coexist sanely -> the later one is skipped (--force overrides).
# `overlaps`: both can run but duplicate a capability -> warn. `when_installed`: values applied when a sibling item is
# installed or in the same batch, to disable bundled copies and wire the shared one instead.
# components some distros ship out of the box -> skipped with a reason instead of installed twice
PROVIDED_BY_DISTRO = {
    "metrics-server": ["rke2", "gke", "aks"],
    "cluster-autoscaler": ["gke", "aks"],     # node pools are created with autoscaling min/max by cloudseed's stack
    # RKE2's bundled ingress (nginx / Traefik) is disabled by cloudseed's rke2 role: it would fight the platform's
    # Gateway API implementation over the CRDs. Ingress on RKE2 is the ordinary ingress-nginx item.
}

RULES: dict[str, dict] = {
    "kubecost-cost-analyzer": {"conflicts": ["opencost"],
                               "when_installed": {"kube-prometheus-stack": {"prometheus.enabled": "false", "grafana.enabled": "false",
                                                                            "global.prometheus.enabled": "false",
                                                                            "global.prometheus.fqdn": "http://monitoring-kube-prometheus-prometheus.monitoring.svc:9090",
                                                                            "global.grafana.enabled": "false"}}},
    "opencost": {"conflicts": ["kubecost-cost-analyzer"]},
    "ingress-nginx": {"overlaps": ["envoy-gateway"]},
    "envoy-gateway": {"overlaps": ["ingress-nginx", "istio-gateway"]},
    "istio-gateway": {"overlaps": ["envoy-gateway"]},
    "agentgateway": {"overlaps": ["envoy-gateway"]},
    "falco": {"overlaps": ["neuvector"]},
    "neuvector": {"overlaps": ["falco"]},
    "vault": {"overlaps": ["external-secrets", "sealed-secrets"]},
    "kiali": {"when_installed": {"kube-prometheus-stack": {"external_services.prometheus.url": "http://monitoring-kube-prometheus-prometheus.monitoring.svc:9090",
                                                           "external_services.grafana.enabled": "true",
                                                           "external_services.grafana.internal_url": "http://monitoring-grafana.monitoring.svc:80"}}},
    "gitlab": {"when_installed": {"cert-manager": {"installCertmanager": "false"}, "kube-prometheus-stack": {"prometheus.install": "false"}}},
    # Harbor's Trivy adapter scans images pushed to the registry; trivy-operator scans running workloads: both stay on
    "harbor": {"overlaps": ["artifactory", "nexus"]},
    "artifactory": {"overlaps": ["harbor", "nexus"]},
    "nexus": {"overlaps": ["harbor", "artifactory"]},
    "kubeflow-pipelines": {"overlaps": ["minio"]},
    # Open WebUI talks to the shared Ollama instead of deploying its own copy next to it
    "open-webui": {"when_installed": {"ollama": {"ollama.enabled": "false", "ollamaUrls[0]": "http://ollama.ollama.svc.cluster.local:11434"}}},
    # kagent bundles an older kmcp controller: with the standalone kmcp item only one controller may reconcile MCPServers
    "kagent": {"when_installed": {"kmcp": {"kmcp.enabled": "false"}}},
    "trivy-operator": {"overlaps": ["neuvector"]},
    "kyverno-policies": {"conflicts": []},
    "litmus": {"overlaps": ["chaos-mesh"]},
    "chaos-mesh": {"overlaps": ["litmus"]},
    "kubescape-operator": {"overlaps": ["trivy-operator"]},
    # both react to the same pending pods (the managed node group's ASG vs Karpenter's default NodePool): racing scale-ups,
    # then consolidation churn. Legitimate while migrating, or with the autoscaler kept for a tainted system group.
    "cluster-autoscaler": {"overlaps": ["karpenter"]},
    "karpenter": {"overlaps": ["cluster-autoscaler"]},
}


class ClusterUnreachable(ui.Abort):
    """`helm list` failed: the cluster is down, unreachable from here, or its credentials do not work. Never read this as
    'nothing is installed' - callers either stop (status/plan/install/uninstall) or say the state is unknown. An Abort,
    so a caller that does not catch it (the CLI's install/uninstall journaling, undo) stops with this message and the
    hint instead of an 'Unexpected error' traceback."""


def _releases_or_abort(ctx: "Cluster") -> dict:
    try:
        return installed_releases(ctx)
    except ClusterUnreachable as e:
        raise ui.Abort(str(e))


def _unknown(name: str) -> ui.Abort:
    """The error for a name that is neither a group nor an item, with a did-you-mean (the CLI checks names up front the
    same way; this covers direct callers such as the web console, undo and chaos)."""
    import difflib
    pool = list(GROUPS) + [k for k, v in CATALOG.items() if not v.get("hidden")]
    near = difflib.get_close_matches(str(name), pool, n=3, cutoff=0.7)
    return ui.Abort(f"Unknown platform group or item '{name}'" + (f" - did you mean {' or '.join(near)}?" if near else ".")
                    + "  See: cs platform list")


def _expand(names: list[str]) -> list[str]:
    """Groups -> their core members plus the shared members they bring (GROUP_EXTRA_MEMBERS); items as named."""
    wanted: list[str] = []
    for n in names:
        if n in GROUPS:
            wanted += [k for k, v in CATALOG.items() if v["group"] == n and not v.get("hidden") and v.get("tier", "core") == "core"]
            wanted += GROUP_EXTRA_MEMBERS.get(n, [])
        elif n in CATALOG:
            wanted.append(n)
        else:
            raise _unknown(n)
    return wanted


def _direct_deps(item: str, ctx: "Cluster", all_modes: bool = False) -> list[str]:
    """What an item needs on this target: `needs`, `needs_by_target` and, for a meta item, its members (the chosen
    mode's, or every mode's when asking 'could this item be using X')."""
    spec = CATALOG[item]
    out = list(spec.get("needs", [])) + list((spec.get("needs_by_target") or {}).get(ctx.target, []))
    if spec["method"] == "meta":
        modes = spec["modes"]
        out += [m for mode in modes.values() for m in mode] if all_modes else modes[ctx.mode(item)]
    return list(dict.fromkeys(out))     # once each (every mode lists istio-base/istiod)


def missing_input(item: str) -> str:
    """Why an item cannot work yet: none of the credentials its catalog entry `requires` is set ('' when it can install)."""
    req = CATALOG[item].get("requires") or {}
    names = req.get("any_env") or []
    if not names or any(os.environ.get(n) for n in names):
        return ""
    return f"needs {' or '.join(names)}: {req.get('hint') or 'set it with cs creds set'}"


def _installed_mode(item: str, ctx: "Cluster", releases: dict) -> str | None:
    """The mode a meta item (istio) runs in on this cluster: the mode whose own members (those no other mode has) have a
    release in any state - a failed ztunnel still means ambient; with only the shared members there, the one istiod was
    installed for (its `profile` value), else the smallest mode. None when none of its members is there."""
    modes = CATALOG[item].get("modes") or {}
    if not modes:
        return None
    shared = set.intersection(*[set(m) for m in modes.values()])

    def there(n: str) -> bool:
        return _release_state(CATALOG[n], n, releases) is not None
    for mode, members in sorted(modes.items(), key=lambda kv: -len(kv[1])):
        if any(there(m) for m in members if m not in shared):
            return mode
    if not any(there(m) for m in shared):
        return None
    profile = _release_values(ctx, "istiod", CATALOG["istiod"]).get("profile") if "istiod" in shared else None
    return profile if profile in modes else min(modes, key=lambda m: len(modes[m]))


def _release_values(ctx: "Cluster", item: str, spec: dict) -> dict:
    """The user-supplied values of an item's release ({} when they cannot be read)."""
    helm = deps.find("helm")
    if not helm:
        return {}
    try:
        proc = subprocess.run([helm, "get", "values", spec.get("release", item), "-n", spec.get("ns", "default"), "-o", "json"],
                              env=ctx.procenv(), capture_output=True, text=True, timeout=60)
        vals = json.loads(proc.stdout or "null") if proc.returncode == 0 else None
    except (subprocess.TimeoutExpired, OSError, ValueError):
        vals = None
    return vals if isinstance(vals, dict) else {}


def _settle_modes(names: list[str], ctx: "Cluster", releases: dict, force: bool) -> tuple[dict[str, str], set]:
    """Keep meta items in the mode they are installed in: with no --set mode=, the installed mode is used (a sidecar
    mesh must not grow the ambient data plane, nor istiod lose its profile on --upgrade). Moving sidecar -> ambient
    adds members and re-applies the shared ones whose values depend on the mode (istiod's profile=ambient: without it
    istiod serves no ztunnel); ambient -> sidecar would leave ztunnel and istio-cni running under a sidecar istiod, so
    it is refused unless --force. Returns ({item: note} for the plan, the installed members to re-apply)."""
    notes: dict[str, str] = {}
    reapply: set = set()
    for item, spec in CATALOG.items():
        if spec["method"] != "meta":
            continue
        have = _installed_mode(item, ctx, releases)
        chosen = ctx.options.get("mode")
        if not have:
            continue
        if not chosen:                  # (a second plan() of the same run - the CLI plans before it installs - finds it set)
            ctx.options["mode"] = chosen = have
            ctx.mode_detected = True
        if chosen == have:
            if getattr(ctx, "mode_detected", False):
                notes[item] = f"mode: {have} (as installed; --set mode=... changes it)"
        else:
            if item not in resolve(names, ctx):
                continue
            modes = spec["modes"]
            if set(modes[chosen]) >= set(modes[have]):
                redo = [m for m in modes[chosen] if m in modes[have] and chosen in (CATALOG[m].get("values") or {})]
                reapply.update(redo)
                notes[item] = (f"mode: {have} -> {chosen} (adds {', '.join(m for m in modes[chosen] if m not in modes[have])}"
                               + (f"; re-applies {', '.join(redo)} for {chosen}" if redo else "") + ")")
            elif not force:
                raise ui.Abort(f"{item} runs in {have} mode here; --set mode={chosen} would leave "
                               f"{', '.join(m for m in modes[have] if m not in modes[chosen])} running. Remove it first "
                               f"(cs platform uninstall {item}, then cs platform install {item} --set mode={chosen}) or pass --force.")
            else:
                notes[item] = f"mode: {have} -> {chosen} (--force: {', '.join(m for m in modes[have] if m not in modes[chosen])} keep running)"
    return notes, reapply


def plan(names: list[str], ctx: "Cluster", releases: dict | None = None, force: bool = False) -> list[dict]:
    """Resolve names into an ordered plan with a decision per item: install | skip-installed | skip-provided |
    skip-conflict | skip-fips | skip-arch | skip-missing-input | skip-unneeded | skip-target | blocked-pending."""
    releases = _releases_or_abort(ctx) if releases is None else releases
    wanted = set(_expand(names))
    mode_notes, reapply = _settle_modes(names, ctx, releases, force)
    items = resolve(names, ctx)
    # an item named explicitly that does not run on this target says so (groups leave such members out quietly)
    off_target = [n for n in dict.fromkeys(names) if n not in GROUPS and CATALOG[n].get("only") and ctx.target not in CATALOG[n]["only"]]
    states = {n: _release_state(sp, n, releases) for n, sp in CATALOG.items()}
    installed_names = {n for n, s in states.items() if s in ("deployed", "present")}
    # amd64-only items on a cluster whose nodes are all arm64 (Apple silicon VMware guests, Graviton): nothing could run
    # them, unless Karpenter (whose default NodePool allows amd64) is there to add an amd64 node
    archs = ctx.node_archs() if any(CATALOG[i].get("arch") for i in items) else set()
    provisions = "karpenter" in installed_names or "karpenter" in items
    # pass 1: decide install / skip (conflicts are judged against what is installed or earlier in the batch)
    batch: set[str] = set()
    out: list[dict] = []
    for item in items:
        rule = RULES.get(item, {})
        entry = {"item": item, "action": "install", "reasons": [], "sets": {}}
        state = states.get(item)
        if ctx.distro in PROVIDED_BY_DISTRO.get(item, []):
            entry["action"] = "skip-provided"
            entry["reasons"].append(f"already provided by {ctx.distro} out of the box")
        elif state == "pending":
            entry["action"] = "blocked-pending"
            entry["reasons"].append(_pending_remedy(CATALOG[item], item, releases))
        elif not ctx.upgrade and item in installed_names and item not in reapply:
            entry["action"] = "skip-installed"
            if _legacy_minio_user(item, ctx):
                entry["reasons"].append(f"its MinIO access key is still the well-known '{MINIO_USERS[item][1]}' of an older "
                                        f"install: rotate it with cs platform install {item} --upgrade")
        elif ctx.fips and not CATALOG[item].get("fips") and not force:
            entry["action"] = "skip-fips"
            entry["reasons"].append("FIPS environment: this item's images ship their own crypto and are not known to be FIPS-validated; --force installs it anyway (cs scan fips will flag it)")
        elif CATALOG[item].get("arch") and archs and not archs & set(CATALOG[item]["arch"]) and not provisions and not force:
            entry["action"] = "skip-arch"
            entry["reasons"].append(f"needs {'/'.join(CATALOG[item]['arch'])} nodes (some of its images are published for "
                                    f"{'/'.join(CATALOG[item]['arch'])} only) and this cluster's nodes are {'/'.join(sorted(archs))}; "
                                    "--force installs it anyway (those pods would not start)")
        elif missing_input(item) and not force:
            entry["action"] = "skip-missing-input"
            entry["reasons"].append(missing_input(item))
        elif item == "metallb" and ctx.target == "vmware" and ctx.lb_pool()[1] and not force:
            entry["action"] = "skip-conflict"   # its pool would hand out the address of a VM or a DHCP lease
            entry["reasons"].append(ctx.lb_pool()[1])
        else:
            hit = [c for c in rule.get("conflicts", []) if c in installed_names or c in batch]
            if hit and not force:
                entry["action"] = "skip-conflict"
                entry["reasons"].append(f"conflicts with {', '.join(hit)} (same role); use --force to install anyway")
        if entry["action"] == "install":
            if state == "failed":
                entry["reasons"].append("its last release attempt failed: it is retried (helm upgrade --install repairs a failed release)")
            elif item in reapply and not ctx.upgrade and state is not None:
                entry["reapply"] = True
                entry["reasons"].append(f"re-applied: its values depend on the mesh mode ({ctx.options.get('mode')})")
            batch.add(item)
            if ctx.fips and CATALOG[item].get("fips") == "tls-restricted":
                entry["reasons"].append("FIPS: user-facing TLS is pinned to 1.2+/FIPS suites, but this proxy's crypto (Envoy BoringSSL / OpenSSL) "
                                        "is not a FIPS-validated module; swap in a FIPS build of the proxy image for strict compliance")
            elif ctx.fips and CATALOG[item].get("fips") == "crypto-restricted":
                entry["reasons"].append("FIPS: it generates keys / encrypts with its upstream crypto, which is not a FIPS-validated module; "
                                        "use a FIPS build of its image for strict compliance (cs scan fips flags it)")
            if ctx.upgrade and state is not None and CATALOG[item].get("upgrade_crds"):
                entry["reasons"].append("its CRDs are re-applied first (helm never upgrades a chart's crds/)")
            if state is not None and _legacy_minio_user(item, ctx):
                key, legacy, _ = MINIO_USERS[item]
                entry["reasons"].append(f"re-applying rotates its well-known MinIO access key '{legacy}' (an older install's) "
                                        f"to a generated one ({key} in platform/secrets.json)")
            if item == "metallb" and ctx.target == "vmware" and ctx.lb_pool()[2]:
                entry["reasons"].append("MetalLB: " + ctx.lb_pool()[2])
            psa = pod_security_labels(item, ctx)
            if psa:
                entry["reasons"].append("RKE2 CIS profile (restricted Pod Security): its pods need namespace "
                                        + ", ".join(f"{ns} at {lv}" for ns, lv in psa) + " - labelled first")
            for pre in CATALOG[item].get("cloud_prereqs", []) if ctx.target != "vmware" else []:
                if pre not in (ctx.cfg.get("platform_prereqs") or []) or not _prereq_outputs_present(pre, ctx):
                    entry.setdefault("cloud_prereqs", []).append(pre)
                    entry["reasons"].append(f"cloud prerequisites '{pre}' (identity, storage, tags) are applied to the {ctx.target} stack first")
        out.append(entry)
    _prune(out, wanted, ctx, batch)
    # pass 2: overlaps and sibling-aware values against everything that will exist after this run
    present = installed_names | {n for n, s in states.items() if s == "failed"} | batch
    for entry in out:
        if entry["action"] != "install":
            continue
        rule = RULES.get(entry["item"], {})
        for o in rule.get("overlaps", []):
            if o in present:
                entry["reasons"].append(f"overlaps with {o} - both will run; make sure that is intended")
        for sibling, sets in rule.get("when_installed", {}).items():
            if sibling in present:
                entry["sets"].update(sets)
                if sets:
                    entry["reasons"].append(f"{sibling} present: bundled copies disabled, shared one wired in")
    for entry in out:
        if entry["item"] in mode_notes:
            entry["reasons"].insert(0, mode_notes[entry["item"]])
    for n in off_target:
        out.append({"item": n, "action": "skip-target", "reasons": [f"{'/'.join(CATALOG[n]['only'])} only - not used on {ctx.target}"], "sets": {}})
    return out


def _legacy_minio_user(item: str, ctx: "Cluster") -> bool:
    """The item uses a MinIO access key (minio's root, velero's on a local cluster, spark-history-server's) and it is
    still the well-known one an older version created (no generated one is stored for the environment)."""
    if item not in MINIO_USERS or (item == "velero" and "velero-minio-credentials" not in _pres_of(CATALOG[item], ctx)):
        return False
    try:
        return ctx.minio_user_is_legacy(item)
    except AttributeError:   # a stand-in context without the environment's secrets
        return False


def _prune(out: list[dict], wanted: set, ctx: "Cluster", batch: set) -> None:
    """Dependencies exist for their dependents: when every dependent in this run is skipped (conflict, FIPS), the
    dependency is not installed either; and an item whose dependency is skipped cannot work, so it is skipped too.
    Repeats until stable (a skipped envoy-gateway frees cert-manager, the issuer, gateway-api and metallb)."""
    by = {e["item"]: e for e in out}
    needs = {i: [d for d in _direct_deps(i, ctx) if d in by and d != i] for i in by}
    dependents: dict[str, list[str]] = {}
    for i, ds in needs.items():
        for d in ds:
            dependents.setdefault(d, []).append(i)

    def drop(e: dict, action: str, reason: str) -> None:
        e["action"] = action
        e["reasons"] = [r for r in e["reasons"] if not r.startswith(("cloud prerequisites", "its last release attempt failed", "RKE2 CIS profile",
                                                                     "re-applying rotates", "MetalLB: "))] + [reason]
        e.pop("cloud_prereqs", None)
        batch.discard(e["item"])

    changed = True
    while changed:
        changed = False
        for e in out:
            if e["action"] != "install":
                continue
            item = e["item"]
            lost = [d for d in needs[item] if by[d]["action"] in ("skip-conflict", "skip-fips", "skip-arch", "skip-missing-input")]
            if lost:
                d = by[lost[0]]
                drop(e, d["action"], f"needs {d['item']}, which is skipped ({d['reasons'][0] if d['reasons'] else d['action']})")
                changed = True
                continue
            users = dependents.get(item, [])
            if item not in wanted and users and all(by[u]["action"] in _SKIPPED for u in users):
                drop(e, "skip-unneeded", f"only needed by {', '.join(users)}, which {'is' if len(users) == 1 else 'are'} skipped")
                changed = True


_SKIPPED = ("skip-conflict", "skip-fips", "skip-arch", "skip-unneeded", "skip-missing-input", "skip-target")
# skips the user has to act on (a named item that ends up like this installs nothing and says why)
_UNMET = ("skip-conflict", "skip-fips", "skip-arch", "skip-missing-input")

_PLAN_LOOK = {  # action -> (mark, colours, label); single-width marks so panels stay aligned
    "install": ("+", ("leaf", "bold"), "install"),
    "skip-installed": ("✔", ("leaf",), "already installed - skip"),
    "skip-conflict": ("✖", ("rose", "bold"), "skip"),
    "skip-provided": ("✔", ("leaf",), "built into the distro - skip"),
    "skip-fips": ("✖", ("rose", "bold"), "not FIPS-capable - skip"),
    "skip-arch": ("✖", ("rose", "bold"), "no image for these nodes - skip"),
    "skip-unneeded": ("○", ("muted",), "not needed - skip"),
    "blocked-pending": ("▲", ("seed", "bold"), "blocked - release in progress"),
    "skip-missing-input": ("○", ("seed", "bold"), "needs input - skip"),
    "skip-target": ("–", ("muted",), "not for this target - skip"),
}


def _shorten(text: str, n: int) -> str:
    """Cut at a word boundary with an ellipsis (never mid-word)."""
    if len(text) <= n:
        return text
    if n < 2:
        return ""
    cut = text[: n - 1].rsplit(" ", 1)[0].rstrip(" ,;:-(")
    return (cut or text[: n - 1]) + "…"


def print_plan(entries: list[dict], ctx: "Cluster", user_sets: list[str] | None = None, version: str | None = None,
               target: str | None = None) -> None:
    rows: list[str] = []
    table = [e for e in entries if e["action"] != "skip-target"]
    if table:
        nw = max(len(e["item"]) for e in table)
        lw = max(len(_PLAN_LOOK[e["action"]][2]) for e in table)
        avail = ui.width() - 6 - (2 + nw + 1 + lw + 1)
        for e in table:
            mark, colours, label = _PLAN_LOOK[e["action"]]
            desc = _shorten(CATALOG[e["item"]]["desc"], avail) if avail >= 20 else ""
            rows.append(f"{ui.style(mark, *colours)} {ui.style(e['item'].ljust(nw), 'text')} {label.ljust(lw)}" + (f" {ui.dim(desc)}" if desc else ""))
            for r in e["reasons"]:
                rows.append(f"      {ui.style('↳', 'seed')} {r}")
            chart = CATALOG[e["item"]]["method"] in ("helm", "oci")
            # --set/--version go to the one named Helm chart; for anything else target_flag_warnings says they are not used
            mine = bool(target) and e["item"] == target and chart
            if mine and e["action"] == "install":
                if version:
                    rows.append(f"      {ui.dim('--version ' + version)}")
                for s in user_sets or []:
                    rows.append(f"      {ui.dim('--set ' + _redact(s))}")
            if e["action"] == "install" and chart:
                given = {s.split("=", 1)[0] if "=" in s else s[:-1] for s in (user_sets or []) if mine}
                for k, v in user_values(ctx, e["item"]).items():
                    if k not in given:
                        kept = "--set " + _redact(k + "=" + v) + "  (kept from an earlier install; --set " + k + "- drops it)"
                        rows.append("      " + ui.dim(kept))
            for k, v in e["sets"].items():
                rows.append(f"      {ui.dim('--set ' + k + '=' + str(v))}")
    # items named explicitly that do not run here: one line each, outside the columns (long names would widen them)
    for e in entries:
        if e["action"] != "skip-target":
            continue
        mark, colours, _ = _PLAN_LOOK[e["action"]]
        head = f"{ui.style(mark, *colours)} {ui.style(e['item'], 'text')}  "
        room = ui.width() - 6 - ui.vis_len(ui._strip(head))
        if room >= len(e["reasons"][0]):
            rows.append(head + ui.dim(e["reasons"][0]))
        else:
            rows += [head.rstrip(), f"      {ui.style('↳', 'seed')} {e['reasons'][0]}"]
    ui.panel(f"Plan for {ctx.env.id} ({ctx.target}/{ctx.distro})", rows or [ui.dim("nothing to do")])


# ------------------------------------------------------------------------------------------------ engine

# MinIO access keys cloudseed creates, per item that uses one: (key in platform/secrets.json, the well-known name
# older versions used, the prefix of a generated one). A name is generated (<prefix>-<12 hex>, within MinIO's 20
# characters) when the item is installed or re-applied; until then an older install keeps its well-known name - so
# `cs platform install <item> --upgrade` rotates it (the bucket Jobs then remove the old user; see POST_MANIFESTS).
MINIO_USERS = {"minio": ("minio_root_user", "admin", "admin"), "velero": ("minio_velero_user", "velero", "velero"),
               "spark-history-server": ("minio_spark_user", "spark", "spark")}
_MINIO_USER_RE = re.compile(r"^(admin|velero|spark)-[0-9a-f]{12}$")

_KNOWN_SECRETS: set = set()   # values generated or read for this cluster: scrubbed from every echoed/logged line


def _remember_secret(value: str) -> None:
    if value and len(value) >= 6:
        _KNOWN_SECRETS.add(value)
        secrets.register(value)   # every other redact() in this process (audit, logs) hides it too (8+ characters)


def _scrub_known(text: str) -> str:
    for value in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        if value in text:
            text = text.replace(value, secrets.REDACTED)
    return text


def _redact(text: str) -> str:
    """secrets.redact plus the platform's own secret values (generated passwords/passcodes, API keys, runner tokens),
    which carry no recognisable shape (`monitoringPasscode=...`, `mc alias set ... '<password>'`)."""
    if not text:
        return text
    return secrets.redact(_scrub_known(text))


def _write_private(path: Path, text: str) -> None:
    """Rendered manifests carry generated passwords: 0600 like secrets.json."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# VMware's host-only network settings (Fusion on macOS, Workstation on Linux): read to keep the MetalLB pool out of the
# vmnet's DHCP range. Module-level so tests can point it at fixtures.
VMWARE_PREFS = (Path("/Library/Preferences/VMware Fusion"), Path("/etc/vmware"))


def _vmnet_dhcp(vmnet: str | None):
    """(first, last) address of a vmnet's DHCP pool; False when DHCP is off on it; None when it cannot be told."""
    import ipaddress
    if not vmnet or not re.fullmatch(r"vmnet\d+", str(vmnet)):
        return None
    num = str(vmnet)[len("vmnet"):]
    for base in VMWARE_PREFS:
        try:
            answers = (base / "networking").read_text()
        except OSError:
            continue
        flag = re.search(rf"^answer VNET_{num}_DHCP (yes|no)\s*$", answers, re.M)
        if flag and flag.group(1) == "no":
            return False
        for conf in (base / str(vmnet) / "dhcpd.conf", base / str(vmnet) / "dhcpd" / "dhcpd.conf"):
            try:
                m = re.search(r"^\s*range\s+([\d.]+)\s+([\d.]+)\s*;", conf.read_text(), re.M)
            except OSError:
                continue
            if m:
                try:
                    return ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
                except ValueError:
                    return None
    return None


def _planned_top(settings: dict | None) -> int:
    """Highest static host offset the environment's settings plan (bastion .2, workloads .10+, control planes .20+,
    workers .40+ - the vmware address plan), so the pool also clears VMs the stack has not reported yet."""
    v = settings or {}

    def count(key: str, default: int) -> int:
        try:
            return max(int(v.get(key, default)), 0)
        except (TypeError, ValueError):
            return default
    top = 2
    wc = count("workload_count", 0)
    if wc:
        top = max(top, 10 + wc - 1)
    if str(v.get("enable_kubernetes", "")).strip().lower() in ("true", "1", "yes", "on"):
        top = max(top, 20 + max(count("kubernetes_control_planes", 1), 1) - 1)
        wk = count("kubernetes_workers", 2)
        if wk:
            top = max(top, 40 + wk - 1)
    return top


def _lb_range(cidr: str, outputs: dict, target: str, settings: dict | None = None) -> str:
    """Addresses MetalLB may hand out on the private network (vmware only): see _lb_pool."""
    return _lb_pool(cidr, outputs, target, settings)[0]


def _lb_pool(cidr: str, outputs: dict, target: str, settings: dict | None = None) -> tuple[str, str, str]:
    """(range, problem, warning) of MetalLB's address pool on the private network (vmware only). The pool must avoid
    cloudseed's static guest addresses (.1 host adapter, .2 bastion, 10+ workloads, 20+ control planes, 40+ workers: the
    stack's outputs and the counts the settings plan) AND the vmnet's DHCP pool (VMware's host-only vmnet1 serves DHCP
    on the upper half, e.g. .128-.254): an LB VIP leased to another VM means ARP conflicts. The pool sits just below the
    DHCP range (.100-.127 on a /24), as far from the workers (which grow upwards from .40) as it can.
    problem: fewer than 4 free addresses remain above the nodes and outside the DHCP range (range is then the old
    fallback, which collides with them: MetalLB is not installed without --force). warning: the pool lies where workers
    added later take their addresses (a network smaller than /24 keeps no block for it, see clouds/vmware.py)."""
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        legacy = f"{hosts[-56]}-{hosts[-6]}" if len(hosts) > 64 else f"{hosts[-8]}-{hosts[-2]}"
    except (ValueError, IndexError):
        return "10.100.0.100-10.100.0.127", "", ""
    if target != "vmware" or net.version != 4:
        return legacy, "", ""
    base = int(net.network_address)
    top_static = 0
    for key in ("bastion_private_ip", "workload_private_ips", "kubernetes_control_plane_ips", "kubernetes_worker_ips"):
        vals = outputs.get(key)
        for ip in vals if isinstance(vals, list) else [vals] if vals else []:
            try:
                addr = ipaddress.ip_address(str(ip))
            except ValueError:
                continue
            if addr in net:
                top_static = max(top_static, int(addr) - base)
    top_static = max(top_static, _planned_top(settings) if settings else 0)
    top_static = top_static or 63          # no outputs or settings (offline plan): assume the static zone covers .1-.63

    def text(lo: int, hi: int) -> str:
        return f"{ipaddress.ip_address(base + lo)}-{ipaddress.ip_address(base + hi)}"

    legacy_lo, legacy_hi = (int(ipaddress.ip_address(a)) - base for a in legacy.split("-"))
    dhcp = _vmnet_dhcp(outputs.get("private_vmnet") or "vmnet1")
    if dhcp and not (dhcp[0] in net and dhcp[1] in net):
        dhcp = None                         # another network's pool (vmnet1's, read for an offline plan): unknown here
    if dhcp is None and net.num_addresses < 256:
        # unknown on a network smaller than /24: that is a vmnet cloudseed created for the environment, with static
        # addressing (no DHCP) - its VMs use addresses up to the top of it, where "DHCP on the upper half" would be
        dhcp = False
    pool = None
    if dhcp is False:                       # no DHCP on this vmnet: the upper range is free, above the static addresses
        start = max(legacy_lo, top_static + 1)
        if legacy_hi - start + 1 >= 4:
            pool = (start, legacy_hi)
        dhcp_text = ""
    else:
        if dhcp:
            lo_dhcp, hi_dhcp = int(dhcp[0]) - base, int(dhcp[1]) - base
        else:                               # unknown: VMware's convention is DHCP on the upper half
            lo_dhcp, hi_dhcp = net.num_addresses // 2, net.num_addresses - 2
        dhcp_text = f" and outside the vmnet's DHCP range ({text(lo_dhcp, hi_dhcp)})"
        end = lo_dhcp - 1
        start = max(top_static + 1, end - 27, 1)
        if end - start + 1 >= 4:
            pool = (start, end)
        else:
            start, end = max(hi_dhcp + 1, top_static + 1), min(hi_dhcp + 28, net.num_addresses - 2)
            if end - start + 1 >= 4:        # no room below the DHCP pool: above it
                pool = (start, end)
    if pool is None:
        return legacy, (f"no room for MetalLB's LoadBalancer pool on {net}: it needs 4 or more free addresses above the VMs' "
                        f"static addresses (up to {ipaddress.ip_address(base + top_static)}){dhcp_text}. Use a larger "
                        f"network (a /24 keeps .100-.127 for it) or fewer VMs; "
                        f"--force installs it anyway with {legacy}, which can hand out the address of a VM"), ""
    from .clouds import vmware as vmw
    max_host = min(vmw.MAX_STATIC_HOST, net.num_addresses - 2)
    # the last address a worker may take: below the kept block on a /24 or larger network, else the whole static zone
    worker_top = vmw.MAX_STATIC_HOST - vmw.LB_POOL_SIZE if max_host == vmw.MAX_STATIC_HOST else max_host
    warning = ""
    if pool[0] <= worker_top and pool[1] >= vmw.WORKER_BASE:
        warning = (f"its pool {text(*pool)} lies where workers added later take their addresses on {net} "
                   f"({text(vmw.WORKER_BASE, worker_top)}): a worker added after it (cs node add) could get a LoadBalancer "
                   "address. Add the workers first, or use a /24 or larger network (it keeps .100-.127 for MetalLB)")
    return text(*pool), "", warning


class Cluster:
    """Everything needed to talk to one cluster: kubeconfig, context strings, secrets for values."""

    def __init__(self, cloud, env, cfg: dict, outputs: dict, kubeconfig: Path):
        self.cloud, self.env, self.cfg, self.outputs, self.kubeconfig = cloud, env, cfg, outputs, kubeconfig
        self.target = cloud.key
        managed = {"aws": "eks", "gcp": "gke", "azure": "aks"}
        # the stack's output first, then the environment's setting (an offline plan has no outputs yet), then the target's
        # default; managed targets always run their own distro
        self.distro = (outputs.get("kubernetes_distro") or managed.get(cloud.key)
                       or (cfg.get("vars") or {}).get("kubernetes_distro") or "rke2")
        self.contexts = {"default", self.target, self.distro}
        self.options: dict[str, str] = {}   # e.g. {"mode": "sidecar"} from --set on meta items
        self.mode_detected = False          # options["mode"] is the installed mesh mode, not one the user chose
        self.upgrade = False                # re-apply releases that already exist
        self.fips = bool((cfg.get("vars") or {}).get("fips_mode")) or bool(outputs.get("fips_mode"))
        # RKE2's CIS profile: restricted Pod Security in every namespace but kube-system (see POD_SECURITY_LEVELS)
        self.cis_profile = self.distro == "rke2" and str((cfg.get("vars") or {}).get("kubernetes_cis_profile", "")).strip().lower() in ("true", "1", "yes", "on")
        self.last_output = ""               # tail of the last _run() (to tell 'not found' from real failures)
        self.done: list[str] = []           # items install() completed so far (also when a later one fails)
        self.failures: list[str] = []       # items uninstall() could not remove
        self.kept: list[str] = []           # items uninstall() left in place on purpose
        self.saved_objects: dict = {}       # item -> {objects, count}: custom resources a --force uninstall kept for undo
        self._archs: set | None = None      # CPU architectures of the nodes (node_archs)
        self._k8s_version: str | None = None
        self.workdir = env.dir / "platform"
        self.workdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.workdir, 0o700)
        except OSError:
            pass

    def procenv(self) -> dict:
        """Process environment for kubectl/helm (self.env is the paths.Env; this is the os.environ to run tools with)."""
        e = deps.path_env()
        e["KUBECONFIG"] = str(self.kubeconfig)
        e["HELM_CACHE_HOME"] = str(paths.HOME / "helm" / "cache")
        e["HELM_CONFIG_HOME"] = str(paths.HOME / "helm" / "config")
        e["HELM_DATA_HOME"] = str(paths.HOME / "helm" / "data")
        reg = paths.HOME / "helm" / "registry.json"          # cloudseed-owned registry auth (public charts need none)
        reg.parent.mkdir(parents=True, exist_ok=True)
        if not reg.exists():
            reg.write_text("{}\n")
        e["HELM_REGISTRY_CONFIG"] = str(reg)
        # Helm (4.x) also consults Docker's config for OCI registries; the user's one may name a credential helper
        # that is not on PATH (Docker Desktop's "desktop" store). Point it at a cloudseed-owned copy without such helpers.
        dockerdir = paths.HOME / "helm" / "docker"
        dockerdir.mkdir(parents=True, exist_ok=True)
        _docker_config_without_missing_helpers(dockerdir / "config.json", e.get("PATH", ""))
        e["DOCKER_CONFIG"] = str(dockerdir)
        if self.target == "aws" and self.fips:
            # the kubeconfig's `aws eks get-token` (run by kubectl/helm with this environment) signs against STS: in FIPS
            # mode that must be the FIPS endpoint, like every other AWS call of the environment
            e["AWS_USE_FIPS_ENDPOINT"] = "true"
        return e

    def node_archs(self) -> set:
        """CPU architectures of the cluster's nodes: the VMware guests' (from the stack, or the image the environment was
        set up with), else what the nodes report. Empty when it cannot be told (no cluster yet): nothing is skipped then."""
        if self._archs is None:
            archs: set = set()
            if self.target == "vmware":
                arch = self.outputs.get("guest_arch")
                guest = str((self.cfg.get("vars") or {}).get("guest_os_id") or "")
                if not arch and guest:
                    arch = "arm64" if guest.startswith("arm-") else "amd64"
                if arch in ("amd64", "arm64"):
                    archs = {arch}
            kubectl = deps.find("kubectl")
            if not archs and kubectl and Path(self.kubeconfig).exists():
                try:
                    proc = subprocess.run([kubectl, "get", "nodes", "-o", "jsonpath={.items[*].status.nodeInfo.architecture}",
                                           "--request-timeout=20s"], env=self.procenv(), capture_output=True, text=True, timeout=60)
                    archs = set(proc.stdout.split()) if proc.returncode == 0 else set()
                except (subprocess.TimeoutExpired, OSError):
                    archs = set()
            self._archs = archs
        return self._archs

    def kubernetes_version(self) -> str:
        """The control plane's major.minor (e.g. "1.31"), '' when the cluster does not say."""
        if self._k8s_version is None:
            version = ""
            kubectl = deps.find("kubectl")
            if kubectl:
                try:
                    proc = subprocess.run([kubectl, "version", "-o", "json", "--request-timeout=20s"], env=self.procenv(),
                                          capture_output=True, text=True, timeout=60)
                    m = re.match(r"v?(\d+)\.(\d+)", str((json.loads(proc.stdout or "{}").get("serverVersion") or {}).get("gitVersion", "")))
                    version = f"{m.group(1)}.{m.group(2)}" if m else ""
                except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
                    version = ""
            self._k8s_version = version
        return self._k8s_version

    def mode(self, item: str) -> str:
        spec = CATALOG[item]
        chosen = self.options.get("mode") or "ambient"
        return chosen if chosen in spec.get("modes", {}) else next(iter(spec.get("modes", {"ambient": []})))

    def lb_pool(self) -> tuple[str, str, str]:
        """(range, problem, warning) of MetalLB's address pool on this cluster's private network (see _lb_pool)."""
        return _lb_pool(self.cfg.get("network_cidr", "10.100.0.0/24"), self.outputs, self.target, self.cfg.get("vars") or {})

    def secret(self, name: str, hex_bytes: int = 0, prefix: str = "") -> str:
        """Generated once per env, kept 0600 in <workdir>/platform/secrets.json (redacted from logs). hex_bytes > 0 makes a
        hex key of that many random bytes (Artifactory's master/join keys) instead of a URL-safe password; `prefix` makes
        an access key name: <prefix>-<12 hex characters>."""
        data = self._secrets()
        if name not in data:
            import secrets as pysecrets
            data[name] = (f"{prefix}-{pysecrets.token_hex(6)}" if prefix else pysecrets.token_hex(hex_bytes) if hex_bytes
                          else pysecrets.token_urlsafe(18))
            self._save_secrets(data)
        _remember_secret(data[name])
        return data[name]

    def _secrets(self) -> dict:
        try:
            data = json.loads((self.workdir / "secrets.json").read_text())
        except (OSError, ValueError):
            data = {}
        return data if isinstance(data, dict) else {}

    def _save_secrets(self, data: dict) -> None:
        fd = os.open(self.workdir / "secrets.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)

    def minio_user(self, item: str) -> str:
        """The MinIO access key of `item` (minio: the root user; velero, spark-history-server: their own users): the
        stored one, else the well-known name an install from an older version runs with (nothing is generated here -
        see settle_minio_user)."""
        key, legacy, _ = MINIO_USERS[item]
        name = self._secrets().get(key)
        if isinstance(name, str) and name:
            if _MINIO_USER_RE.match(name):
                _remember_secret(name)   # a generated key is kept out of logs like a password
            return name
        return legacy

    def minio_user_is_legacy(self, item: str) -> bool:
        """The item's MinIO access key is still the well-known one of an older version (nothing stored yet)."""
        name = self._secrets().get(MINIO_USERS[item][0])
        return not (isinstance(name, str) and name)

    def settle_minio_user(self, item: str, values_file: str | None = None) -> None:
        """Before `item` is installed or re-applied: generate its MinIO access key (once; a stored one stays). An undo of
        an uninstall (values_file) brings the release back with the root login it had, which is recorded instead - unless
        that is the well-known 'admin' of an older install: nothing is stored then, so the plan still offers the rotation
        and `cs platform install minio --upgrade` still makes it."""
        if item not in MINIO_USERS:
            return
        if item == "velero" and "velero-minio-credentials" not in _pres_of(CATALOG[item], self):
            return   # velero on a cloud: its bucket is the cloud's, no MinIO user
        key, legacy, prefix = MINIO_USERS[item]
        if item == "minio" and values_file:
            try:
                root = json.loads(Path(values_file).read_text()).get("rootUser")
            except (OSError, ValueError, AttributeError):
                root = None
            if isinstance(root, str) and root and "{" not in root:
                data = self._secrets()
                if root == legacy:
                    data.pop(key, None)
                else:
                    data[key] = root
                self._save_secrets(data)
                return
        self.secret(key, prefix=prefix)

    def placeholders(self) -> dict:
        irsa = self.outputs.get("kubernetes_irsa_role_arns") or {}
        vals = {"cluster_name": self.outputs.get("kubernetes_cluster_name", self.env.id), "region": self.cfg.get("region", ""),
                "vpc_id": self.outputs.get("vpc_id", ""), "spark": "default",
                "lb_role_arn": irsa.get("lb-controller", ""), "autoscaler_role_arn": irsa.get("autoscaler", ""),
                "external_secrets_role_arn": irsa.get("external-secrets", ""),
                "external_secrets_gsa": self.outputs.get("kubernetes_external_secrets_gsa", ""),
                "external_secrets_client_id": self.outputs.get("kubernetes_external_secrets_client_id", ""),
                "external_dns_role_arn": irsa.get("external-dns", ""), "external_dns_gsa": self.outputs.get("kubernetes_external_dns_gsa", ""),
                "external_dns_client_id": self.outputs.get("kubernetes_external_dns_client_id", ""),
                "velero_role_arn": irsa.get("velero", ""), "velero_bucket": self.outputs.get("kubernetes_velero_bucket", ""),
                "velero_gsa": self.outputs.get("kubernetes_velero_gsa", ""), "velero_client_id": self.outputs.get("kubernetes_velero_client_id", ""),
                "velero_storage_account": self.outputs.get("kubernetes_velero_storage_account", ""), "velero_container": self.outputs.get("kubernetes_velero_container", ""),
                "karpenter_role_arn": irsa.get("karpenter", ""), "karpenter_queue": self.outputs.get("kubernetes_karpenter_queue", ""),
                "karpenter_node_role": self.outputs.get("kubernetes_karpenter_node_role", ""),
                "resource_group": self.outputs.get("resource_group_name", ""), "node_resource_group": self.outputs.get("kubernetes_node_resource_group", ""),
                "tenant_id": self.outputs.get("tenant_id", ""), "subscription_id": self.outputs.get("subscription_id", "") or self.cfg.get("vars", {}).get("subscription_id", ""),
                "containerd_socket": "/run/k3s/containerd/containerd.sock" if self.distro == "rke2" else "/run/containerd/containerd.sock",
                "project_id": self.cfg.get("vars", {}).get("project_id", ""),
                "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
                "openai_api_key": os.environ.get("OPENAI_API_KEY", "")}
        for s in ("grafana_password", "minio_password", "airflow_password", "jupyter_password", "harbor_password", "sonar_passcode",
                  "artifactory_password", "nexus_password", "minio_spark_password", "minio_velero_password", "polaris_password",
                  "litellm_db_password", "falco_ui_password"):
            vals[s] = self.secret(s)
        for s in ("artifactory_master_key", "artifactory_join_key"):
            vals[s] = self.secret(s, hex_bytes=32)
        for item, (key, _legacy, _prefix) in MINIO_USERS.items():
            vals[key] = self.minio_user(item)
        # pod annotations that change with a consumer's MinIO key, so its pods restart and read the new one
        for who in ("velero", "spark"):
            digest = hashlib.sha256(f"{vals['minio_' + who + '_user']}:{vals['minio_' + who + '_password']}".encode()).hexdigest()
            vals[f"minio_{who}_checksum"] = "sha256-" + digest[:16]
        # model provider for kagent: Anthropic when its key is set, else OpenAI when only that key is set
        vals["llm_provider"] = "openAI" if vals["openai_api_key"] and not vals["anthropic_api_key"] else "anthropic"
        vals["gitlab_runner_token"] = os.environ.get("GITLAB_RUNNER_TOKEN", "")
        for s in ("anthropic_api_key", "openai_api_key", "gitlab_runner_token"):
            _remember_secret(vals[s])
        vals["platform_domain"] = self.cfg.get("platform_domain") or f"{self.env.id}.local"
        # AWS: EKS's built-in service controller only honours aws-load-balancer-internal (the scheme annotation is read by
        # the AWS Load Balancer Controller, which is an optional extra); both are set so either controller makes it internal.
        lb = {"aws": {"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
                      "service.beta.kubernetes.io/aws-load-balancer-internal": "true",
                      "service.beta.kubernetes.io/aws-load-balancer-type": "nlb"},
              "gcp": {"networking.gke.io/load-balancer-type": "Internal"},
              "azure": {"service.beta.kubernetes.io/azure-load-balancer-internal": "true"}}.get(self.target, {})
        vals["lb_annotations"] = "\n".join(f'          {k}: "{v}"' for k, v in lb.items()) or "          cloudseed.io/lb: local"
        vals["lb_range"] = self.lb_pool()[0]
        return vals


def _docker_config_without_missing_helpers(target: Path, path: str) -> None:
    """The user's Docker config minus credential helpers that are not installed: registry logins (auths) and helpers
    that do resolve keep working for private OCI charts; a missing helper can no longer break a public pull."""
    src = Path(os.environ.get("DOCKER_CONFIG") or Path.home() / ".docker") / "config.json"
    try:
        if src.resolve() == target.resolve():
            return   # a child process started with this environment: the copy is already the filtered one
        user = json.loads(src.read_text())
    except (OSError, ValueError):
        user = {}
    if not isinstance(user, dict):
        user = {}

    def usable(helper) -> bool:
        return isinstance(helper, str) and bool(helper) and shutil.which(f"docker-credential-{helper}", path=path) is not None

    out: dict = {"auths": user.get("auths") if isinstance(user.get("auths"), dict) else {}}
    if usable(user.get("credsStore")):
        out["credsStore"] = user["credsStore"]
    helpers = {reg: h for reg, h in (user.get("credHelpers") or {}).items() if usable(h)} if isinstance(user.get("credHelpers"), dict) else {}
    if helpers:
        out["credHelpers"] = helpers
    text = json.dumps(out, indent=2) + "\n"
    try:
        if target.exists() and target.read_text() == text:
            return
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            os.fchmod(fh.fileno(), 0o600)   # it now carries registry logins: an older, world-readable file is tightened
            fh.write(text)
    except OSError:
        pass


def resolve(names: list[str], ctx: Cluster) -> list[str]:
    """Expand groups, add dependencies (in order), drop items not applicable to this cluster."""
    wanted = _expand(names)
    ordered: list[str] = []

    def add(item: str) -> None:
        spec = CATALOG[item]
        if spec.get("only") and ctx.target not in spec["only"]:
            return
        for dep in _direct_deps(item, ctx):
            add(dep)
        if item not in ordered:
            ordered.append(item)

    for w in wanted:
        add(w)
    return ordered


_IN_PROGRESS = "another operation (install/upgrade/rollback) is in progress"


def _run(cmd: list[str], ctx: Cluster, check: bool = True) -> int:
    shown = " ".join(_redact(c) for c in cmd)
    print(ui.dim("  $ " + shown))
    audit.write("$ " + shown)
    tail: list[str] = []
    red = secrets.StreamRedactor()   # one per stream: a private key printed over several lines is hidden whole
    child = subprocess.Popen(cmd, env=ctx.procenv(), text=True, errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        assert child.stdout is not None
        for line in child.stdout:
            clean = red.feed(_scrub_known(line))
            if clean:
                print("    " + clean, end="", flush=True)
                audit.write(clean)
            tail = (tail + [line])[-60:]
        rc = child.wait()
    finally:
        if child.poll() is None:        # our side broke (Ctrl-C, closed pipe): never leave helm running half-way
            child.kill()
            child.wait()
        if child.stdout:
            child.stdout.close()
    ctx.last_output = "".join(tail)
    if check and rc != 0:
        if _IN_PROGRESS in ctx.last_output:
            rel, ns = _helm_target(cmd)
            raise ui.Abort(f"helm: another install/upgrade/rollback of {rel or 'this release'} is in progress (or was interrupted). "
                           f"If nothing else is working on it: cs helm rollback {rel or '<release>'} -n {ns or '<namespace>'} "
                           f"(first install: cs helm uninstall {rel or '<release>'} -n {ns or '<namespace>'}), then re-run.")
        raise ui.Abort(f"command failed (exit {rc})")
    return rc


def _helm_target(cmd: list[str]) -> tuple[str, str]:
    """(release, namespace) of a helm upgrade/install/uninstall command line, best effort."""
    words, ns = [], ""
    skip = False
    for i, a in enumerate(cmd[1:], 1):
        if skip:
            skip = False
            continue
        if a in ("-n", "--namespace"):
            ns = cmd[i + 1] if i + 1 < len(cmd) else ""
            skip = True
        elif a in ("--version", "--timeout", "--set", "--set-string", "-f", "--values"):
            skip = True
        elif not a.startswith("-"):
            words.append(a)
    return (words[1] if len(words) > 1 else ""), ns


_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
# chart values that Kubernetes requires to be strings (labels, annotations): `--set` would turn "true" into a boolean
# (labels, annotations) and container env values ("true" must reach the API as a string, not a YAML boolean)
_STRING_VALUE_KEY = re.compile(r"(?i:(^|\.)[a-z0-9]*(labels|annotations)\.)|(^|\.)(env|extraEnv|extraEnvVars)(\[\d+\]\.value|\.[A-Z_][A-Z0-9_]*)$")


def _substitute(text: str, ph: dict) -> str:
    """One pass over `{name}` tokens: known placeholders are replaced, everything else (YAML/JSON flow maps such as
    `{selfSigned: {}}`, Helm list syntax such as `{mon,tue}`) stays exactly as written, and substituted values are
    never re-scanned."""
    return _PLACEHOLDER.sub(lambda m: str(ph[m.group(1)]) if m.group(1) in ph else m.group(0), text)


# FIPS environments: Karpenter's AMI aliases have no FIPS variant, so its nodes get the Bottlerocket FIPS images of the
# cluster's Kubernetes version through their SSM parameters (the controller policy may read /aws/service/*). Pinned to the
# version: re-applied by `cs platform install karpenter --upgrade` after a control-plane upgrade.
_KARPENTER_ALIAS = "  amiSelectorTerms: [{alias: bottlerocket@latest}]\n"
_KARPENTER_FIPS_AMIS = ("  amiFamily: Bottlerocket\n  amiSelectorTerms:\n"
                        + "".join(f"    - ssmParameter: /aws/service/bottlerocket/aws-k8s-{{kubernetes_version}}-fips/{a}/latest/image_id\n"
                                  for a in ("x86_64", "arm64")))


def render_manifest(name: str, ctx: Cluster) -> str:
    """POST_MANIFESTS[name] with this cluster's placeholders filled in (what install applies and uninstall deletes)."""
    text = POST_MANIFESTS[name]
    ph = ctx.placeholders()
    if name == "karpenter-default" and ctx.fips:
        text = text.replace(_KARPENTER_ALIAS, _KARPENTER_FIPS_AMIS)
        version = ctx.kubernetes_version()
        if version:
            ph = dict(ph, kubernetes_version=version)
    return _substitute(text, ph)


def _manifest_file(ctx: Cluster, name: str) -> Path:
    path = ctx.workdir / f"{name}.yaml"
    _write_private(path, render_manifest(name, ctx))
    return path


def _strip_documents(text: str, keep: list | tuple = ()) -> tuple[str, list[tuple[str, str, str]]]:
    """A multi-document manifest minus (1) the Namespace documents of catalog namespaces (velero, external-dns, kubeflow
    ...): those can hold what the user or another item keeps there (backups, PVCs, the other kubeflow item), so
    _cleanup_namespaces removes them only when empty and unused - a namespace only this manifest uses (cloudseed) goes
    with it; and (2) the (kind, name) documents in `keep` (data that outlives the item: the Polaris database).
    Returns (text, the kept objects as (kind, name, namespace))."""
    chart_ns = {sp.get("ns", "default") for sp in CATALOG.values()}
    kept_objs: list[tuple[str, str, str]] = []
    out = []
    for doc in re.split(r"(?m)^---\s*$", text):
        objs = _manifest_objects(doc)
        if objs:
            kind, name, ns = objs[0]
            if kind == "Namespace" and name in chart_ns:
                continue
            if (kind, name) in {tuple(k) for k in keep}:
                kept_objs.append(objs[0])
                continue
        out.append(doc)
    return "---".join(out), kept_objs


def _deletion_file(ctx: Cluster, name: str, keep: list | tuple = ()) -> Path:
    """The rendered manifest to delete when its item is removed (see _strip_documents for what stays)."""
    text, _ = _strip_documents(render_manifest(name, ctx), keep)
    path = ctx.workdir / f"{name}.delete.yaml"
    _write_private(path, text)
    return path


def _value_contexts(spec: dict, ctx: Cluster) -> tuple:
    """The `values` contexts that apply, in merge order (later wins)."""
    contexts = ("default", ctx.target, ctx.distro, ctx.options.get("mode") or "ambient")
    if ctx.fips:
        contexts += ("fips", f"{ctx.target}+fips")
    arch = spec.get("arch") or []
    if len(arch) == 1:
        contexts += (f"arch-{arch[0]}",)    # pins a single-architecture item's pods to nodes that can run them
    return contexts


def _values_args(spec: dict, ctx: Cluster, skip: set | None = None) -> list[str]:
    """--set flags for the catalog values of this cluster; keys in `skip` are left out (a restored values file has them)."""
    out: list[str] = []
    merged: dict = {}
    for c in _value_contexts(spec, ctx):
        merged.update((spec.get("values") or {}).get(c, {}))
    ph = ctx.placeholders()
    for k, v in merged.items():
        if skip and k in skip:
            continue
        v = _substitute(str(v), ph)
        if _PLACEHOLDER.search(v):
            continue  # a {placeholder} this cluster has no value for: leave the chart default
        out += ["--set-string" if _STRING_VALUE_KEY.search(k) else "--set", f"{k}={v}"]
    return out


def _flat_keys(values, prefix: str = "") -> set:
    """Every --set style key a values tree defines: dots inside a key escaped (a\\.b), list entries as [i]; a key whose
    value is a map is listed too (a catalog key may name it)."""
    keys: set = set()
    if isinstance(values, dict):
        for k, v in values.items():
            key = f"{prefix}.{str(k).replace('.', chr(92) + '.')}" if prefix else str(k).replace(".", chr(92) + ".")
            keys.add(key)
            keys |= _flat_keys(v, key)
    elif isinstance(values, list):
        for i, v in enumerate(values):
            key = f"{prefix}[{i}]"
            keys.add(key)
            keys |= _flat_keys(v, key)
    return keys


def _release_key(spec: dict, item: str) -> str:
    return f"{spec.get('ns', 'default')}/{spec.get('release', item)}"


def _release_state(spec: dict, item: str, releases: dict) -> str | None:
    """deployed | failed | pending (install/upgrade/rollback/uninstall in progress or interrupted) | present (a
    release-less item's probe object exists) | None (not there)."""
    if spec["method"] in ("helm", "oci"):
        rel = releases.get(_release_key(spec, item))
        if rel is None:
            return None
        status_ = str(rel.get("status", "")).lower()
        if status_ == "deployed":
            return "deployed"
        if status_.startswith("pending") or status_ == "uninstalling":
            return "pending"
        return "failed"
    if spec.get("probe"):
        return "present" if releases.get("probe:" + item) is not None else None
    return None


def _already_installed(spec: dict, item: str, releases: dict) -> bool:
    """Installed and healthy: a deployed release, or a release-less item's probe object. Failed and pending releases
    are NOT installed (re-running install repairs a failed one; a pending one needs a rollback/uninstall first)."""
    return _release_state(spec, item, releases) in ("deployed", "present")


def _pending_fix(spec: dict, item: str, releases: dict) -> str:
    """The command that unblocks a pending release: nothing to roll back to on a first install, so uninstall it."""
    key = _release_key(spec, item)
    rel = releases.get(key) or {}
    ns, name = key.split("/", 1)
    first = rel.get("status") in ("pending-install", "uninstalling") or str(rel.get("revision", "1")) == "1"
    return f"cs helm uninstall {name} -n {ns}" if first else f"cs helm rollback {name} -n {ns}"


def _pending_remedy(spec: dict, item: str, releases: dict) -> str:
    key = _release_key(spec, item)
    st = (releases.get(key) or {}).get("status", "pending")
    return (f"release {key} is {st}: an earlier install/upgrade was interrupted (or is still running elsewhere). "
            f"If nothing else is working on it: {_pending_fix(spec, item, releases)}, then re-run.")


def _probe_installed(ctx: "Cluster", spec: dict) -> bool:
    """Items installed by manifest/kustomize/post manifests leave no helm release; a probe names one object whose
    presence means 'installed' (crd/clusterissuer are cluster-scoped; a third element is the namespace)."""
    kubectl = deps.find("kubectl")
    probe = spec["probe"]
    cmd = [kubectl, "get", probe[0], probe[1]] + (["-n", probe[2]] if len(probe) > 2 else [])
    return subprocess.run(cmd, env=ctx.procenv(), capture_output=True).returncode == 0


def install_one(item: str, ctx: Cluster, wait: bool, version: str | None = None, extra_sets: list[str] | None = None,
                releases: dict | None = None, values_file: str | None = None, reapply: bool = False) -> None:
    """Install (or with ctx.upgrade or `reapply` - a mesh mode switch - re-apply) one item. `values_file` (undo of an
    uninstall) holds the exact values the removed release ran with: catalog and remembered --set keys it defines are not
    passed again (--set would win over it)."""
    spec = CATALOG[item]
    helm, kubectl = deps.find("helm"), deps.find("kubectl")
    ns, release = spec.get("ns", "default"), spec.get("release", item)
    print(f"\n  {ui.style('◆', 'brand')} {ui.style(item, 'bold', 'text')}  {ui.dim(spec['desc'])}")
    releases = releases if releases is not None else _releases_or_abort(ctx)
    state = _release_state(spec, item, releases)
    if state == "pending":
        raise ui.Abort(f"{item}: " + _pending_remedy(spec, item, releases))
    if not ctx.upgrade and not reapply and state in ("deployed", "present"):
        rel = releases.get(_release_key(spec, item)) or releases.get("probe:" + item) or {}
        ui.ok(f"already installed ({rel.get('chart', '')}, {rel.get('status', '')}) - skipping. Use --upgrade to re-apply.")
        return
    if spec.get("notes"):
        ui.info(spec["notes"])
    _ensure_pod_security(ctx, kubectl, item)
    ctx.settle_minio_user(item, values_file)   # before anything renders its access key (placeholders)
    restored: set = set()
    if values_file:
        try:
            restored = _flat_keys(json.loads(Path(values_file).read_text()))
        except (OSError, ValueError):
            restored = set()
        _user_values_restore(ctx, item)
    else:
        _user_values_drop_stash(ctx, item)
    sets = _values_args(spec, ctx, skip=restored) + _set_args(item, ctx, extra_sets, restored)
    common = ["-n", ns, "--create-namespace"] + (["--wait", "--timeout", "15m"] if wait else []) + _helm_apply_flags(helm) \
        + (["-f", values_file] if values_file else [])   # values of a previous install (undo of an uninstall)
    version = version or spec.get("version")
    if version:
        common += ["--version", version]
    for pre in spec.get("pre", []) + (spec.get("pre_by_target") or {}).get(ctx.target, []):
        _apply_manifest(ctx, kubectl, pre, ns, wait_ns=False)
    if spec["method"] == "helm":
        repo_name = item.replace("/", "-")
        _run([helm, "repo", "add", "--force-update", repo_name, spec["repo"]], ctx)
        _run([helm, "repo", "update", repo_name], ctx, check=False)
        _refresh_crds(ctx, helm, kubectl, item, f"{repo_name}/{spec['chart']}", version, releases)
        _run([helm, "upgrade", "--install", release, f"{repo_name}/{spec['chart']}", *common, *sets], ctx)
    elif spec["method"] == "oci":
        _refresh_crds(ctx, helm, kubectl, item, spec["chart"], version, releases)
        _run([helm, "upgrade", "--install", release, spec["chart"], *common, *sets], ctx)
    elif spec["method"] == "kustomize":
        _need_git(item)
        # its own field manager: two items applying the same object (kubeflow's shared Namespace) must not strip the
        # fields the other one set (server-side apply removes what the same manager no longer sends)
        manager = f"--field-manager=cloudseed-{item}"
        _run([kubectl, "apply", "-k", spec["url"], "--server-side", "--force-conflicts", manager], ctx)
        if spec.get("then"):
            _run([kubectl, "wait", "--for=condition=Established", "--all", "crd", "--timeout=120s"], ctx, check=False)
            _run([kubectl, "apply", "-k", spec["then"], "--server-side", "--force-conflicts", manager], ctx)
        _pin_arch(ctx, kubectl, item, spec)
    elif spec["method"] == "manifest":
        if spec.get("gateway_api"):
            _prepare_gateway_api_change(ctx, kubectl, spec["gateway_api"])
        _run([kubectl, "apply", "-f", spec["url"], "--server-side", "--force-conflicts"], ctx)
    if wait and spec["method"] in ("kustomize", "manifest") and ns not in _PROTECTED_NS:
        _wait_deployments(ctx, kubectl, item, ns)   # helm --wait does this for charts; kubectl apply returns at once
    if wait and spec.get("ready"):
        _wait_ready(ctx, kubectl, item, spec)
    for post in _posts_of(spec, ctx):
        _apply_manifest(ctx, kubectl, post, ns, wait_ns=True, wait=wait)
    _warn_if_public_lb(ctx, item)
    audit.note(ctx.env, f"platform-install-{item}", {"namespace": ns, "release": release, "method": spec["method"]})
    ui.ok(f"{item} installed {_where(spec)}")


PSA_NAMESPACE_TEMPLATE = """apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
  labels:
    pod-security.kubernetes.io/enforce: {level}
    pod-security.kubernetes.io/audit: {level}
    pod-security.kubernetes.io/warn: {level}
"""


def _pod_security_needs(spec: dict) -> dict[str, str]:
    """{namespace: level} the item's pods need (catalog "pod_security"; a plain level is for its own namespace)."""
    ps = spec.get("pod_security")
    if not ps:
        return {}
    return dict(ps) if isinstance(ps, dict) else {spec.get("ns", "default"): ps}


def pod_security_labels(item: str, ctx: Cluster) -> list[tuple[str, str]]:
    """(namespace, level) to label before the item is installed on this cluster: only under the RKE2 CIS profile, only
    the namespaces this install runs pods in (its own, and those of its manifests on this target), never the system
    ones (kube-system is exempt from the profile)."""
    if not getattr(ctx, "cis_profile", False):
        return []
    spec = CATALOG[item]
    here = {spec.get("ns", "default")}
    for m in _pres_of(spec, ctx) + _posts_of(spec, ctx):
        here |= {ns for _, _, ns in _manifest_objects(POST_MANIFESTS[m]) if ns}
    return [(ns, lv) for ns, lv in _pod_security_needs(spec).items() if ns in here and ns not in _PROTECTED_NS]


def _ensure_pod_security(ctx: Cluster, kubectl: str, item: str) -> None:
    """Label (creating it when missing) each namespace the item needs above restricted, before anything of it is
    applied: helm --create-namespace cannot label, and a pod the profile refuses never starts - the install would only
    time out. Server-side apply with its own field manager, so the item's manifests (velero's Namespace document) and
    helm leave the labels alone; a namespace already at that level or higher is not touched."""
    for ns, level in pod_security_labels(item, ctx):
        proc = subprocess.run([kubectl, "get", "namespace", ns, "-o", "jsonpath={.metadata.labels.pod-security\\.kubernetes\\.io/enforce}"],
                              env=ctx.procenv(), capture_output=True, text=True)
        have = proc.stdout.strip() if proc.returncode == 0 else ""
        if have in POD_SECURITY_LEVELS and POD_SECURITY_LEVELS.index(have) >= POD_SECURITY_LEVELS.index(level):
            continue
        path = ctx.workdir / f"pod-security-{ns}.yaml"
        _write_private(path, PSA_NAMESPACE_TEMPLATE.format(ns=ns, level=level))
        if _run([kubectl, "apply", "--server-side", "--force-conflicts", "--field-manager=cloudseed-pod-security", "-f", str(path)],
                ctx, check=False) != 0:
            raise ui.Abort(f"{item}: could not label namespace {ns} for {level} pods (see above); under the RKE2 CIS profile "
                           f"its pods would be refused. Fix the cause and re-run: cs platform install {item} --upgrade")
        ui.info(f"RKE2 CIS profile: namespace {ns} now admits {level} pods (was {have or 'restricted, the cluster default'}) "
                f"- {item} needs that")


def _where(spec: dict) -> str:
    """Where an installed item lives, for messages: a CRD-only item ("crds_only") is cluster-scoped - its namespace is
    at most where Helm keeps the release record (the gateway-api manifest has none at all)."""
    ns = spec.get("ns", "default")
    if not spec.get("crds_only"):
        return f"in namespace {ns}"
    if spec["method"] in ("helm", "oci"):
        return f"(cluster-scoped CRDs; Helm release record in namespace {ns})"
    return "(cluster-scoped CRDs)"


def _set_args(item: str, ctx: Cluster, extra_sets: list[str] | None, skip: set | None = None) -> list[str]:
    """--set flags after the catalog's: the item's remembered --set values (an earlier `install <item> --set`), then this
    run's (which win). `key-` forgets a remembered key. The mesh mode= never gets here (install() splits it off with
    split_mode when istio is part of the request); any other mode= is the chart's own value (MinIO's)."""
    current = list(extra_sets or [])
    saved = user_values(ctx, item)
    for e in current:
        if "=" not in e and e.endswith("-"):
            saved.pop(e[:-1], None)
    given = {e.split("=", 1)[0] for e in current if "=" in e}
    out: list[str] = []
    for k, v in saved.items():
        if k not in given and not (skip and k in skip):
            out += ["--set", f"{k}={v}"]
    for e in current:
        if "=" in e:
            out += ["--set", e]
    return out


# --set values the user gave for an item, re-applied by every later install/--upgrade of it (a group --upgrade cannot
# carry --set; without this it would put the chart back to the catalog values). 0600: they may hold secrets.
_USER_VALUES = "user-values.json"


def _user_values_all(ctx: Cluster) -> dict:
    try:
        data = json.loads((ctx.workdir / _USER_VALUES).read_text())
    except (OSError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


def _user_values_save(ctx: Cluster, data: dict) -> None:
    data = {k: v for k, v in data.items() if v}
    path = ctx.workdir / _USER_VALUES
    if not data:
        try:
            path.unlink()
        except OSError:
            pass
        return
    _write_private(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def user_values(ctx: Cluster, item: str) -> dict:
    """{key: value} the user set for an item with --set in an earlier install (re-applied by later ones)."""
    v = (_user_values_all(ctx).get("items") or {}).get(item)
    return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}


def remember_sets(ctx: Cluster, item: str, sets: list[str]) -> None:
    """Keep this run's --set values for the item (`key=value` sets, `key-` forgets; the mesh mode= is split off before)."""
    changes = list(sets or [])
    if not changes:
        return
    data = _user_values_all(ctx)
    items = data.setdefault("items", {})
    cur = dict(items.get(item) or {})
    for e in changes:
        if "=" in e:
            k, v = e.split("=", 1)
            cur[k] = v
        elif e.endswith("-"):
            cur.pop(e[:-1], None)
    if cur:
        items[item] = cur
    else:
        items.pop(item, None)
    _user_values_save(ctx, data)


def _user_values_stash(ctx: Cluster, item: str) -> None:
    """An uninstalled item's remembered values wait for `cs undo` (which restores them); a fresh install drops them."""
    data = _user_values_all(ctx)
    vals = (data.get("items") or {}).pop(item, None)
    if vals:
        data.setdefault("removed", {})[item] = vals
        _user_values_save(ctx, data)


def _user_values_restore(ctx: Cluster, item: str) -> None:
    data = _user_values_all(ctx)
    vals = (data.get("removed") or {}).pop(item, None)
    if vals:
        data.setdefault("items", {})[item] = vals
        _user_values_save(ctx, data)


def _user_values_drop_stash(ctx: Cluster, item: str) -> None:
    data = _user_values_all(ctx)
    if (data.get("removed") or {}).pop(item, None) is not None:
        _user_values_save(ctx, data)


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v).lstrip("v").split("-")[0])[:4])


def _installed_chart_version(spec: dict, item: str, releases: dict) -> str:
    """The chart version of the item's deployed release ('' when unknown): helm lists the chart as <name>-<version>."""
    chart = str((releases.get(_release_key(spec, item)) or {}).get("chart") or "")
    base = str(spec.get("chart") or "").rstrip("/").rsplit("/", 1)[-1]
    return chart[len(base) + 1:] if base and chart.startswith(base + "-") else ""


def _refresh_crds(ctx: Cluster, helm: str, kubectl: str, item: str, ref: str, version: str | None, releases: dict) -> None:
    """Helm installs a chart's crds/ once and never upgrades them: on --upgrade of an installed item that lists
    "upgrade_crds" (the API groups it owns), apply the new chart's CRDs of those groups first - never a downgrade, never
    CRDs of disabled subcharts or of other owners (the Gateway API bundle belongs to the gateway-api item)."""
    spec = CATALOG[item]
    groups = spec.get("upgrade_crds")
    if not groups or not ctx.upgrade or _release_state(spec, item, releases) is None:
        return
    have = _installed_chart_version(spec, item, releases)
    if have and version and _version_key(version) < _version_key(have):
        ui.info(f"{item}: its CRDs are left as they are ({version} is older than the installed {have}; CRDs are never downgraded)")
        return
    cmd = [helm, "show", "crds", ref] + (["--version", version] if version else [])
    try:
        proc = subprocess.run(cmd, env=ctx.procenv(), capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as e:
        proc = subprocess.CompletedProcess(cmd, 1, "", str(e))
    if proc.returncode != 0:
        ui.warn(f"{item}: could not read the chart's CRDs ({_redact((proc.stderr or '').strip()[-200:]) or 'helm show crds failed'}); "
                "they stay as they are")
        return
    docs, names = [], []
    for doc in re.split(r"(?m)^---\s*$", proc.stdout):
        objs = _manifest_objects(doc)
        if objs and objs[0][0] == "CustomResourceDefinition" and objs[0][1].split(".", 1)[-1] in groups:
            docs.append(doc.strip("\n"))
            names.append(objs[0][1])
    if not docs:
        return
    path = ctx.workdir / f"{item}-crds.yaml"
    _write_private(path, "\n---\n".join(docs) + "\n")
    ui.info(f"{item}: re-applying its {len(docs)} CRD(s) ({', '.join(groups)}) - helm upgrade never touches them")
    if _run([kubectl, "apply", "--server-side", "--force-conflicts", "--field-manager=cloudseed-crds", "-f", str(path)], ctx, check=False) != 0:
        ui.warn(f"{item}: its CRDs could not be updated (see above); the upgrade goes on with the ones on the cluster")
        return
    _run([kubectl, "wait", "--for=condition=Established", "--timeout=120s", *[f"crd/{n}" for n in names]], ctx, check=False)


_ARCH_PATCH = '{{"spec":{{"template":{{"spec":{{"nodeSelector":{{"kubernetes.io/arch":"{arch}"}}}}}}}}}}'


def _pin_arch(ctx: Cluster, kubectl: str, item: str, spec: dict) -> None:
    """Deployments of a kustomize item whose images exist for one architecture only: pinned to nodes that can run them
    (a Helm item does this through its arch-* values)."""
    arch = spec.get("arch") or []
    if len(arch) != 1:
        return
    for dep in spec.get("arch_pin", []):
        _run([kubectl, "-n", spec.get("ns", "default"), "patch", "deployment", dep, "--type=merge",
              "-p", _ARCH_PATCH.format(arch=arch[0])], ctx, check=False)


def _wait_ready(ctx: Cluster, kubectl: str, item: str, spec: dict) -> None:
    """An operator-made workload (the StarRocks FE/BE) is invisible to helm --wait: wait for its custom resource to
    report ready, and fail the install - with the pods and their scheduling messages - when it does not."""
    ready = spec["ready"]
    ns = spec.get("ns", "default")
    obj = f"{ready['kind']}/{ready['name']}"
    rc = _run([kubectl, "-n", ns, "wait", f"--for=jsonpath={ready['jsonpath']}={ready['value']}", obj, f"--timeout={_DEPLOY_WAIT}"], ctx, check=False)
    if rc == 0:
        return
    _run([kubectl, "-n", ns, "get", "pods", "-o", "wide"], ctx, check=False)
    _run([kubectl, "-n", ns, "get", "events", "--field-selector", "type=Warning", "--sort-by=.lastTimestamp"], ctx, check=False)
    raise ui.Abort(f"{item}: {obj} in namespace {ns} did not become {ready['value']} within {_DEPLOY_WAIT} (see the pods and warnings above: "
                   f"often too little CPU/memory on the nodes, or a volume that cannot be provisioned); fix the cause, then "
                   f"cs platform install {item} --upgrade")


def _need_git(item: str) -> None:
    """kubectl's built-in kustomize fetches github.com/... bases with git: without it `apply -k` fails half-way through."""
    if not shutil.which("git", path=deps.path_env().get("PATH")):
        raise ui.Abort(f"{item} is fetched from GitHub by kubectl's kustomize, which needs git: install git (macOS: xcode-select --install; "
                       "Debian/Ubuntu: sudo apt install git) and re-run.")


_DEPLOY_WAIT = "15m"   # as long as helm --wait gives a chart


def _wait_deployments(ctx: Cluster, kubectl: str, item: str, ns: str) -> None:
    """kubectl apply returns as soon as the objects are stored: an item counts as installed only once the Deployments in
    its namespace are available (a crash-looping one fails the install instead of being reported as done)."""
    rc = _run([kubectl, "-n", ns, "wait", "--for=condition=Available", "deployment", "--all", f"--timeout={_DEPLOY_WAIT}"], ctx, check=False)
    if rc == 0 or "no matching resources" in ctx.last_output:
        return
    _run([kubectl, "-n", ns, "get", "deployments,pods", "-o", "wide"], ctx, check=False)
    raise ui.Abort(f"{item}: its Deployments in namespace {ns} did not become available within {_DEPLOY_WAIT} (see above); "
                   f"fix the cause, then re-run with --upgrade: cs platform install {item} --upgrade")


def _manifest_objects(text: str) -> list[tuple[str, str, str]]:
    """(kind, name, namespace) of every document in a rendered manifest; metadata may be a flow map ({name: a,
    namespace: b, labels: {...}}) or a block. Namespace is '' when the document sets none."""
    out = []
    for doc in re.split(r"(?m)^---\s*$", text):
        kind = re.search(r"(?m)^kind:\s*([A-Za-z][A-Za-z0-9]*)\s*$", doc)
        meta = re.search(r"(?m)^metadata:[ \t]*(.*)$", doc)
        if not kind or not meta:
            continue
        fields: dict = {}
        flow = meta.group(1).strip()
        if flow.startswith("{"):
            inner = flow[1:flow.rfind("}")] if "}" in flow else flow[1:]
            while re.search(r"\{[^{}]*\}", inner):            # nested maps (labels) are not metadata's own keys
                inner = re.sub(r"\{[^{}]*\}", "", inner)
            for k, v in re.findall(r"(?:^|,)\s*([A-Za-z]+):\s*([^,]*)", inner):
                fields.setdefault(k, v.strip().strip("'\""))
        else:
            indent = None
            for line in doc[meta.end():].splitlines()[1:]:
                if not line.strip():
                    continue
                depth = len(line) - len(line.lstrip())
                if depth == 0:
                    break
                indent = depth if indent is None else indent
                m = re.match(r"\s*([A-Za-z]+):\s*(.*)$", line)
                if depth == indent and m:
                    fields.setdefault(m.group(1), m.group(2).strip().strip("'\""))
        if fields.get("name"):
            out.append((kind.group(1), fields["name"], fields.get("namespace", "")))
    return out


def _posts_of(spec: dict, ctx: Cluster, every: bool = False) -> list[str]:
    """Manifests rendered after the item (the FIPS ones only in FIPS envs, or always with every=True for removal)."""
    return (spec.get("post", []) + (spec.get("post_by_target") or {}).get(ctx.target, [])
            + (spec.get("post_fips", []) if (ctx.fips or every) else []))


def _pres_of(spec: dict, ctx: Cluster) -> list[str]:
    return spec.get("pre", []) + (spec.get("pre_by_target") or {}).get(ctx.target, [])


def _apply_manifest(ctx: Cluster, kubectl: str, name: str, ns: str, wait_ns: bool, wait: bool = True) -> None:
    """Render one of POST_MANIFESTS with the cluster placeholders and apply it (retrying while an operator's CRDs settle).
    Its one-shot Jobs must complete, and (unless wait=False, i.e. --no-wait) its Deployments must roll out, before the
    item counts as installed."""
    manifest = render_manifest(name, ctx)
    path = ctx.workdir / f"{name}.yaml"
    if "{kubernetes_version}" in manifest:
        raise ui.Abort(f"{name}: the cluster did not say its Kubernetes version (kubectl version), which picks the FIPS node images; "
                       "re-run once it answers")
    if name == "metallb-pool":
        _warn_pool_move(ctx, kubectl, ctx.placeholders()["lb_range"])
    _write_private(path, manifest)
    if wait_ns:
        _run([kubectl, "wait", "-n", ns, "--for=condition=Available", "deployment", "--all", "--timeout=300s"], ctx, check=False)
    # a one-shot Job of an earlier run (kept for 10 minutes after it finished) cannot be re-applied once its template
    # changed (spec.template is immutable), and running it again is what re-applying asks for: remove it first
    for kind, obj, obj_ns in _manifest_objects(manifest):
        if kind == "Job":
            _run([kubectl, "-n", obj_ns or ns, "delete", "job", obj, "--ignore-not-found"], ctx, check=False)
    rc = 1
    for attempt in range(6):  # CRDs registered by an operator can lag a few seconds
        rc = _run([kubectl, "apply", "-f", str(path)], ctx, check=False)
        if rc == 0:
            break
        if attempt < 5:
            import time
            time.sleep(10)
    if rc != 0:
        raise ui.Abort(f"could not apply {name}")
    objects = _manifest_objects(manifest)
    # one-shot Jobs in the manifest (bucket creation ...) must actually succeed before the item counts as installed
    for kind, obj, obj_ns in objects:
        if kind != "Job":
            continue
        obj_ns = obj_ns or ns
        rc = _run([kubectl, "-n", obj_ns, "wait", "--for=condition=complete", f"job/{obj}", "--timeout=300s"], ctx, check=False)
        if rc != 0:
            _run([kubectl, "-n", obj_ns, "describe", f"job/{obj}"], ctx, check=False)
            raise ui.Abort(f"job {obj_ns}/{obj} from {name} did not complete (see above); fix the cause and re-run with --upgrade")
    # and the services it runs (spark-history-server) must come up: a crash-looping one is a failed install
    for kind, obj, obj_ns in objects if wait else []:
        if kind != "Deployment":
            continue
        obj_ns = obj_ns or ns
        rc = _run([kubectl, "-n", obj_ns, "rollout", "status", f"deployment/{obj}", f"--timeout={_DEPLOY_WAIT}"], ctx, check=False)
        if rc != 0:
            _run([kubectl, "-n", obj_ns, "describe", f"deployment/{obj}"], ctx, check=False)
            raise ui.Abort(f"deployment {obj_ns}/{obj} from {name} did not become ready (see above); fix the cause and re-run with --upgrade")


def _warn_pool_move(ctx: Cluster, kubectl: str, new_range: str) -> None:
    """Re-applying the MetalLB pool with a new range (it used to overlap the vmnet's DHCP pool) moves LoadBalancer
    addresses: say so, so /etc/hosts entries for the ingress get refreshed. Only a warning: a kubectl that cannot run
    or does not answer leaves it out, the apply that follows reports the real problem."""
    try:
        have = subprocess.run([kubectl, "-n", "metallb-system", "get", "ipaddresspool", "cloudseed", "-o", "jsonpath={.spec.addresses[0]}"],
                              env=ctx.procenv(), capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return
    if have and have != new_range:
        ui.warn(f"MetalLB pool moves from {have} to {new_range} (kept clear of the vmnet's DHCP range): LoadBalancer services "
                "get new addresses - run `cs platform ui` for the new ingress address and update /etc/hosts.")


def _warn_if_public_lb(ctx: Cluster, item: str) -> None:
    """EKS keeps the scheme an NLB was created with: one made before cloudseed marked it internal stays internet-facing
    after an upgrade. Detect that (its DNS name resolves to public addresses) and say how to recreate it."""
    if ctx.target != "aws" or item not in ("envoy-gateway", "ingress-nginx"):
        return
    import ipaddress
    import socket
    kubectl = deps.find("kubectl")
    if item == "envoy-gateway":
        ns, sel = "envoy-gateway-system", ["-l", "gateway.envoyproxy.io/owning-gateway-name=cloudseed"]
        how = "cs kubectl -n envoy-gateway-system delete svc -l gateway.envoyproxy.io/owning-gateway-name=cloudseed"
    else:
        ns, sel = "ingress-nginx", ["ingress-nginx-controller"]
        how = "cs kubectl -n ingress-nginx delete svc ingress-nginx-controller && cs platform install ingress-nginx --upgrade"
    jp = "{.items[*].status.loadBalancer.ingress[*].hostname}" if item == "envoy-gateway" else "{.status.loadBalancer.ingress[*].hostname}"
    out = subprocess.run([kubectl, "-n", ns, "get", "svc", *sel, "-o", f"jsonpath={jp}"], env=ctx.procenv(), capture_output=True, text=True).stdout.split()
    for host in out:
        try:
            ips = {ipaddress.ip_address(ai[4][0].split("%")[0]) for ai in socket.getaddrinfo(host, None)}
        except (OSError, ValueError):
            continue
        # is_global, not "not is_private": VPCs may use 100.64.0.0/10 (shared, neither private nor global)
        if ips and all(ip.is_global for ip in ips):
            ui.warn(f"{item}: its load balancer {host} is INTERNET-FACING (created before cloudseed marked it internal; AWS keeps the "
                    f"scheme of an existing NLB). Recreate it as an internal one: {how}")


def _prereq_outputs_present(pre: str, ctx: Cluster) -> bool:
    """Do the stack outputs already carry what this prerequisite produces on this target?"""
    o = ctx.outputs
    if ctx.target == "vmware":
        return True
    if pre == "velero":
        return bool({"aws": o.get("kubernetes_velero_bucket"), "gcp": o.get("kubernetes_velero_bucket"), "azure": o.get("kubernetes_velero_storage_account")}.get(ctx.target))
    if pre == "karpenter":
        return ctx.target != "aws" or bool(o.get("kubernetes_karpenter_queue"))
    return True


def missing_prereqs(names: list[str], ctx: Cluster, releases: dict | None = None, force: bool = False) -> list[str]:
    """Cloud prerequisites the stack must gain before these items can be installed (empty on local targets)."""
    if ctx.target == "vmware":
        return []
    out: list[str] = []
    for e in plan(names, ctx, releases, force=force):
        for pre in e.get("cloud_prereqs", []):
            if pre not in out:
                out.append(pre)
    return out


def _closure(names: list[str]) -> set:
    """Every item a request can reach on any target: groups expanded, then needs, needs_by_target (every target) and
    the members of every mode of a meta item, transitively."""
    seen: set = set()
    todo = list(_expand(names))
    while todo:
        item = todo.pop()
        if item in seen:
            continue
        seen.add(item)
        spec = CATALOG[item]
        todo += spec.get("needs", [])
        for ds in (spec.get("needs_by_target") or {}).values():
            todo += ds
        if spec["method"] == "meta":
            for members in spec["modes"].values():
                todo += members
    return seen


def meta_modes() -> list[str]:
    """The modes a meta item can run in (istio: ambient, sidecar)."""
    return sorted({m for v in CATALOG.values() if v["method"] == "meta" for m in v.get("modes", {})})


def meta_mode_applies(names: list[str]) -> bool:
    """Whether `--set mode=...` chooses a meta item's mode (istio: ambient | sidecar) for this request: only when a meta
    item is part of it - named, in a named group, or a dependency (kiali and istio-gateway need istio) - or one of its
    members is (istiod, istio-cni ...: their values depend on the mode). Otherwise mode=... is an ordinary chart value
    (MinIO's chart has a top-level `mode`: standalone | distributed)."""
    members = {m for v in CATALOG.values() if v["method"] == "meta" for ms in v["modes"].values() for m in ms}
    return bool(names) and any(CATALOG[i]["method"] == "meta" or i in members for i in _closure(names))


def split_mode(names: list[str], extra_sets: list[str] | None) -> tuple[str | None, list[str]]:
    """(the mesh mode `--set mode=...` picks - None when not given or when no meta item is part of the request -, the
    --set values meant for charts). The last mode= wins; an unknown mode is refused (a typo must not install another
    mode silently)."""
    sets = list(extra_sets or [])
    if not meta_mode_applies(names):
        return None, sets
    mode, rest = None, []
    for e in sets:
        if e.startswith("mode="):
            mode = e.split("=", 1)[1]
        else:
            rest.append(e)
    if mode is not None and mode not in meta_modes():
        raise ui.Abort(f"Unknown mode '{mode}' (choose: {', '.join(meta_modes())})")
    return mode, rest


def check_install_args(names: list[str], version: str | None, extra_sets: list[str] | None) -> tuple[list[str], str | None]:
    """(user --set values for charts - without the mesh mode= when a meta item is part of the request -, the one item
    they and --version apply to). --set/--version are chart-specific: they go to the single item the user named, never
    to its dependencies, so a group or several items are refused."""
    _, user_sets = split_mode(names, extra_sets)
    bad = [e for e in user_sets if "=" not in e and not (e.endswith("-") and len(e) > 1)]
    if bad:
        raise ui.Abort(f"--set {bad[0]}: expected key=value (or key- to drop a value kept from an earlier --set)")
    if not (user_sets or version):
        return user_sets, None
    if len(names) != 1 or names[0] not in CATALOG:
        raise ui.Abort("--set/--version apply to exactly one named item (not a group or several items; --set mode=... works "
                       "with groups that include istio). Install that item on its own: cs platform install <item> --set key=value")
    return user_sets, names[0]


def target_flag_warnings(entries: list[dict], ctx: Cluster, target: str | None, user_sets: list[str] | None,
                         version: str | None) -> None:
    """Say when --set/--version will not be applied: the item they are for is skipped, or it is not a Helm chart.
    install() and `cs platform plan` both call this, so the dry run says what the install will do."""
    user_sets = user_sets or []
    if not target or not (user_sets or version):
        return
    flags = " and ".join(f for f, v in (("--set", user_sets), ("--version", version)) if v)
    if CATALOG[target]["method"] not in ("helm", "oci"):   # never applied, whatever the plan does with it (--upgrade included)
        used = ("only --set mode=... is used by it" if CATALOG[target]["method"] == "meta"
                else "it is applied from manifests, which take no chart values or versions")
        ui.warn(f"{flags} not applied: {target} is not a Helm chart ({used})")
        return
    te = next((e for e in entries if e["item"] == target), None)
    if te is None or te["action"] != "install":
        why = ("not applicable here" if te is None else "already installed" if te["action"] == "skip-installed"
               else f"not used on {ctx.target}" if te["action"] == "skip-target"
               else f"skipped ({te['reasons'][-1]})" if te["reasons"] else f"skipped ({te['action']})")
        ui.warn(f"{flags} not applied: {target} is {why}" + ("; re-run with --upgrade to apply them" if te and te["action"] == "skip-installed" else ""))


def install(names: list[str], ctx: Cluster, wait: bool = True, version: str | None = None, extra_sets: list[str] | None = None,
            upgrade: bool = False, force: bool = False, summary: bool = True) -> list[str]:
    """Plan and install. Stops (non-zero, nothing installed) when every item named explicitly is skipped for a reason the
    user must act on (missing key, conflict, FIPS, architecture). summary=False: another command drives this (platform
    ui, chaos, dr) and prints its own result, so no closing panel."""
    user_sets, target = check_install_args(names, version, extra_sets)
    ensure_tools()
    ctx.upgrade = upgrade
    mode, _ = split_mode(names, extra_sets)
    if mode:
        ctx.options["mode"] = mode
    releases = _releases_or_abort(ctx)
    entries = plan(names, ctx, releases, force=force)
    if all(e["action"] == "skip-target" for e in entries):
        ui.warn(f"Nothing applicable to install on this cluster ({ctx.target}/{ctx.distro})"
                + "".join(f"; {e['item']}: {e['reasons'][0]}" for e in entries) + ".")
        return []
    print_plan(entries, ctx, user_sets=user_sets, version=version, target=target)
    blocked = [e for e in entries if e["action"] == "blocked-pending"]
    if blocked:
        raise ui.Abort("Nothing installed. " + " ".join(f"{e['item']}: {e['reasons'][0]}" for e in blocked))
    installs = [e["item"] for e in entries if e["action"] == "install"]
    unmet = [e for e in entries if e["action"] in _UNMET]
    if not installs and unmet:
        # nothing to install and something asked for cannot be: a failure when an item named explicitly is among them,
        # or when nothing of the request is there at all (a whole group skipped); already-installed members say "done"
        named = [e for e in unmet if e["item"] in names]
        if named or not any(e["action"] in ("skip-installed", "skip-provided") for e in entries):
            raise ui.Abort("Nothing installed. " + " ".join(f"{e['item']}: {e['reasons'][-1]}" for e in (named or unmet)))
    target_flag_warnings(entries, ctx, target, user_sets, version)
    done = ctx.done = []
    for e in entries:
        if e["action"] != "install":
            if e["action"] in _UNMET + ("skip-target",):
                ui.warn(f"{e['item']}: " + "; ".join(e["reasons"]))
            continue
        if e.get("cloud_prereqs"):
            raise ui.Abort(f"{e['item']} needs cloud prerequisites ({', '.join(e['cloud_prereqs'])}) that are not applied yet; "
                           f"run `cs platform install {e['item']}` (it applies them) instead of calling install() directly.")
        mine = e["item"] == target and CATALOG[target]["method"] in ("helm", "oci")   # (the others were warned about above)
        sets = (list(user_sets) if mine else []) + [f"{k}={v}" for k, v in e["sets"].items()]
        try:
            install_one(e["item"], ctx, wait, version if mine else None, sets, releases,
                        **({"reapply": True} if e.get("reapply") else {}))   # a mesh mode switch re-applies it
        except (SystemExit, KeyboardInterrupt):
            rest = installs[installs.index(e["item"]) + 1:]
            if done or rest:             # a batch: say what it did and did not get to (one item's error says it all)
                _stopped_panel(e["item"], done, rest, names)
            raise
        if mine:
            remember_sets(ctx, target, user_sets)   # re-applied by later installs and --upgrade of it
        done.append(e["item"])
    if summary:
        _done_panel(done, unmet)
    return done


def _done_panel(done: list[str], unmet: list[dict]) -> None:
    """What the run did: installed items, the ones skipped for a reason to act on, and where to look next."""
    if not done:
        ui.ok("Nothing to do: everything that can be installed here already is (or is built in)"
              + (" - the rest is skipped (see above)" if unmet else "") + ". --upgrade re-applies it.")
        return
    rows = [("installed", ", ".join(done))]
    for e in unmet:
        rows.append(("skipped", f"{e['item']}: {e['reasons'][-1] if e['reasons'] else e['action']}"))
    rows += [("status", "cs platform status"), ("pods", "cs kubectl get pods -A"), ("web UIs", "cs platform ui"), ("k9s", "cs k9s")]
    ui.panel("Done" if not unmet else "Done (some items skipped)", rows, accent="leaf" if not unmet else "seed")


def _stopped_panel(failed: str, done: list[str], rest: list[str], names: list[str]) -> None:
    """What a batch that stopped part-way did: installed (they stay), the item that failed, and what was never tried."""
    again = f"cs platform install {' '.join(names)}"
    nxt = f"fix the cause, then cs platform install {failed} --upgrade (re-applies it)"
    if rest or again != f"cs platform install {failed}":
        nxt += f" and {again} (skips what is installed)"
    ui.panel(f"Stopped at {failed}", [
        ("installed", ", ".join(done) + f"  (kept; cs platform uninstall {' '.join(done)} removes {'it' if len(done) == 1 else 'them'})"
         if done else "nothing"),
        ("failed", f"{failed} (it may be partly applied)"),
        ("not attempted", ", ".join(rest) or "-"),
        ("next", nxt)], accent="rose")


# ------------------------------------------------------------------------------------------------ uninstall

_PROTECTED_NS = {"default", "kube-system", "kube-public", "kube-node-lease"}
# Controllers that turn the item's own objects (its post manifests) into cloud resources: once those objects are deleted,
# what the controller made from them - EC2 instances, the shared Gateway's cloud load balancer - must be gone before the
# controller itself goes. Removed first, it leaves them running (billed, and blocking the VPC teardown) with nothing
# left to delete them. `get` lists them (kubectl get ... -o name, lines starting with `prefix`); `others` are the same
# kind made from anything else, and `foreign` (get, prefix, cloudseed's own) the user's own objects of the kind the posts
# create: either keeps the controller in place, since nothing else would delete what it launched.
_DRAIN_BEFORE_REMOVAL = {
    "karpenter": {"what": "the default NodePool's nodes (EC2 instances)", "prefix": "nodeclaim.karpenter.sh/", "timeout": 900,
                  "get": ["nodeclaims.karpenter.sh", "-l", "karpenter.sh/nodepool=default"], "others": ["nodeclaims.karpenter.sh"],
                  "foreign": (["nodepools.karpenter.sh"], "nodepool.karpenter.sh/", ("nodepool.karpenter.sh/default",)),
                  "fix": "delete those NodePools first (cs kubectl get nodepools; cs kubectl delete nodepool <name>)"},
    "envoy-gateway": {"what": "the shared Gateway's load balancer", "prefix": "service/", "timeout": 600,
                      "get": ["services", "-n", "envoy-gateway-system", "-l",
                              "gateway.envoyproxy.io/owning-gateway-name=cloudseed,gateway.envoyproxy.io/owning-gateway-namespace=cloudseed"]},
}
_GONE_KIND = ("the server doesn't have a resource type", "no matches for kind", "could not find the requested resource")
_GATEWAY_API_KINDS_OWNED = {("GatewayClass", "", "cloudseed"), ("Gateway", "cloudseed", "cloudseed")}


def _present(item: str, states: dict) -> bool:
    spec = CATALOG[item]
    if spec["method"] == "meta":
        return any(states.get(m) for mode in spec["modes"].values() for m in mode)
    return states.get(item) is not None


def removal_plan(names: list[str], ctx: Cluster, releases: dict, force: bool = False) -> dict:
    """What `uninstall` does: groups expand to their own core members, meta items to their members, and nothing else -
    dependencies are never removed implicitly (they are shared: cert-manager, gateway-api, metallb, local-path ...).
    Hidden companions (CRD charts) go along only when nothing else still uses them. Items still needed by an installed
    item outside the removal - or whose CRDs still hold objects nothing in this removal made (removing the chart deletes
    the CRDs and with them every such object) - are refused unless --force; items that are not installed are reported,
    not 'removed'."""
    states = {n: _release_state(sp, n, releases) for n, sp in CATALOG.items()}
    selected: list[str] = []
    kept: list[str] = []
    not_here: list[str] = []

    def pick(n: str) -> None:
        spec = CATALOG[n]
        if spec.get("only") and ctx.target not in spec["only"]:
            if n not in not_here:
                not_here.append(n)
            return
        if n not in selected:
            selected.append(n)
        if spec["method"] == "meta":
            for mode in spec["modes"].values():
                for m in mode:
                    pick(m)

    for n in names:
        if n in GROUPS:
            for k, v in CATALOG.items():
                if v["group"] == n and not v.get("hidden") and v.get("tier", "core") == "core":
                    pick(k)
            kept += [s for s in GROUP_EXTRA_MEMBERS.get(n, []) if s not in kept]
        elif n in CATALOG:
            pick(n)
        else:
            raise _unknown(n)
    kept = [k for k in kept if k not in selected and _present(k, states)]
    installed = {n for n in CATALOG if _present(n, states)}
    changed = True
    orphans: set = set()
    while changed:                      # orphaned hidden companions (kagent-crds, kserve-crd, agentgateway-crds, ...)
        changed = False
        for i in list(selected):
            for d in _direct_deps(i, ctx):
                if d in selected or not CATALOG[d].get("hidden") or d not in installed:
                    continue
                if not [o for o in installed if o not in selected and o != d and d in _direct_deps(o, ctx, all_modes=True)]:
                    pick(d)
                    orphans.add(d)
                    changed = True
    remove = [n for n in selected if _present(n, states)]
    absent = [n for n in selected if not _present(n, states)]   # every item has a release or a probe to tell
    # CRD charts whose CRDs still hold objects nothing in this removal made: a companion that only came along (nobody
    # named it) stays, with those objects - `uninstall kagent` removes the controller and keeps the user's agents; one
    # that was named (or a guard_crds item such as keda) is refused below unless --force
    crd_blocked: dict[str, str] = {}
    kept_notes: dict[str, str] = {}
    for n, theirs in _crd_users(ctx, remove).items():
        if n in orphans:
            remove.remove(n)
            kept.append(n)
            kept_notes[n] = f"kept: removing it would delete {_crd_users_text(theirs)} - name it (with --force) to do that"
        else:
            crd_blocked[n] = f"{_crd_users_text(theirs)} that removing it would delete too; delete or move them first"
    removal = set(remove)
    blocked: dict[str, list[str]] = {}
    for o in sorted(installed - removal):
        for d in _direct_deps(o, ctx, all_modes=True):
            if d in removal:
                blocked.setdefault(d, []).append(o)
    if any(CATALOG[n].get("gateway_api") for n in remove):
        foreign = _gateway_api_objects(ctx, owned="envoy-gateway" in removal)
        if foreign:
            gw = next(n for n in remove if CATALOG[n].get("gateway_api"))
            blocked.setdefault(gw, []).append(f"{len(foreign)} Gateway API object(s) that deleting the CRDs would delete too "
                                              f"(e.g. {', '.join(foreign[:3])})")
    for n, why in crd_blocked.items():
        blocked.setdefault(n, []).append(why)
    order = [i for i in reversed(resolve(remove, ctx)) if i in removal] if remove else []
    # operators that outlive what they still run (cloudnative-pg with a Postgres cluster): uninstall keeps them - even
    # with --force - so the panel says so up front instead of listing them as removed (_remove_one checks again)
    keeping: dict[str, str] = {}
    kubectl = deps.find("kubectl") if any(n in _KEEP_WHILE_USED for n in order) else None
    for n in order if kubectl else []:
        if n in _KEEP_WHILE_USED:
            running = _still_running(ctx, kubectl, n)
            if running:
                what, how = _KEEP_WHILE_USED[n][1], _KEEP_WHILE_USED[n][2]
                keeping[n] = (f"kept: it still runs {len(running)} {what} ({', '.join(running[:3])}{' ...' if len(running) > 3 else ''}); "
                              f"remove them first ({how})")
    return {"remove": order, "absent": absent, "kept": kept, "kept_notes": kept_notes, "not_here": not_here, "blocked": blocked,
            "states": states, "force": force, "keeping": keeping, "crd_blocked": sorted(crd_blocked)}


_CRD_COLUMNS = ("custom-columns=KIND:.kind,NS:.metadata.namespace,NAME:.metadata.name,"
                "REL:.metadata.annotations.meta\\.helm\\.sh/release-name,OWNERS:.metadata.ownerReferences[*].kind")


def _crd_users(ctx: Cluster, remove: list[str]) -> dict[str, list[str] | None]:
    """item -> the objects ("Kind ns/name") that stand in the way, for the CRD charts in this removal (hidden companions
    such as kagent-crds, and items marked "guard_crds") whose CRDs Helm deletes on uninstall (templated, without
    resource-policy keep) while objects of those kinds exist that nothing in this removal made: not created by one of
    its releases, not owned by another object (a controller's), not one of its own manifests. Deleting a CRD deletes
    every such object - the user's agents, InferenceServices, ScaledObjects, ExternalSecrets. None: they could not be
    listed (as unsafe as a list)."""
    helm, kubectl = deps.find("helm"), deps.find("kubectl")
    guarded = [n for n in remove if _guards_crds(n)]
    if not guarded or not helm or not kubectl:
        return {}
    releases = {CATALOG[n].get("release", n) for n in remove}
    ours = _removal_objects(ctx, remove)
    out: dict[str, list[str] | None] = {}
    for n in guarded:
        crds = _deletable_crds(ctx, helm, n)
        if not crds:
            continue
        rows = _crd_objects(ctx, kubectl, crds)
        if rows is None:
            out[n] = None
            continue
        theirs = []
        for parts in rows:
            if len(parts) < 5:
                continue
            kind, ns, name, rel, owners = parts[:5]
            if (rel != "<none>" and rel in releases) or owners != "<none>" or (kind, name) in ours:
                continue
            theirs.append(f"{kind} {ns + '/' if ns != '<none>' else ''}{name}")
        if theirs:
            out[n] = theirs
    return out


def _guards_crds(item: str) -> bool:
    """A CRD chart whose removal _crd_users checks: a hidden companion (kagent-crds ...) or an item marked guard_crds."""
    spec = CATALOG[item]
    return spec["method"] in ("helm", "oci") and bool(spec.get("hidden") or spec.get("guard_crds"))


def _removal_objects(ctx: Cluster, remove: list[str]) -> set:
    """(kind, name) of the objects the manifests of the items in this removal create (they come back with the items)."""
    ours = set()
    for n in remove:
        for m in _posts_of(CATALOG[n], ctx, every=True) + _pres_of(CATALOG[n], ctx):
            ours |= {(k, name) for k, name, _ in _manifest_objects(POST_MANIFESTS[m])}
    return ours


def _deletable_crds(ctx: Cluster, helm: str, item: str) -> list[str]:
    """The CRDs `helm uninstall` of the item's release deletes: templated ones without helm.sh/resource-policy keep."""
    spec = CATALOG[item]
    proc = subprocess.run([helm, "get", "manifest", spec.get("release", item), "-n", spec.get("ns", "default")],
                          env=ctx.procenv(), capture_output=True, text=True)
    crds = []
    for doc in re.split(r"(?m)^---\s*$", proc.stdout if proc.returncode == 0 else ""):
        objs = _manifest_objects(doc)
        if objs and objs[0][0] == "CustomResourceDefinition" and not re.search(r"helm\.sh/resource-policy:\s*[\"']?keep", doc):
            crds.append(objs[0][1])
    return crds


# metadata the API server sets: a saved object carrying it cannot be created again
_SERVER_METADATA = ("uid", "resourceVersion", "creationTimestamp", "generation", "managedFields", "selfLink",
                    "deletionTimestamp", "deletionGracePeriodSeconds")


def save_crd_objects(ctx: Cluster, items: list[str], remove: list[str], dest: Path) -> dict[str, dict]:
    """Before a forced removal of CRD charts (uninstall --force past _crd_users' refusal): the objects of their CRDs that
    the removal deletes and nothing brings back (_crd_users' rule: not made by a release or manifest of this removal, not
    owned by another object) are saved, one kubectl List per item, <dest>/<item>.objects.json (0600), so the undo can
    create them again once the charts are back (restore_crd_objects). Returns {item: {"objects": path, "count": n}}."""
    helm, kubectl = deps.find("helm"), deps.find("kubectl")
    if not helm or not kubectl:
        return {}
    releases = {CATALOG[n].get("release", n) for n in remove}
    ours = _removal_objects(ctx, remove)
    saved: dict[str, dict] = {}
    for n in items:
        crds = _deletable_crds(ctx, helm, n) if _guards_crds(n) else []
        found: list[dict] = []
        for crd in crds:
            proc = subprocess.run([kubectl, "get", crd, "-A", "--ignore-not-found", "-o", "json"], env=ctx.procenv(),
                                  capture_output=True, text=True)
            listed: list = []
            if proc.returncode == 0:
                try:
                    listed = json.loads(proc.stdout or "{}").get("items") or []
                except (ValueError, AttributeError):
                    listed = []
            else:
                ui.warn(f"{n}: could not read the objects of {crd} to keep them for the undo: "
                        f"{secrets.redact((proc.stderr or '').strip()[-200:])}")
            for obj in listed:
                if not isinstance(obj, dict) or not isinstance(obj.get("metadata"), dict):
                    continue
                meta = obj["metadata"]
                rel = (meta.get("annotations") or {}).get("meta.helm.sh/release-name")
                if (rel and rel in releases) or meta.get("ownerReferences") or (obj.get("kind"), meta.get("name")) in ours:
                    continue
                obj.pop("status", None)
                for key in _SERVER_METADATA:
                    meta.pop(key, None)
                found.append(obj)
        if not found:
            continue
        dest.mkdir(parents=True, exist_ok=True)
        path = dest / f"{n}.objects.json"
        _write_private(path, json.dumps({"apiVersion": "v1", "kind": "List", "items": found}, indent=1))
        saved[n] = {"objects": str(path), "count": len(found)}
        ui.info(f"{n}: saved {len(found)} custom resource(s) its removal deletes to {path} - `cs undo` creates them "
                f"again after re-installing {n}")
    return saved


def restore_crd_objects(ctx: Cluster, path: str) -> bool:
    """Create the objects save_crd_objects kept (after their CRD charts are installed again). Server-side apply with its
    own field manager: an object someone created again meanwhile is updated, not duplicated. False when kubectl failed
    for some of them (the file stays, and the warning says how to apply it by hand)."""
    kubectl = deps.find("kubectl")
    if not kubectl or not Path(path).exists():
        return False
    rc = _run([kubectl, "apply", "--server-side", "--force-conflicts", "--field-manager=cloudseed-undo", "-f", path],
              ctx, check=False)
    if rc != 0:
        ui.warn(f"Some of the saved custom resources could not be created again (see above). They are in {path}: "
                f"kubectl apply --server-side -f {path}")
    return rc == 0


def _crd_objects(ctx: Cluster, kubectl: str, crds: list[str]) -> list[list[str]] | None:
    """_CRD_COLUMNS rows of every object of these CRDs (None when they cannot be listed). One kubectl call; when one of
    the CRDs is already gone that call fails as a whole, so the rest are then listed one by one."""
    def get(names: list[str]):
        return subprocess.run([kubectl, "get", ",".join(names), "-A", "--no-headers", "--ignore-not-found", "-o", _CRD_COLUMNS],
                              env=ctx.procenv(), capture_output=True, text=True)
    q = get(crds)
    if q.returncode == 0:
        return [line.split() for line in q.stdout.splitlines()]
    if not any(g in (q.stderr or "") for g in _GONE_KIND):
        return None
    rows: list[list[str]] = []
    for crd in crds if len(crds) > 1 else []:
        q = get([crd])
        if q.returncode == 0:
            rows += [line.split() for line in q.stdout.splitlines()]
        elif not any(g in (q.stderr or "") for g in _GONE_KIND):
            return None
    return rows


def _crd_users_text(theirs: list[str] | None) -> str:
    if theirs is None:
        return "custom resources of its CRDs that could not be listed"
    return f"{len(theirs)} object(s) of its CRDs (e.g. {', '.join(theirs[:3])}{' ...' if len(theirs) > 3 else ''})"


def _gateway_api_objects(ctx: Cluster, owned: bool) -> list[str]:
    """Gateway API objects on the cluster that are not cloudseed's own (its GatewayClass/Gateway when envoy-gateway goes
    too, and the cloudseed-* UI routes `cs platform ui` recreates)."""
    kubectl = deps.find("kubectl")
    kinds = subprocess.run([kubectl, "api-resources", "--api-group=gateway.networking.k8s.io", "-o", "name"], env=ctx.procenv(),
                           capture_output=True, text=True).stdout.split()
    if not kinds:
        return []
    proc = subprocess.run([kubectl, "get", ",".join(kinds), "-A", "--no-headers", "--ignore-not-found",
                           "-o", "custom-columns=KIND:.kind,NS:.metadata.namespace,NAME:.metadata.name"],
                          env=ctx.procenv(), capture_output=True, text=True)
    out = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        kind, ns, name = parts[0], "" if parts[1] == "<none>" else parts[1], parts[2]
        if owned and (kind, ns, name) in _GATEWAY_API_KINDS_OWNED:
            continue
        if name.startswith("cloudseed-") and kind in ("HTTPRoute", "BackendTLSPolicy"):
            continue
        out.append(f"{kind} {ns + '/' if ns else ''}{name}")
    return out


def print_removal(rp: dict, ctx: Cluster) -> None:
    names = rp["remove"] + rp["absent"] + rp["kept"] + rp["not_here"] + list(rp["blocked"])
    nw = max([len(n) for n in names] + [8])
    avail = ui.width() - 6 - (2 + nw + 1)
    rows: list[str] = []
    keeping = rp.get("keeping") or {}
    for n in rp["remove"]:
        if n in rp["blocked"] and not rp["force"]:
            continue                    # shown below as blocked
        if n in keeping:
            rows.append(f"{ui.style('✔', 'leaf')} {ui.style(n.ljust(nw), 'text')} {ui.dim(keeping[n])}")
            continue
        keep = CATALOG[n].get("keep_on_uninstall")
        note = ("its data stays: " + ", ".join(f"{k} {nm}" for k, nm in keep)) if keep else CATALOG[n]["desc"]
        note = _shorten(note, max(0, avail))
        rows.append(f"{ui.style('−', 'rose', 'bold')} {ui.style(n.ljust(nw), 'text')} " + ui.dim(note if avail >= 20 else ""))
    for n in rp["absent"]:
        rows.append(f"{ui.style('○', 'muted')} {ui.style(n.ljust(nw), 'text')} {ui.dim('not installed - nothing to remove')}")
    for n in rp["not_here"]:
        rows.append(f"{ui.style('–', 'dim')} {ui.style(n.ljust(nw), 'text')} {ui.dim('not used on ' + ctx.target)}")
    for n in rp["kept"]:
        note = (rp.get("kept_notes") or {}).get(n) or "kept: shared with other groups (name it to remove it)"
        rows.append(f"{ui.style('✔', 'leaf')} {ui.style(n.ljust(nw), 'text')} {ui.dim(note)}")
    for n, why in rp["blocked"].items():
        rows.append(f"{ui.style('✖', 'rose', 'bold')} {ui.style(n.ljust(nw), 'text')} still needed by {', '.join(why)}")
    ui.panel(f"Uninstall from {ctx.env.id} ({ctx.target}/{ctx.distro})", rows or [ui.dim("nothing to do")])


def _deleted_something(ctx: Cluster) -> bool:
    return bool(re.search(r"\b(deleted|uninstalled)\b", ctx.last_output))


def _missing_kinds(ctx: Cluster) -> bool:
    """kubectl could not map the kinds (their CRDs are gone): the objects cannot exist either."""
    out = ctx.last_output
    return ("resource mapping not found" in out or "no matches for kind" in out) and "Error from server" not in out


def uninstall(names: list[str], ctx: Cluster, force: bool = False, approve=None, strict: bool = True,
              keep_objects: Path | None = None) -> list[str]:
    """Remove exactly what was asked for (see removal_plan), in reverse dependency order, each item's own objects first
    (Gateway, NodePool, Kafka CR ... while their controller still runs to release finalizers and cloud resources), then
    its release/manifests, then its pre-manifests (minus the data it keeps) and - when it is empty and nothing else uses
    it - its namespace. `approve(question)` is called with the final list before anything changes. Returns the items
    actually removed; ctx.failures lists the ones that could not be (and what they still need, which is kept), ctx.kept
    the ones deliberately left in place (an operator still running the data another item kept). With strict=True (undo
    and other internal callers) a failure raises once everything else is done, so the caller does not count it as done.
    `keep_objects`: a private directory where a --force removal of CRD charts first saves the custom resources it
    deletes (save_crd_objects; ctx.saved_objects says which), so an undo can bring them back."""
    ensure_tools()
    helm, kubectl = deps.find("helm"), deps.find("kubectl")
    releases = _releases_or_abort(ctx)
    rp = removal_plan(names, ctx, releases, force=force)
    print_removal(rp, ctx)
    ctx.failures = []
    ctx.kept = []
    if rp["blocked"]:
        why = "; ".join(f"{i} is still needed by {', '.join(w)}" for i, w in rp["blocked"].items())
        if not force:
            raise ui.Abort(f"Nothing removed: {why}. Uninstall those too (name them), or pass --force to remove it anyway.")
        ui.warn(f"--force: removing anyway, although {why}")
    if not rp["remove"]:
        ui.info("Nothing to uninstall.")
        return []
    going = [n for n in rp["remove"] if n not in (rp.get("keeping") or {})]
    if approve and going:               # (only kept operators: nothing changes, nothing to approve)
        approve(f"Uninstall {', '.join(going)} from {ctx.env.id}?")
    ctx.saved_objects = {}
    forced = [n for n in going if n in (rp.get("crd_blocked") or ())]
    if force and forced and keep_objects is not None:
        ctx.saved_objects = save_crd_objects(ctx, forced, rp["remove"], Path(keep_objects))
    removed: list[str] = []
    still_needed: dict[str, str] = {}   # dependency -> the item that could not be removed and still uses it
    keeping = rp.get("keeping") or {}
    for item in rp["remove"]:
        if item in still_needed:
            ui.warn(f"{item}: kept - {still_needed[item]} could not be removed and still needs it")
            ctx.failures.append(item)
            result = False
        elif item in keeping:           # shown as kept and not approved: stays even if what it runs is gone by now
            ui.warn(f"{item}: {keeping[item]}, then cs platform uninstall {item}")
            ctx.kept.append(item)
            result = "kept"
        else:
            result = _remove_one(item, ctx, helm, kubectl)
            if result is True:
                removed.append(item)
            elif result is False:
                ctx.failures.append(item)
            elif result == "kept":
                ctx.kept.append(item)
        if result is False or result == "kept":
            for d in _direct_deps(item, ctx, all_modes=True):
                still_needed.setdefault(d, still_needed.get(item, item))
    _cleanup_namespaces(ctx, kubectl, removed, rp["states"])
    if ctx.kept:
        ui.warn(f"Kept on purpose: {', '.join(ctx.kept)} (see above) - uninstall it once what it still runs is gone")
    if ctx.failures:
        msg = f"Could not remove: {', '.join(ctx.failures)} (see above)"
        if strict:
            raise ui.Abort(msg + (f"; removed: {', '.join(removed)}" if removed else "") + ". Fix the cause and re-run.")
        ui.warn(msg)
    return removed


# Operators that must outlive the data they run: while objects of these kinds exist (a Postgres cluster - e.g. the Polaris
# catalog database, which outlives `cs platform uninstall polaris`), the operator stays, or nothing would run, back up or
# ever clean them up. item -> (kubectl get args, what, how to remove them)
_KEEP_WHILE_USED = {
    "cloudnative-pg": (["clusters.postgresql.cnpg.io", "-A", "-o", "custom-columns=NS:.metadata.namespace,NAME:.metadata.name", "--no-headers"],
                       "Postgres cluster(s)", "cs kubectl delete clusters.postgresql.cnpg.io <name> -n <namespace> - that deletes its data"),
}


def _still_running(ctx: Cluster, kubectl: str, item: str) -> list[str] | None:
    """The objects an operator in _KEEP_WHILE_USED still runs ([] none, None when it cannot be told)."""
    get = _KEEP_WHILE_USED[item][0]
    proc = subprocess.run([kubectl, "get", *get], env=ctx.procenv(), capture_output=True, text=True)
    if proc.returncode != 0:
        return [] if any(g in (proc.stderr or "") for g in _GONE_KIND) else None
    return ["/".join(line.split()[:2]) for line in proc.stdout.splitlines() if len(line.split()) >= 2]


def _remove_one(item: str, ctx: Cluster, helm: str, kubectl: str):
    """True: removed; None: nothing of it was there; False: failed (the reason was printed); "kept": left in place on
    purpose (it still runs data that outlived another item - said why)."""
    spec = CATALOG[item]
    ns, release = spec.get("ns", "default"), spec.get("release", item)
    print(f"\n  {ui.style('◆', 'brand')} {ui.style(item, 'bold', 'text')}  {ui.dim('removing')}")
    found = False
    if item in _KEEP_WHILE_USED:
        running = _still_running(ctx, kubectl, item)
        what, how = _KEEP_WHILE_USED[item][1], _KEEP_WHILE_USED[item][2]
        if running is None:
            ui.warn(f"{item}: could not check for the {what} it runs; nothing removed - re-run the uninstall")
            return False
        if running:
            ui.warn(f"{item}: kept - it still runs {len(running)} {what} ({', '.join(running[:3])}{' ...' if len(running) > 3 else ''}); "
                    f"without it nothing would run or clean them up. Remove them first ({how}), then cs platform uninstall {item}")
            return "kept"
    drain = _DRAIN_BEFORE_REMOVAL.get(item)
    if drain and not _only_ours(ctx, kubectl, item, drain):
        return False
    for post in reversed(_posts_of(spec, ctx, every=True)):
        path = _deletion_file(ctx, post)
        # a NodePool's EC2NodeClass waits for its nodes to terminate: give it as long as the drain below
        rc = _run([kubectl, "delete", "-f", str(path), "--ignore-not-found", f"--timeout={drain['timeout'] if drain else 180}s"], ctx, check=False)
        found = found or _deleted_something(ctx)
        if rc != 0 and not _missing_kinds(ctx):
            # its controller must keep running until they are gone (it releases their finalizers, LBs and nodes)
            ui.warn(f"{item}: some objects from {post} were not deleted in time (a finalizer may be stuck); "
                    f"{item} itself is left in place - re-run the uninstall once they are gone")
            _report_stuck(ctx, kubectl, item)
            return False
    if drain and not _drained(ctx, kubectl, item, drain):
        return False
    method = spec["method"]
    if method in ("helm", "oci"):
        rc = _run([helm, "uninstall", release, "-n", ns, "--wait", "--timeout", "10m"], ctx, check=False)
        if rc == 0:
            found = True
        elif re.search(r"release: not found|release not loaded", ctx.last_output.lower()):
            pass                        # already gone (any other "not found" - a hook, a CRD - is a real failure)
        else:
            ui.warn(f"{item}: helm uninstall failed (exit {rc})")
            return False
    elif method == "kustomize":
        try:
            _need_git(item)
        except ui.Abort as e:
            ui.warn(f"{item}: not removed - {e}")
            return False
        for n, src in enumerate([s for s in (spec.get("then"), spec["url"]) if s]):
            # rendered here and deleted without its Namespace document: `delete -k` would delete the whole namespace,
            # with the other item that shares it (kubeflow) and everything the user keeps there
            path = _kustomize_deletion_file(ctx, kubectl, item, src, n)
            if path is None:
                return False
            rc = _run([kubectl, "delete", "-f", str(path), "--ignore-not-found", "--timeout=300s"], ctx, check=False)
            found = found or _deleted_something(ctx)
            if rc != 0 and not _missing_kinds(ctx):
                ui.warn(f"{item}: kubectl delete of {src} failed (exit {rc})")
                _report_stuck(ctx, kubectl, item)
                return False
    elif method == "manifest":
        rc = _run([kubectl, "delete", "-f", spec["url"], "--ignore-not-found", "--timeout=300s"], ctx, check=False)
        found = True
        if rc != 0:
            ui.warn(f"{item}: kubectl delete failed or timed out (exit {rc})")
            _report_stuck(ctx, kubectl, item)
            return False
    else:
        found = True                    # meta / post-only: their own objects were the posts above
    keep = spec.get("keep_on_uninstall") or []
    for pre in reversed(_pres_of(spec, ctx)):
        path = _deletion_file(ctx, pre, keep=keep)
        _run([kubectl, "delete", "-f", str(path), "--ignore-not-found", "--timeout=180s"], ctx, check=False)
    for pre in _pres_of(spec, ctx):
        for kind, name, obj_ns in _strip_documents(render_manifest(pre, ctx), keep)[1]:
            ui.info(f"{item}: its data is kept - {kind} {obj_ns + '/' if obj_ns else ''}{name} (a re-install picks it up again; "
                    f"delete it yourself to start empty)")
    if not found:
        ui.info(f"{item}: nothing of it was found on the cluster - it was not installed")
        return None
    _drop_ui_objects(ctx, kubectl, item)
    _user_values_stash(ctx, item)
    audit.note(ctx.env, f"platform-uninstall-{item}", {"namespace": ns})
    ui.ok(f"{item} removed")
    return True


def _kustomize_deletion_file(ctx: Cluster, kubectl: str, item: str, src: str, n: int) -> Path | None:
    """A kustomize source rendered locally minus the Namespace documents of catalog namespaces (see _strip_documents);
    None when it cannot be rendered (the reason is printed)."""
    try:
        proc = subprocess.run([kubectl, "kustomize", src], env=ctx.procenv(), capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError) as e:
        proc = subprocess.CompletedProcess([], 1, "", str(e))
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        ui.warn(f"{item}: not removed - could not render {src} ({_redact(detail[-1]) if detail else 'kubectl kustomize failed'}); "
                "re-run the uninstall when GitHub is reachable")
        return None
    text, _ = _strip_documents(proc.stdout)
    path = ctx.workdir / f"{item}.{n}.delete.yaml"
    _write_private(path, text)
    return path


def _drop_ui_objects(ctx: Cluster, kubectl: str, item: str) -> None:
    """What `cs platform ui` made for a removed item (its routes, TLS secret, login): cloudseed's own objects, gone with
    the item - left behind they route to nothing and keep its namespace alive."""
    if item not in UIS:
        return
    ns = UIS[item][0]
    names = {f"cloudseed-{item}", f"cloudseed-{item}-redirect", f"cloudseed-{item}-tls", f"cloudseed-{item}-basic-auth"}
    found = []
    for kind in ("httproutes.gateway.networking.k8s.io", "backendtlspolicies.gateway.networking.k8s.io", "securitypolicies.gateway.envoyproxy.io",
                 "ingresses.networking.k8s.io", "certificates.cert-manager.io", "secrets"):
        proc = subprocess.run([kubectl, "-n", ns, "get", kind, "-o", "name", "--ignore-not-found"], env=ctx.procenv(), capture_output=True, text=True)
        if proc.returncode == 0:
            found += [o for o in proc.stdout.split() if o.split("/", 1)[-1] in names]
    if found and _run([kubectl, "-n", ns, "delete", *found, "--ignore-not-found", "--timeout=60s"], ctx, check=False) == 0:
        ui.info(f"{item}: removed its web UI route ({', '.join(found)})")


def _cloud_objects(ctx: Cluster, kubectl: str, get: list[str], prefix: str) -> list[str] | None:
    """Names of the objects `kubectl get <get> -o name` lists ([] when their kind no longer exists); None when kubectl
    could not tell (unreachable API ...)."""
    proc = subprocess.run([kubectl, "get", *get, "-o", "name"], env=ctx.procenv(), capture_output=True, text=True)
    if proc.returncode != 0:
        return [] if any(g in (proc.stderr or "") for g in _GONE_KIND) else None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip().startswith(prefix)]


def _only_ours(ctx: Cluster, kubectl: str, item: str, drain: dict) -> bool:
    """Before anything is deleted: False (the item stays) when the user made more objects of the kind its controller
    turns into cloud resources (their own NodePools) - removing the controller would orphan what it launched for them."""
    if not drain.get("foreign"):
        return True
    get, prefix, mine = drain["foreign"]
    found = _cloud_objects(ctx, kubectl, get, prefix)
    if found is None:
        ui.warn(f"{item}: could not list the objects it manages; nothing removed - re-run the uninstall")
        return False
    theirs = [o for o in found if o not in mine]
    if theirs:
        ui.warn(f"{item}: kept - it also manages {', '.join(theirs[:3])}{' ...' if len(theirs) > 3 else ''}, which cloudseed did not "
                f"create; without {item} nothing would delete what they launched: {drain['fix']}, then re-run the uninstall")
        return False
    return True


def _drained(ctx: Cluster, kubectl: str, item: str, drain: dict) -> bool:
    """Wait (up to drain['timeout']) for the cloud-backed objects the controller made from the item's own objects to go.
    False - the controller stays, so it can still delete them - when some are left or it cannot be told."""
    left = _cloud_objects(ctx, kubectl, drain["get"], drain["prefix"])
    if left:
        ui.info(f"waiting for {drain['what']} to go (up to {drain['timeout'] // 60} min): {item} does that cleanup in the cloud, "
                f"so it is removed only afterwards")
        _run([kubectl, "wait", "--for=delete", *drain["get"], f"--timeout={drain['timeout']}s"], ctx, check=False)
        left = _cloud_objects(ctx, kubectl, drain["get"], drain["prefix"])
    if left is None:
        ui.warn(f"{item}: could not check that {drain['what']} went away; {item} is left in place - re-run the uninstall")
        return False
    if left:
        ui.warn(f"{item}: {drain['what']} not gone after {drain['timeout'] // 60} min ({', '.join(left[:3])}); {item} is left in "
                f"place so it can finish that cleanup - re-run the uninstall afterwards")
        return False
    others = _cloud_objects(ctx, kubectl, drain["others"], drain["prefix"]) if drain.get("others") else []
    if others is None:
        ui.warn(f"{item}: could not check for other resources it manages; {item} is left in place - re-run the uninstall")
        return False
    if others:
        ui.warn(f"{item}: kept - {len(others)} more of its cloud resources still run ({', '.join(others[:3])}); without {item} "
                f"nothing would delete them: {drain['fix']}, then re-run the uninstall")
        return False
    return True


def _report_stuck(ctx: Cluster, kubectl: str, item: str) -> None:
    """Objects that keep a finalizer after their controller is gone block deletes forever: show them and the fix."""
    kinds = "gatewayclasses,gateways" if CATALOG[item].get("gateway_api") or item == "envoy-gateway" else ""
    if kinds:
        out = subprocess.run([kubectl, "get", kinds, "-A", "--ignore-not-found", "-o",
                              "custom-columns=KIND:.kind,NS:.metadata.namespace,NAME:.metadata.name,FINALIZERS:.metadata.finalizers"],
                             env=ctx.procenv(), capture_output=True, text=True).stdout.strip()
        if out:
            print(ui.dim("\n".join("    " + line for line in out.splitlines())))
    ui.info("An object whose controller is gone keeps its finalizer; clear it with "
            "cs kubectl patch <kind> <name> [-n <ns>] --type=merge -p '{\"metadata\":{\"finalizers\":null}}' and re-run the uninstall.")


def _namespace_leftovers(ctx: Cluster, kubectl: str, ns: str) -> list[str] | None:
    """Objects still in a namespace (noise such as events, leases and the auto-created CA configmap ignored); None when
    the namespace is gone."""
    env = ctx.procenv()
    if subprocess.run([kubectl, "get", "namespace", ns], env=env, capture_output=True).returncode != 0:
        return None
    kinds = [k for k in subprocess.run([kubectl, "api-resources", "--verbs=list", "--namespaced", "-o", "name"], env=env,
                                       capture_output=True, text=True).stdout.split()
             if k not in ("events", "events.events.k8s.io") and not k.endswith(".metrics.k8s.io")]
    if not kinds:
        return ["(could not list its contents)"]
    proc = subprocess.run([kubectl, "get", ",".join(kinds), "-n", ns, "-o", "name", "--ignore-not-found"], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return ["(could not list all of its contents)"]
    noise = ("configmap/kube-root-ca.crt", "configmap/istio-ca-root-cert", "serviceaccount/default")
    left = [o for o in proc.stdout.split() if o not in noise
            and not o.startswith(("lease.coordination.k8s.io/", "endpoints/", "endpointslice.discovery.k8s.io/", "event"))]
    if any(o.startswith(_GC_CHILDREN) for o in left):
        going = _going_away(ctx, kubectl, ns)
        left = [o for o in left if o not in going]
    return left


# helm uninstall --wait returns once the Deployments/StatefulSets are gone; their ReplicaSets and (Terminating) pods are
# removed by the garbage collector moments later, so they must not count as "something is still in the namespace"
_GC_CHILDREN = ("pod/", "replicaset.apps/", "controllerrevision.apps/", "job.batch/")


def _going_away(ctx: Cluster, kubectl: str, ns: str) -> set:
    """Pods, ReplicaSets, ControllerRevisions and Jobs in `ns` that are being deleted or have an owner (the garbage
    collector deletes them with it; an owner that is still there is itself listed, and keeps the namespace)."""
    jp = '{range .items[*]}{.apiVersion}|{.kind}|{.metadata.name}|{.metadata.deletionTimestamp}|{.metadata.ownerReferences[*].kind}{"\\n"}{end}'
    proc = subprocess.run([kubectl, "get", "pods,replicasets.apps,controllerrevisions.apps,jobs.batch", "-n", ns, "--ignore-not-found",
                           "-o", f"jsonpath={jp}"], env=ctx.procenv(), capture_output=True, text=True)
    out = set()
    for line in proc.stdout.splitlines() if proc.returncode == 0 else []:
        parts = line.split("|")
        if len(parts) != 5:
            continue
        api, kind, name, deleting, owners = parts
        group = api.split("/")[0] if "/" in api else ""
        if deleting.strip() or owners.strip():
            out.add(f"{kind.lower()}{'.' + group if group else ''}/{name}")
    return out


def _cleanup_namespaces(ctx: Cluster, kubectl: str, removed: list[str], states: dict) -> None:
    """Delete the namespaces of removed items when nothing else of the catalog lives there and they are empty (so a
    PVC, a user's CR or anything else keeps its namespace)."""
    gone = set(removed)
    in_use = {CATALOG[n].get("ns", "default") for n in CATALOG if n not in gone and _present(n, states)}
    for ns in sorted({CATALOG[i].get("ns", "default") for i in removed}):
        if ns in _PROTECTED_NS or ns in in_use:
            continue
        left = _namespace_leftovers(ctx, kubectl, ns)
        if left is None:
            continue
        # what the removed items made there at runtime (operator certificates, meta-info, Helm hook leftovers) is theirs,
        # not the user's: it goes with the namespace instead of keeping it alive
        own = {o for i in removed if CATALOG[i].get("ns", "default") == ns for o in CATALOG[i].get("runtime_objects", [])}
        left = [o for o in left if o not in own]
        if left:
            ui.info(f"namespace {ns} kept: it still holds {len(left)} object(s), e.g. {left[0]} "
                    f"(delete it yourself when you no longer need them: cs kubectl delete namespace {ns})")
            continue
        if _run([kubectl, "delete", "namespace", ns, "--ignore-not-found", "--wait=false"], ctx, check=False) == 0:
            ui.ok(f"namespace {ns} removed (it was empty)")


_HELM_MAJOR: dict[str, int] = {}


def _helm_apply_flags(helm: str) -> list[str]:
    """Helm 4 applies with server-side apply; objects another manager already owns (Gateway API CRDs that cloudseed
    applied with kubectl, or a chart that ships the same CRDs as another) would fail with field conflicts. cloudseed
    owns everything it installs, so taking ownership is the right step-over."""
    if helm not in _HELM_MAJOR:
        try:
            out = subprocess.run([helm, "version", "--short"], capture_output=True, text=True).stdout.strip()
            _HELM_MAJOR[helm] = int(out.lstrip("v").split(".")[0])
        except (ValueError, OSError):
            _HELM_MAJOR[helm] = 3
    return ["--force-conflicts"] if _HELM_MAJOR[helm] >= 4 else []


def gateway_api_installed(ctx: Cluster) -> dict | None:
    """{'channel': ..., 'version': ...} of the Gateway API CRDs on the cluster, or None."""
    kubectl = deps.find("kubectl")
    proc = subprocess.run([kubectl, "get", "crd", "gateways.gateway.networking.k8s.io", "-o", "jsonpath={.metadata.annotations}"],
                          env=ctx.procenv(), capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        ann = json.loads(proc.stdout)
    except ValueError:
        return None
    return {"channel": ann.get("gateway.networking.k8s.io/channel", ""), "version": ann.get("gateway.networking.k8s.io/bundle-version", "")}


def _prepare_gateway_api_change(ctx: Cluster, kubectl: str, want: dict) -> None:
    """Upstream ships a ValidatingAdmissionPolicy that refuses experimental-over-standard and version downgrades of the
    Gateway API CRDs. cloudseed pins one channel/version for the whole platform (the one its gateway ships), so when the
    cluster has a different one, lift the policy for this apply exactly as the upstream message instructs."""
    have = gateway_api_installed(ctx)
    if not have or (have["channel"] == want["channel"] and have["version"] == want["version"]):
        return
    ui.info(f"Gateway API CRDs are {have['channel']} {have['version']}; moving to {want['channel']} {want['version']} "
            f"(removing the safe-upgrades admission policy for this apply, it is re-created by the manifest)")
    for kind in ("validatingadmissionpolicybinding", "validatingadmissionpolicy"):
        _run([kubectl, "delete", kind, "safe-upgrades.gateway.networking.k8s.io", "--ignore-not-found"], ctx, check=False)


def _unreachable_hint(ctx: Cluster) -> str:
    if ctx.target == "vmware":
        return f"are its VMs running? (cs status vmware --env {ctx.env.name})"
    where = f"{ctx.target} --env {ctx.env.name}"
    return f"connect the VPN (cs vpn connect {where}) or open the bastion tunnel (cs k8s tunnel {where})"


_HELM_PAGE = 256


def installed_releases(ctx: Cluster) -> dict[str, dict]:
    """Releases on the cluster (any status: deployed, failed, pending-*) keyed ns/name, plus 'probe:<item>' entries for
    release-less items. Raises ClusterUnreachable when helm cannot answer - that is never 'nothing installed'."""
    helm = deps.find("helm")
    if not helm:
        raise ClusterUnreachable("cannot tell what is installed: helm is not installed (cloudseed install helm)")
    # explicit status filters: Helm 3 lists only deployed+failed by default (and has --all), Helm 4 lists everything
    # (and dropped --all); these flags mean the same on both. helm returns at most --max releases per call (256 by
    # default): page through all of them, or a release past the first page would read as "not installed".
    base = [helm, "list", "-A", "--deployed", "--failed", "--pending", "--uninstalling", "-o", "json", "--max", str(_HELM_PAGE)]
    out: dict[str, dict] = {}
    offset = 0
    while True:
        cmd = base + (["--offset", str(offset)] if offset else [])
        try:
            proc = subprocess.run(cmd, env=ctx.procenv(), capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise ClusterUnreachable(f"cluster {ctx.env.id} did not answer within 2 minutes - {_unreachable_hint(ctx)}")
        if proc.returncode != 0:
            lines = (proc.stderr or proc.stdout or "").strip().splitlines()
            detail = secrets.redact(lines[-1].strip()) if lines else f"helm exited {proc.returncode}"
            raise ClusterUnreachable(f"cluster {ctx.env.id} is not reachable ({detail[:300]}) - {_unreachable_hint(ctx)}")
        try:
            page = [r for r in (json.loads(proc.stdout or "[]") or []) if isinstance(r, dict)]
        except (ValueError, TypeError):
            page = []
        before = len(out)
        for r in page:
            if r.get("namespace") is not None and r.get("name") is not None:
                out[f"{r['namespace']}/{r['name']}"] = r
        if len(page) < _HELM_PAGE or len(out) == before or offset > 100 * _HELM_PAGE:
            break                       # the last page (or a helm that ignores --offset: nothing new came back)
        offset += len(page)
    for name, spec in CATALOG.items():
        if spec.get("probe") and _probe_installed(ctx, spec):
            out["probe:" + name] = {"status": "present", "chart": "/".join(spec["probe"][:2])}
    return out


def source_of(spec: dict) -> str:
    m = spec["method"]
    if m == "helm":
        return f"{spec['repo']}  chart {spec['chart']}" + (f" @{spec['version']}" if spec.get("version") else "")
    if m == "oci":
        return spec["chart"] + (f" @{spec['version']}" if spec.get("version") else "")
    if m == "kustomize":
        return spec["url"] + (f"  then {spec['then']}" if spec.get("then") else "")
    if m == "manifest":
        return spec["url"]
    if m == "meta":
        return "bundle of: " + " | ".join(f"{k}: {', '.join(v)}" for k, v in spec["modes"].items())
    return "manifests rendered by cloudseed: " + ", ".join(spec.get("post", []))


def _releases_for_view(ctx: Cluster | None) -> tuple[dict, str]:
    """(releases, problem) for read-only views: an unreachable cluster gives ({}, reason) instead of pretending."""
    if not ctx:
        return {}, ""
    try:
        return installed_releases(ctx), ""
    except ClusterUnreachable as e:
        return {}, str(e)


def _state_of(name: str, spec: dict, releases: dict) -> str | None:
    if spec["method"] == "meta":
        return _release_state(CATALOG["istiod"], "istiod", releases) if name == "istio" else None
    return _release_state(spec, name, releases)


def _group_deps(core: list[str], shared: list[str], ctx: Cluster | None) -> list[tuple[str, str]]:
    """(item, tag) of what a group pulls in beyond its own members. With a cluster: exactly what install resolves there
    (target-specific needs, the installed or chosen mesh mode, off-target items dropped). Without one: every target's,
    the target-specific ones tagged with where they apply (minio and local-path-provisioner come with velero on vmware)."""
    if ctx is not None:
        return [(d, "") for d in resolve(core + shared, ctx) if d not in core and d not in shared]
    order: list[str] = []
    scope: dict = {}                    # item -> None (every target) or the set of targets it is pulled in on

    def collect(item: str, where) -> None:
        spec = CATALOG[item]
        nxt = [(d, where) for d in spec.get("needs", [])]
        for t, ds in (spec.get("needs_by_target") or {}).items():
            if where is None or where == t:
                nxt += [(d, t) for d in ds]
        if spec["method"] == "meta":
            nxt += [(m, where) for members in spec["modes"].values() for m in members]
        for d, w in nxt:
            if d in core or d in shared:
                continue
            if d not in scope:
                order.append(d)
                scope[d] = None if w is None else {w}
            elif scope[d] is None or (w is not None and w in scope[d]):
                continue
            else:
                scope[d] = None if w is None else scope[d] | {w}
            collect(d, w)

    for i in core + shared:
        collect(i, None)
    out = []
    for d in order:
        where = scope[d]
        if where is not None and set(CATALOG[d].get("only") or []) >= where:
            where = None                # the item runs only there anyway (its own [.. only] tag says so)
        out.append((d, "" if where is None else f"{'/'.join(sorted(where))} only"))
    return out


def _suggested_extras(extras: list[str], brought: set, ctx: Cluster | None) -> list[str]:
    """Up to two extras worth suggesting next to a group: ones that run on this target (none restricted to a target
    when it is unknown) and that neither conflict nor overlap with what the group brings, or with each other."""
    target = ctx.target if ctx is not None else None
    out: list[str] = []
    for e in extras:
        only = CATALOG[e].get("only")
        if only and target not in only:
            continue
        rule = RULES.get(e, {})
        if any(c in brought or c in out for c in rule.get("conflicts", []) + rule.get("overlaps", [])):
            continue
        out.append(e)
        if len(out) == 2:
            break
    return out


def group_info(group: str, ctx: Cluster | None) -> None:
    """Every tool a group brings: core items (installed by the group), extras (by name), shared members, and pulled-in dependencies."""
    releases, problem = _releases_for_view(ctx)
    if ctx is not None and not problem and "mode" not in ctx.options:
        mode = _installed_mode("istio", ctx, releases)
        if mode:
            ctx.options["mode"] = mode
    core = [k for k, v in CATALOG.items() if v["group"] == group and not v.get("hidden") and v.get("tier", "core") == "core"]
    extras = [k for k, v in CATALOG.items() if v["group"] == group and not v.get("hidden") and v.get("tier") == "extra"]
    shared = GROUP_EXTRA_MEMBERS.get(group, [])
    deps_ = _group_deps(core, shared, ctx)
    nw = max(len(n) for n in core + shared + [d for d, _ in deps_] + extras)

    def line(name, tag=""):
        spec = CATALOG[name]
        st = _state_of(name, spec, releases)
        built_in = ctx is not None and ctx.distro in PROVIDED_BY_DISTRO.get(name, [])   # as status() shows it
        mark = (ui.style("✔", "leaf", "bold") if built_in else ui.style("?", "seed") if problem
                else ui.style("✔", "leaf", "bold") if st in ("deployed", "present")
                else ui.style("✖", "rose", "bold") if st == "failed" else ui.style("▲", "seed") if st == "pending" else ui.style("○", "muted"))
        if built_in:
            tag = f"  (built into {ctx.distro}){tag}"
        only = f"  [{'/'.join(spec['only'])} only]" if spec.get("only") else ""
        avail = ui.width() - 6 - (2 + nw + 1) - len(only) - len(tag)
        return f"{mark} {ui.style(name.ljust(nw), 'text')} {_shorten(spec['desc'], max(avail, 20))}{ui.dim(only)}{ui.dim(tag)}"

    rows = [ui.style(f"installed by `cs platform install {group}`", "muted")] + [line(i) for i in core]
    if shared:
        rows += ["", ui.style("shared with other groups (installed too)", "muted")] + [line(i) for i in shared]
    if deps_:
        rows += ["", ui.style("dependencies pulled in automatically", "muted")] + \
            [line(d, f"  (dependency, {where})" if where else "  (dependency)") for d, where in deps_]
    if extras:
        rows += ["", ui.style("extras - install by name", "muted")] + [line(i, "  [extra]") for i in extras]
    if problem:
        rows += ["", ui.style("installed state unknown: " + problem, "seed")]
    ui.panel(f"group · {group}  ·  {GROUPS[group]}", rows)
    hints = [f"cs platform install {group}"]
    suggest = _suggested_extras(extras, set(core) | set(shared) | {d for d, _ in deps_}, ctx)
    if suggest:
        hints.append(f"cs platform install {group} {' '.join(suggest)}")
    _hint_line(hints + ["cs platform info <item>"])


_FIPS_TEXT = {
    "compatible": "compatible - runs on FIPS kernels, terminates no user-facing TLS of its own",
    "tls-restricted": "tls-restricted - TLS pinned to 1.2+/FIPS suites, but its proxy crypto is not a validated module (cs scan fips flags it)",
    "crypto-restricted": "crypto-restricted - its key generation/encryption is not a FIPS-validated module (cs scan fips flags it)",
}


def info(item: str, ctx: Cluster | None) -> None:
    """Everything about one catalog item: source, namespace, dependencies (per target), manifests applied around it,
    cloud prerequisites, FIPS class, step-over rules, values per context, notes and - with a cluster - its state."""
    if item in GROUPS:
        return group_info(item, ctx)
    if item not in CATALOG:
        raise _unknown(item)
    spec = CATALOG[item]
    ns_row = spec.get("ns", "default")
    if spec.get("crds_only"):
        ns_row = (f"cluster-scoped (CRDs only; Helm release record in {ns_row})" if spec["method"] in ("helm", "oci")
                  else "cluster-scoped (CRDs only)")
    rows: list = [("group", spec["group"]), ("what", spec["desc"]), ("method", spec["method"]), ("source", source_of(spec)),
                  ("namespace", ns_row)]
    if spec["method"] in ("helm", "oci"):
        rows.append(("release", spec.get("release", item)))
    elif spec["method"] == "meta":
        rows.append(("state from", "its members' releases (" + ", ".join(dict.fromkeys(m for ms in spec["modes"].values() for m in ms)) + ")"))
    if spec.get("probe"):
        p = spec["probe"]
        rows.append(("detected by", f"{p[0]} {p[1]}" + (f" in {p[2]}" if len(p) > 2 else "")))
    rows += [("tier", spec.get("tier", "core")), ("targets", ", ".join(spec.get("only", [])) or "all")]
    if spec.get("needs"):
        rows.append(("needs", ", ".join(spec["needs"])))
    for t, ds in (spec.get("needs_by_target") or {}).items():
        rows.append((f"needs[{t}]", ", ".join(ds)))
    if spec.get("requires"):
        rows.append(("requires", " or ".join(spec["requires"].get("any_env", [])) + "  (cs creds set <NAME>; skipped until one is set)"))
    if spec.get("cloud_prereqs"):
        rows.append(("cloud prereqs", ", ".join(spec["cloud_prereqs"]) + "  (identity, storage, tags added to the aws/gcp/azure stack first; not on vmware)"))
    if spec.get("pre"):
        rows.append(("applies first", ", ".join(spec["pre"]) + "  (manifests rendered by cloudseed)"))
    for t, ms in (spec.get("pre_by_target") or {}).items():
        rows.append((f"applies first[{t}]", ", ".join(ms)))
    if spec.get("post"):
        rows.append(("also applies", ", ".join(spec["post"]) + "  (manifests rendered by cloudseed)"))
    for t, ms in (spec.get("post_by_target") or {}).items():
        rows.append((f"also applies[{t}]", ", ".join(ms)))
    if spec.get("post_fips"):
        rows.append(("also applies[fips]", ", ".join(spec["post_fips"])))
    rows.append(("fips", _FIPS_TEXT.get(spec.get("fips"), "not FIPS-capable - skipped in FIPS environments unless --force")))
    if spec.get("arch"):
        rows.append(("architectures", "/".join(spec["arch"]) + " only (skipped where no node can run it; pinned to such nodes elsewhere)"))
    if spec.get("pod_security"):
        rows.append(("pod security", ", ".join(f"{lv} (namespace {ns})" for ns, lv in _pod_security_needs(spec).items())
                     + "  - labelled before install where the RKE2 CIS profile enforces restricted"))
    rule = RULES.get(item, {})
    if rule.get("conflicts"):
        rows.append(("conflicts", ", ".join(rule["conflicts"]) + "  (same role: skipped when one is there; --force installs anyway)"))
    if rule.get("overlaps"):
        rows.append(("overlaps", ", ".join(rule["overlaps"]) + "  (both can run; the plan warns)"))
    for sib, sets in (rule.get("when_installed") or {}).items():
        rows.append((f"with {sib}", ", ".join(f"{k}={v}" for k, v in sets.items())))
    if spec.get("upgrade_crds"):
        rows.append(("--upgrade", "re-applies its CRDs first (" + ", ".join(spec["upgrade_crds"]) + "); helm alone never upgrades them"))
    if spec.get("keep_on_uninstall"):
        rows.append(("uninstall keeps", ", ".join(f"{k} {n}" for k, n in spec["keep_on_uninstall"]) + "  (its data; a re-install picks it up)"))
    if item in UIS:
        rows.append(("web UI", f"https://{item}.<domain> (cs platform ui)" + (f"; login: {UIS[item][4]}" if UIS[item][4] else "")))
    for ctx_name, vals in (spec.get("values") or {}).items():
        for k, v in vals.items():
            rows.append((f"values[{ctx_name}]", f"{k} = {v}"))
    if spec.get("notes"):
        rows.append(("notes", spec["notes"]))
    if ctx:
        releases, problem = _releases_for_view(ctx)
        key = f"{spec['ns']}/istiod" if item == "istio" else _release_key(spec, item)
        rel = releases.get(key) or releases.get("probe:" + item)
        st = _state_of(item, spec, releases)
        carrier = ("istiod", CATALOG["istiod"]) if item == "istio" else (item, spec)   # the release that carries the state
        if ctx.distro in PROVIDED_BY_DISTRO.get(item, []):
            rows.append(("installed", f"built into {ctx.distro} - cloudseed does not install it there"))
        elif problem:
            rows.append(("installed", "unknown - " + problem))
        elif rel:
            mode = _installed_mode(item, ctx, releases) if spec["method"] == "meta" else None
            rows.append(("installed", f"{rel.get('chart', '')} ({rel.get('status', '')})" + (f", {mode} mode" if mode else "")
                         + ("  - repair: cs platform install " + item if st == "failed" else "")
                         + ("  - " + _pending_remedy(carrier[1], carrier[0], releases) if st == "pending" else "")))
            saved = user_values(ctx, item)
            if saved:
                rows.append(("your --set", ", ".join(_redact(f"{k}={v}") for k, v in saved.items()) + "  (re-applied by every install/--upgrade)"))
        else:
            rows.append(("installed", "no"))
    ui.panel(f"platform item · {item}", rows)
    _hint_line([f"install: cs platform install {item}", f"uninstall: cs platform uninstall {item}", "all items: cs platform list --charts"])


def status(ctx: Cluster | None, charts: bool = False, unknown: bool = False, releases: dict | None = None) -> None:
    """Catalog by group with the installed state on this cluster. Stops (non-zero) when the cluster cannot be asked:
    'not installed' would be a lie. unknown=True (a cluster exists but could not be asked, e.g. `platform list`): the
    catalog is shown with every state as unknown instead. `releases`: installed_releases() the caller already read
    (`platform list` asks helm once and falls back to unknown itself)."""
    if unknown:
        releases = {}
    elif releases is None:
        releases = _releases_or_abort(ctx) if ctx else {}
    for group, group_desc in GROUPS.items():
        entries = []
        for name, spec in CATALOG.items():
            if spec["group"] != group or spec.get("hidden"):
                continue
            key = _release_key(spec, name)
            if spec["method"] == "meta" and name == "istio":
                key = f"{spec['ns']}/istiod"
            st = _state_of(name, spec, releases)
            rel = releases.get(key) or releases.get("probe:" + name) or {}
            applicable = not spec.get("only") or (ctx and ctx.target in spec["only"])
            hint = ""
            if ctx and ctx.distro in PROVIDED_BY_DISTRO.get(name, []):
                mark, state = ui.style("✔", "leaf", "bold"), ui.style(f"built into {ctx.distro}", "leaf")
            elif st in ("deployed", "present"):
                mark = ui.style("✔", "leaf", "bold")
                state = ui.style(rel.get("status", ""), "leaf") + ui.dim("  " + rel.get("chart", ""))
            elif st == "failed":
                mark = ui.style("✖", "rose", "bold")
                state = ui.style(rel.get("status", "failed"), "rose") + ui.dim("  " + rel.get("chart", ""))
                hint = f"repair: cs platform install {name}"
            elif st == "pending":
                mark = ui.style("▲", "seed", "bold")
                state = ui.style(rel.get("status", "pending"), "seed") + ui.dim("  " + rel.get("chart", ""))
                fix = _pending_fix(CATALOG["istiod"] if name == "istio" else spec, "istiod" if name == "istio" else name, releases)
                hint = f"interrupted: {fix}, then cs platform install {name}"
            elif not applicable:
                only = "/".join(spec["only"])
                mark, state = ui.style("–", "dim"), ui.dim(f"{only} only" if ctx is None else f"not for {ctx.target} ({only} only)")
            elif unknown:
                mark, state = ui.style("?", "muted"), ui.dim("unknown")
            else:
                mark, state = ui.style("○", "muted"), ui.dim("not installed" + ("  [extra]" if spec.get("tier") == "extra" else ""))
            entries.append((mark, name, spec["desc"], state, hint, spec))
        if not entries:
            continue
        nw = max(len(e[1]) for e in entries)
        sw = max(len(ui._strip(e[3])) for e in entries)
        dw = ui.width() - 6 - (2 + nw + 1) - (1 + sw)
        rows = []
        for mark, name, desc, state, hint, spec in entries:
            if dw >= 16:
                rows.append(f"{mark} {ui.style(name.ljust(nw), 'text')} {_shorten(desc, dw).ljust(dw)} {state}")
            else:
                rows.append(f"{mark} {ui.style(name.ljust(nw), 'text')} {state}")
            if hint:
                rows.append(f"      {ui.style('↳', 'seed')} {hint}")
            if charts:
                rows.append(f"      {ui.dim(spec['method'].ljust(9) + source_of(spec))}")
        ui.panel(f"{group}  ·  {group_desc}", rows)
    total = sum(1 for v in CATALOG.values() if not v.get("hidden"))
    print()
    _hint_line([f"{total} items in {len(GROUPS)} groups", "cs platform info <item>", "cs platform list --charts",
                "cs platform install <group|item ...>", "cs help platform"])


def _hint_line(parts: list[str]) -> None:
    """Dim `a   ·   b   ·   c` footer, broken between parts to fit the terminal."""
    if ui.collect("hints", list(parts)):     # explain.lookup reads info pages as data
        return
    lines, cur = [], ""
    for p in parts:
        cand = f"{cur}   ·   {p}" if cur else p
        if cur and len(cand) + 2 > ui.width():
            lines.append(cur)
            cand = p
        cur = cand
    for line in lines + [cur]:
        print(ui.dim("  " + line))


def ensure_tools() -> None:
    """kubectl and helm, installed only with consent (asked on a terminal; with -y only when --auto-approve was given)."""
    from . import services
    for tool in ("kubectl", "helm"):
        services.ensure_tool(tool, "to manage the cluster's platform items", default=True)
    # git is needed only by the kustomize items fetched from GitHub: install_one/_remove_one check it for those
