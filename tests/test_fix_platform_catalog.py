"""Regression tests for the platform catalog data (cloudseed/platform.py CATALOG, POST_MANIFESTS, UIS, RULES, GROUPS)
and the GitLab CI template. Offline, stdlib only: nothing talks to a cluster, a registry or the network."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloudseed import clouds, paths, platform as pl  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OUTPUTS = {
    "kubernetes_cluster_name": "c1", "vpc_id": "vpc-1", "resource_group_name": "rg", "tenant_id": "tid", "subscription_id": "sid",
    "kubernetes_irsa_role_arns": {k: f"arn:{k}" for k in ("lb-controller", "autoscaler", "external-secrets", "external-dns", "velero", "karpenter")},
    "kubernetes_external_secrets_gsa": "es@p", "kubernetes_external_secrets_client_id": "es-cid", "kubernetes_external_dns_gsa": "dns@p",
    "kubernetes_external_dns_client_id": "dns-cid", "kubernetes_velero_bucket": "vb", "kubernetes_velero_gsa": "v@p", "kubernetes_velero_client_id": "v-cid",
    "kubernetes_velero_storage_account": "vsa", "kubernetes_velero_container": "velero", "kubernetes_karpenter_queue": "kq",
    "kubernetes_karpenter_node_role": "knr", "kubernetes_node_resource_group": "mc_rg",
}
TARGETS = (("vmware", "rke2"), ("vmware", "kubeadm"), ("aws", "eks"), ("gcp", "gke"), ("azure", "aks"))


def ctx(target="vmware", distro="rke2", fips=False, name="fixcat"):
    env = paths.Env(target, f"{name}{distro}{'f' if fips else ''}")
    env.create_dirs()
    cfg = {"env": env.name, "region": "us-east-1", "network_cidr": "10.100.0.0/24",
           "vars": {"fips_mode": fips, "project_id": "proj", "subscription_id": "sid"}, "platform_prereqs": ["velero", "karpenter"]}
    return pl.Cluster(clouds.get(target), env, cfg, dict(OUTPUTS, kubernetes_distro=distro), env.dir / "kubeconfig")


def args_of(item, c):
    return " ".join(pl._values_args(pl.CATALOG[item], c))


def render(c, name):
    """The manifest exactly as cloudseed writes it before `kubectl apply` (real _apply_manifest, kubectl stubbed)."""
    seen = {}

    def fake_run(cmd, _ctx, check=True):
        if "apply" in cmd and "-f" in cmd:
            seen["path"] = cmd[cmd.index("-f") + 1]
        return 0
    with mock.patch.object(pl, "_run", fake_run), mock.patch.object(pl, "_warn_pool_move"):
        # Cluster inspection is separate from rendering; never query a real kubectl here.
        pl._apply_manifest(c, "kubectl", name, "default", wait_ns=False)
    return Path(seen["path"]).read_text()


def docs_of(text):
    return [d for d in re.split(r"(?m)^---\s*$", text) if d.strip()]


def yaml_lines(text):
    """The YAML structure lines of a manifest: block scalar contents (after `key: |`) are skipped."""
    block = None
    for n, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        if block is not None and (not line.strip() or indent > block):
            continue
        block = indent if re.search(r":\s*[|>][-+]?\s*$", line) or re.match(r"^\s*-\s*[|>][-+]?\s*$", line) else None
        yield n, line


def balanced(line):
    """Flow-style braces/brackets on one YAML line must balance (quoted strings ignored)."""
    line = re.sub(r"'[^']*'|\"(?:[^\"\\\\]|\\\\.)*\"", "", line)
    return line.count("{") == line.count("}") and line.count("[") == line.count("]")


class PostManifestTests(unittest.TestCase):
    def test_manifests_render_without_brace_corruption_on_every_target(self):
        """cert-manager-issuer, the shared Gateway, karpenter and spark-history-server used to lose a '}' in rendering."""
        for target, distro in TARGETS:
            c = ctx(target, distro)
            known = set(c.placeholders())
            for name, raw in pl.POST_MANIFESTS.items():
                self.assertNotIn("{{", raw, name)
                self.assertNotIn("}}", raw, name)
                for token in re.findall(r"\{([a-z_][a-z0-9_]*)\}", raw):
                    self.assertIn(token, known, f"{name}: unknown placeholder {{{token}}}")
                text = render(c, name)
                self.assertNotRegex(text, r"\{[a-z_][a-z0-9_]*\}", f"{name} on {target}: unresolved placeholder")
                for n, line in yaml_lines(text):
                    self.assertTrue(balanced(line), f"{name} on {target} line {n}: {line!r}")
                for doc in docs_of(text):
                    self.assertRegex(doc, r"(?m)^kind: \w+", f"{name} on {target}")

    def test_manifests_parse_as_yaml_when_pyyaml_is_available(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed (structural checks above still ran)")
        import yaml
        for target, distro in (("vmware", "rke2"), ("aws", "eks"), ("azure", "aks")):
            c = ctx(target, distro)
            for name in pl.POST_MANIFESTS:
                docs = [d for d in yaml.safe_load_all(render(c, name)) if d]
                self.assertTrue(docs and all("kind" in d for d in docs), name)

    def test_specific_manifest_shapes(self):
        c = ctx("azure", "aks")
        issuer = render(c, "selfsigned-issuer")
        self.assertIn("spec:\n  selfSigned: {}", issuer)
        azure = render(c, "external-dns-azure-config")
        blob = re.search(r"azure\.json: \|\n\s+(\{.*\})", azure).group(1)
        self.assertEqual(json.loads(blob), {"tenantId": "tid", "subscriptionId": "sid", "resourceGroup": "rg", "useWorkloadIdentityExtension": True})
        gw = render(ctx("aws", "eks"), "cloudseed-gateway")
        self.assertEqual(gw.count("allowedRoutes:\n        namespaces:\n          from: All"), 2)
        karp = render(ctx("aws", "eks"), "karpenter-default")
        self.assertIn('karpenter.sh/discovery: "c1"', karp)
        self.assertIn('role: "knr"', karp)

    def test_strimzi_dev_cluster_uses_the_served_v1_api(self):
        kafka = pl.POST_MANIFESTS["kafka-cluster"]
        self.assertEqual(kafka.count("apiVersion: kafka.strimzi.io/v1\n"), 2)
        self.assertNotIn("v1beta2", kafka)
        self.assertTrue(pl.CATALOG["strimzi"]["version"].startswith("1."))


class PinningTests(unittest.TestCase):
    def test_every_item_installs_a_fixed_release(self):
        for name, spec in pl.CATALOG.items():
            m = spec["method"]
            if m in ("helm", "oci"):
                self.assertRegex(spec.get("version", ""), r"^v?\d+\.\d+\.\d+$", f"{name} is not pinned")
            self.assertNotEqual(m, "git", f"{name}: git items track a moving branch")
            if m == "manifest":
                self.assertNotIn("/latest/", spec["url"], name)
                self.assertRegex(spec["url"], r"/v?\d+\.\d+\.\d+/", name)
            if m == "kustomize":
                for url in (spec["url"], spec.get("then") or spec["url"]):
                    self.assertRegex(url, r"\?ref=v?\d+\.\d+\.\d+$", name)
        self.assertIn("/download/v0.7.1/", pl.CATALOG["kube-green"]["url"])

    def test_istio_charts_move_together(self):
        versions = {pl.CATALOG[n]["version"] for n in ("istio-base", "istiod", "istio-cni", "ztunnel", "istio-gateway")}
        self.assertEqual(len(versions), 1)

    def test_images_in_post_manifests_are_pinned(self):
        for name, raw in pl.POST_MANIFESTS.items():
            for image in re.findall(r"image: (\S+)", raw):
                self.assertNotRegex(image, r":latest$", f"{name}: {image}")
                self.assertIn(":", image, f"{name}: {image} has no tag")


class ItemValueTests(unittest.TestCase):
    def test_velero_service_account_matches_cloud_trust(self):
        tf = {"aws": (REPO / "terraform/aws/modules/kubernetes/main.tf").read_text(),
              "gcp": (REPO / "terraform/gcp/modules/kubernetes/platform.tf").read_text(),
              "azure": (REPO / "terraform/azure/modules/kubernetes/platform.tf").read_text()}
        self.assertIn('velero = { ns = "velero", sa = "velero"', tf["aws"])
        self.assertIn("[velero/velero]", tf["gcp"])
        self.assertIn("system:serviceaccount:velero:velero", tf["azure"])
        for target, distro in (("aws", "eks"), ("gcp", "gke"), ("azure", "aks"), ("vmware", "rke2")):
            a = args_of("velero", ctx(target, distro))
            self.assertIn("serviceAccount.server.name=velero", a, target)
            self.assertRegex(a, r"velero-plugin-for-[a-z-]+:v1\.14\.\d+", target)
            self.assertNotIn("v1.13", a, target)
        self.assertIn("nodeAgent.podLabels.azure\\.workload\\.identity/use=true", args_of("velero", ctx("azure", "aks")))

    def test_aws_load_balancers_are_internal_for_the_cloud_controller(self):
        aws = ctx("aws", "eks")
        self.assertIn('service.beta.kubernetes.io/aws-load-balancer-internal: "true"', aws.placeholders()["lb_annotations"])
        self.assertIn("aws-load-balancer-scheme", aws.placeholders()["lb_annotations"])
        for item in ("ingress-nginx", "istio-gateway"):
            self.assertIn("aws-load-balancer-internal=true", args_of(item, aws), item)

    def test_spark_operator_job_namespaces_is_a_list(self):
        a = args_of("spark-operator", ctx())
        self.assertIn("spark.jobNamespaces[0]=default", a)
        self.assertNotIn("spark.jobNamespaces=", a)

    def test_airflow_creates_the_admin_user_shown_by_platform_ui(self):
        c = ctx()
        a = args_of("airflow", c)
        self.assertIn("createUserJob.defaultUser.password=" + c.placeholders()["airflow_password"], a)
        self.assertIn("createUserJob.defaultUser.username=admin", a)
        self.assertNotIn("webserver.defaultUser", a)
        self.assertGreaterEqual(tuple(int(x) for x in pl.CATALOG["airflow"]["version"].split(".")), (1, 20, 0))

    def test_agentgateway_is_the_real_agentgateway(self):
        ag = pl.CATALOG["agentgateway"]
        self.assertEqual(ag["chart"], "oci://cr.agentgateway.dev/charts/agentgateway")
        self.assertIn("agentgateway-crds", ag["needs"])
        self.assertTrue(pl.CATALOG["agentgateway-crds"]["hidden"])
        self.assertNotIn("values", ag)
        self.assertNotIn("kgateway-crds", pl.CATALOG)

    def test_gitlab_chart_and_cert_manager_key(self):
        self.assertTrue(pl.CATALOG["gitlab"]["version"].startswith("9.11."))
        a = args_of("gitlab", ctx())
        self.assertIn("installCertmanager=false", a)
        self.assertNotIn("certmanager.install", a)
        sets = {e["item"]: e["sets"] for e in pl.plan(["gitlab"], ctx(), releases={})}
        self.assertEqual(sets["gitlab"].get("installCertmanager"), "false")
        self.assertNotIn("certmanager.install", json.dumps(pl.RULES))
        self.assertTrue(pl.CATALOG["gitlab-runner"]["version"].startswith("0.88."))   # runner 18.11 = GitLab 18.11

    def test_sonarqube_community_build(self):
        a = args_of("sonarqube", ctx())
        self.assertIn("community.enabled=true", a)
        self.assertNotIn("edition=", a)
        self.assertIn("monitoringPasscode=", a)

    def test_kubecost_standalone_2_8_with_cluster_id(self):
        self.assertTrue(pl.CATALOG["kubecost-cost-analyzer"]["version"].startswith("2.8."))
        a = args_of("kubecost-cost-analyzer", ctx())
        self.assertIn("prometheus.server.global.external_labels.cluster_id=c1", a)

    def test_artifactory_keys_come_from_a_secret(self):
        c = ctx()
        spec = pl.CATALOG["artifactory"]
        self.assertIn("artifactory-keys", spec["pre"])
        a = args_of("artifactory", c)
        self.assertIn("global.masterKeySecretName=artifactory-mandatory-keys", a)
        self.assertIn("global.joinKeySecretName=artifactory-mandatory-keys", a)
        ph = c.placeholders()
        for key in ("artifactory_master_key", "artifactory_join_key"):
            self.assertRegex(ph[key], r"^[0-9a-f]{64}$")
            self.assertNotIn(ph[key], a)
        self.assertEqual(ph["artifactory_master_key"], c.placeholders()["artifactory_master_key"])   # stable across --upgrade
        text = render(c, "artifactory-keys")
        self.assertIn(f'master-key: "{ph["artifactory_master_key"]}"', text)

    def test_nexus_admin_password_is_applied(self):
        c = ctx()
        self.assertIn("nexus-root-password", pl.CATALOG["nexus"]["pre"])
        a = args_of("nexus", c)
        self.assertIn("rootPassword.secret=nexus-root-password", a)
        self.assertNotIn("rootPassword.value", a)
        self.assertIn(f'password: "{c.placeholders()["nexus_password"]}"', render(c, "nexus-root-password"))

    def test_langfuse_gets_the_clickhouse_operator_it_needs(self):
        self.assertIn("clickhouse-operator-official", pl.CATALOG["langfuse"]["needs"])
        op = pl.CATALOG["clickhouse-operator-official"]
        self.assertEqual(op["chart"], "oci://ghcr.io/clickhouse/clickhouse-operator-helm")
        order = pl.resolve(["langfuse"], ctx("aws", "eks"))
        self.assertLess(order.index("cert-manager"), order.index("clickhouse-operator-official"))
        self.assertLess(order.index("clickhouse-operator-official"), order.index("langfuse"))
        self.assertNotIn("langfuse", pl.RULES)

    def test_litellm_and_kubeflow_pipelines_moved_off_deleted_images(self):
        self.assertNotEqual(pl.CATALOG["litellm"]["version"], "0.1.499")
        self.assertIn("postgresql.auth.password=", args_of("litellm", ctx()))
        kfp = pl.CATALOG["kubeflow-pipelines"]
        self.assertTrue(kfp["url"].endswith("?ref=2.17.2") and kfp["then"].endswith("?ref=2.17.2"))
        self.assertIn("SeaweedFS", kfp["notes"])
        self.assertEqual(pl.RULES["kubeflow-pipelines"], {"overlaps": ["minio"]})

    def test_llm_d_archived_chart_is_gone(self):
        self.assertNotIn("llm-d", pl.CATALOG)
        self.assertNotIn("llm-d", pl.GROUPS["ai"])

    def test_istio_cni_uses_rke2_paths(self):
        rke2 = args_of("istio-cni", ctx("vmware", "rke2"))
        self.assertNotIn("global.platform=k3s", rke2)
        self.assertIn("cni.cniBinDir=/opt/cni/bin", rke2)
        self.assertIn("cni.cniConfDir=/etc/cni/net.d", rke2)
        self.assertIn("global.platform=gke", args_of("istio-cni", ctx("gcp", "gke")))

    def test_kured_reboot_window_is_not_dropped(self):
        a = pl._values_args(pl.CATALOG["kured"], ctx())
        days = [x.split("=", 1)[1] for x in a if x.startswith("configuration.rebootDays[")]
        self.assertEqual(days, ["mon", "tue", "wed", "thu", "fri"])

    def test_descheduler_interval_applies_to_deployment_mode(self):
        a = args_of("descheduler", ctx())
        self.assertIn("kind=Deployment", a)
        self.assertIn("deschedulingInterval=30m", a)
        self.assertNotIn("schedule=", a)

    def test_minio_has_no_default_console_user(self):
        self.assertIn("users=null", args_of("minio", ctx()))

    def test_polaris_is_the_released_chart_backed_by_postgres(self):
        p = pl.CATALOG["polaris"]
        self.assertEqual((p["method"], p["version"]), ("helm", "1.7.0"))
        self.assertIn("polaris-db", p["pre"])
        a = args_of("polaris", ctx())
        self.assertIn("persistence.type=relational-jdbc", a)
        self.assertIn("extraInitContainers[0].image=apache/polaris-admin-tool:1.7.0", a)
        db = render(ctx(), "polaris-db")
        self.assertIn("kind: Cluster", db)
        self.assertIn("POLARIS,root," + ctx().placeholders()["polaris_password"], db)
        self.assertNotIn("Polaris, Airflow", pl.CATALOG["cloudnative-pg"]["desc"])

    def test_loki_replaces_the_deprecated_stack(self):
        loki = pl.CATALOG["loki"]
        self.assertEqual(loki["chart"], "loki")
        self.assertIn("alloy", loki["needs"])
        a = args_of("loki", ctx())
        self.assertIn("deploymentMode=SingleBinary", a)
        self.assertIn("singleBinary.persistence.enabled=true", a)
        self.assertIn("isDefault: false", pl.POST_MANIFESTS["loki-datasource"])
        self.assertIn("alloy-logs-config", pl.CATALOG["alloy"]["pre"])
        self.assertIn("loki.monitoring.svc:3100/loki/api/v1/push", pl.POST_MANIFESTS["alloy-logs-config"])
        order = pl.resolve(["basek8s"], ctx())
        self.assertLess(order.index("alloy"), order.index("loki"))
        self.assertIn("local-path-provisioner", loki["needs_by_target"]["vmware"])


class SparkHistoryAndMinioTests(unittest.TestCase):
    def test_history_server_has_s3a_jars(self):
        m = pl.POST_MANIFESTS["spark-history-server"]
        self.assertIn("hadoop-aws-3.3.4.jar", m)
        self.assertIn("aws-java-sdk-bundle-1.12.262.jar", m)
        self.assertIn('SPARK_DAEMON_CLASSPATH\n              value: "/extra-jars/*"', m)
        self.assertEqual(pl.CATALOG["spark-history-server"]["probe"], ["deployment", "spark-history-server", "spark-operator"])

    def test_minio_credentials_only_in_secrets(self):
        c = ctx()
        ph = c.placeholders()
        for name in ("spark-history-server", "velero-minio-credentials", "velero-minio-bucket"):
            raw = pl.POST_MANIFESTS[name]
            self.assertNotIn("{minio_password}", raw, name)
            for doc in docs_of(render(c, name)):
                for secret in (ph["minio_password"], ph["minio_spark_password"], ph["minio_velero_password"]):
                    if secret in doc:
                        self.assertRegex(doc, r"(?m)^kind: Secret$", f"{name}: a password outside a Secret")
        creds = render(c, "velero-minio-credentials")
        self.assertIn("aws_access_key_id = velero", creds)
        for name in ("spark-history-server", "velero-minio-bucket"):
            text = pl.POST_MANIFESTS[name]
            self.assertRegex(text, r"kind: Job\nmetadata: \{name: [a-z0-9-]+, namespace: minio\}")   # awaited by _apply_manifest
            self.assertIn("name: minio\n                  key: rootPassword", text)
        self.assertNotIn("secret.key", pl.POST_MANIFESTS["spark-history-server"])


class UiTests(unittest.TestCase):
    def test_ui_services_match_the_charts(self):
        self.assertEqual(pl.UIS["mlflow"][1:3], ("mlflow", 80))
        self.assertEqual(pl.UIS["litmus"][1], "litmus-frontend-service")
        self.assertEqual(pl.UIS["artifactory"][1:3], ("artifactory", 8082))
        self.assertEqual(pl.UIS["neuvector"][3], "http")
        self.assertIn("manager.env.ssl=false", args_of("neuvector", ctx()))
        for item in pl.UIS:
            self.assertIn(item, pl.CATALOG)


class StepOverTests(unittest.TestCase):
    def test_harbor_keeps_its_scanner_and_open_webui_uses_the_shared_ollama(self):
        by = {e["item"]: e for e in pl.plan(["trivy-operator", "harbor"], ctx(), releases={})}
        self.assertNotIn("trivy.enabled", by["harbor"]["sets"])
        by = {e["item"]: e for e in pl.plan(["ollama", "open-webui"], ctx(), releases={})}
        self.assertEqual(by["open-webui"]["sets"]["ollama.enabled"], "false")
        self.assertIn("ollama.ollama.svc", by["open-webui"]["sets"]["ollamaUrls[0]"])

    def test_one_kmcp_controller(self):
        self.assertIn("kagent-crds", pl.CATALOG["kmcp"]["needs"])
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-x"}):
            by = {e["item"]: e for e in pl.plan(["agentic"], ctx(), releases={})}
        self.assertEqual(by["kagent"]["sets"].get("kmcp.enabled"), "false")
        self.assertEqual([e["item"] for e in pl.plan(["agentic"], ctx(), releases={})].count("kagent-crds"), 1)

    def test_scaling_pulls_in_metrics_server(self):
        order = pl.resolve(["scaling"], ctx("aws", "eks"))
        self.assertLess(order.index("metrics-server"), order.index("vpa"))
        by = {e["item"]: e["action"] for e in pl.plan(["goldilocks"], ctx("vmware", "rke2"), releases={})}
        self.assertEqual(by["metrics-server"], "skip-provided")

    def test_security_group_brings_the_dev_ca(self):
        self.assertIn("cert-manager-issuer", pl.resolve(["security"], ctx()))


class RequiredInputTests(unittest.TestCase):
    def setUp(self):
        self.clean = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITLAB_RUNNER_TOKEN")}

    def test_kagent_without_a_model_key_is_skipped_with_a_hint(self):
        with mock.patch.dict(os.environ, self.clean, clear=True):
            by = {e["item"]: e for e in pl.plan(["kagent"], ctx(), releases={})}
            self.assertEqual(by["kagent"]["action"], "skip-missing-input")
            self.assertIn("ANTHROPIC_API_KEY or OPENAI_API_KEY", by["kagent"]["reasons"][0])
            self.assertEqual({e["item"]: e for e in pl.plan(["kagent"], ctx(), releases={}, force=True)}["kagent"]["action"], "install")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pl.print_plan(list(by.values()), ctx())
            self.assertIn("needs input", buf.getvalue())

    def test_kagent_uses_whichever_provider_has_a_key(self):
        with mock.patch.dict(os.environ, dict(self.clean, OPENAI_API_KEY="sk-openai-x"), clear=True):
            a = args_of("kagent", ctx())
            self.assertIn("providers.default=openAI", a)
            self.assertIn("providers.openAI.apiKey=sk-openai-x", a)
            self.assertEqual({e["item"]: e for e in pl.plan(["kagent"], ctx(), releases={})}["kagent"]["action"], "install")
        with mock.patch.dict(os.environ, dict(self.clean, ANTHROPIC_API_KEY="sk-ant-x", OPENAI_API_KEY="sk-openai-x"), clear=True):
            self.assertIn("providers.default=anthropic", args_of("kagent", ctx()))

    def test_devsecops_group_finishes_without_a_runner_token(self):
        with mock.patch.dict(os.environ, self.clean, clear=True):
            by = {e["item"]: e for e in pl.plan(["devsecops"], ctx(), releases={})}
            self.assertEqual(by["gitlab-runner"]["action"], "skip-missing-input")
            self.assertEqual(by["gitlab"]["action"], "install")
        with mock.patch.dict(os.environ, dict(self.clean, GITLAB_RUNNER_TOKEN="glrt-x"), clear=True):
            self.assertEqual({e["item"]: e for e in pl.plan(["gitlab-runner"], ctx(), releases={})}["gitlab-runner"]["action"], "install")

    def test_info_names_the_required_credentials(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pl.info("kagent", None)
        self.assertIn("ANTHROPIC_API_KEY or OPENAI_API_KEY", buf.getvalue())


class FipsTierTests(unittest.TestCase):
    def test_tls_terminators_are_tls_restricted_and_say_so(self):
        for item in ("envoy-gateway", "ingress-nginx"):
            self.assertEqual(pl.CATALOG[item]["fips"], "tls-restricted", item)
        by = {e["item"]: e for e in pl.plan(["envoy-gateway"], ctx("aws", "eks", fips=True), releases={})}
        self.assertEqual(by["envoy-gateway"]["action"], "install")
        self.assertTrue(any("not a FIPS-validated module" in r for r in by["envoy-gateway"]["reasons"]))
        by = {e["item"]: e for e in pl.plan(["envoy-gateway"], ctx("aws", "eks"), releases={})}
        self.assertFalse(any("FIPS" in r for r in by["envoy-gateway"]["reasons"]))
        self.assertEqual(pl.CATALOG["alloy"]["fips"], "compatible")

    def test_scan_fips_does_not_pass_the_tls_terminators(self):
        """`cs scan fips` used to report envoy-gateway / ingress-nginx as PASS 'FIPS-compatible'."""
        import subprocess
        from cloudseed import scan
        c = ctx("aws", "eks", fips=True)
        rel = {"envoy-gateway-system/eg": {"status": "deployed"}, "ingress-nginx/ingress-nginx": {"status": "deployed"},
               "kube-system/metrics-server": {"status": "deployed"}}
        saved = {}

        def save(_env, kind, report):
            saved[kind] = report
            return Path(os.devnull)
        with mock.patch.object(scan, "_hosts", return_value=[]), mock.patch.object(pl, "installed_releases", return_value=rel), \
                mock.patch.object(scan, "_kubectl", return_value=subprocess.CompletedProcess([], 1, "", "")), \
                mock.patch.object(scan, "save_report", save), contextlib.redirect_stdout(io.StringIO()):
            scan.fips(c.cloud, c.env, c.cfg, c.outputs, ctx=c)
        checks = {x["check"].split(":")[0]: x for x in saved["fips"]["checks"] if x["area"] == "platform"}
        for item in ("envoy-gateway", "ingress-nginx"):
            self.assertEqual(checks[item]["status"], "FAIL", item)
            self.assertIn("not FIPS-validated", checks[item]["check"])
        self.assertEqual(checks["metrics-server"]["status"], "PASS")


class ProbeAndStateTests(unittest.TestCase):
    def test_release_less_items_have_probes(self):
        for item in ("kubeflow-trainer", "kubeflow-pipelines", "spark-history-server", "istio"):
            spec = pl.CATALOG[item]
            self.assertIn("probe", spec, item)
            self.assertTrue(pl._already_installed(spec, item, {"probe:" + item: {"status": "present"}}), item)
            self.assertFalse(pl._already_installed(spec, item, {}), item)

    def test_install_one_skips_an_installed_probe_item_without_crashing(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), mock.patch.object(pl, "_run", side_effect=AssertionError("must not run anything")):
            pl.install_one("cert-manager-issuer", ctx(), wait=False, releases={"probe:cert-manager-issuer": {"status": "present", "chart": "clusterissuer/cloudseed-ca"}})
        self.assertIn("already installed", buf.getvalue())


class TemplateTests(unittest.TestCase):
    def test_gitlab_ci_images_are_pinned_and_argocd_matches_the_catalog(self):
        text = (REPO / "templates/gitlab-ci/.gitlab-ci.yml").read_text()
        self.assertNotIn(":latest", text)
        self.assertNotIn("argoproj/argocd:latest", text)
        tag = re.search(r"quay\.io/argoproj/argocd:(v[\d.]+)", text).group(1)
        # argo-cd chart -> Argo CD version it ships; the CI CLI must be bumped together with the chart
        self.assertEqual({"10.9.2": "v3.5.3"}.get(pl.CATALOG["argocd"]["version"]), tag)


if __name__ == "__main__":
    unittest.main()
