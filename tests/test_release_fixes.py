"""Regression tests for the fixes found by the live scenario run (docs/scenarios, tests/scenarios): MinIO images that
can be pulled, Terraform outputs that cannot be read (never blamed on the VMs), no shared plugin cache for the local
VMware provider, `vpn connect` with Tailscale before the subnet router exists, undo entries that name the changed
variables, MCP descriptions that say how to estimate a new environment, troubleshoot treating an approval stop
(exit 3) as what it is, a local cluster that is only reported ready once every node is Ready, and velero commands
that run in the Velero server pod, never a node-agent pod. Offline, stdlib only."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, deps, dr, mcp, paths, services, tf, troubleshoot, ui, undo  # noqa: E402
from cloudseed import help as helpmod  # noqa: E402
from cloudseed import platform as pl  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def _name(prefix: str) -> str:
    """An environment name no earlier run (in a reused CLOUDSEED_HOME) can have used."""
    return f"{prefix}{uuid.uuid4().hex[:8]}"


@contextlib.contextmanager
def _captured():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


LOCK_MISMATCH_ERR = (
    "╷\n│ Error: Required plugins are not installed\n│ \n│ The installed provider plugins are not consistent with the "
    "packages selected\n│ in the dependency lock file:\n│   - registry.local/cloudseed/vmdesktop: the cached package for "
    "registry.local/cloudseed/vmdesktop 0.1.0 (in .terraform/providers) does not match any of the checksums recorded "
    "in the dependency lock file\n╵\n")


def _local_root() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "main.tf.json").write_text(json.dumps({"terraform": {"required_providers": {"vmdesktop": {"source": tf.LOCAL_PROVIDER}}}}))
    return root


def _cloud_root() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "main.tf.json").write_text(json.dumps({"terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}}}))
    return root


def _tf(workdir: Path) -> tf.Terraform:
    t = tf.Terraform.__new__(tf.Terraform)
    t.workdir, t.binary = workdir, "terraform"
    return t


# ---------------------------------------------------------------------------------------------------- (1) MinIO images

class MinioImageTests(unittest.TestCase):
    def _ctx(self):
        env = paths.Env("vmware", _name("rfminio"))
        env.create_dirs()
        cfg = {"env": env.name, "region": "", "network_cidr": "10.100.0.0/24", "vars": {"fips_mode": False}}
        return pl.Cluster(clouds.get("vmware"), env, cfg, {"kubernetes_distro": "rke2", "kubernetes_cluster_name": "c1"},
                          env.dir / "k8s" / "kubeconfig")

    def test_server_and_client_images_are_the_public_pgsty_builds(self):
        args = " ".join(pl._values_args(pl.CATALOG["minio"], self._ctx()))
        self.assertEqual(pl.MINIO_IMAGE[0], "docker.io/pgsty/minio")
        self.assertEqual(pl.MINIO_MC_IMAGE[0], "docker.io/pgsty/mc")
        for repo, tag in (pl.MINIO_IMAGE, pl.MINIO_MC_IMAGE):
            self.assertRegex(tag, r"^RELEASE\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$")   # a pinned release, never latest
        self.assertIn(f"image.repository={pl.MINIO_IMAGE[0]}", args)
        self.assertIn(f"image.tag={pl.MINIO_IMAGE[1]}", args)
        self.assertIn(f"mcImage.repository={pl.MINIO_MC_IMAGE[0]}", args)
        self.assertIn(f"mcImage.tag={pl.MINIO_MC_IMAGE[1]}", args)

    def test_bucket_jobs_run_the_same_client_image(self):
        ctx = self._ctx()
        image = ":".join(pl.MINIO_MC_IMAGE)
        for name in ("velero-minio-bucket", "spark-history-server"):
            text = pl.render_manifest(name, ctx)
            self.assertIn(f"image: {image}", text, name)
            for other in re.findall(r"image: (\S+)", text):               # every MinIO client image there is this one
                if "minio" in other or re.search(r"/mc[:@]", other):
                    self.assertEqual(other, image, name)

    def test_no_minio_image_that_answers_401(self):
        # quay.io/minio/* and docker.io/minio/* refuse anonymous pulls for every tag: a pod on them never starts.
        # Everything the catalog deploys: chart values of every item and target, and every manifest
        bad = re.compile(r"(?:quay\.io|docker\.io)/minio/|(?<![\w./-])minio/(?:minio|mc):")
        for item, spec in pl.CATALOG.items():
            for target, values in (spec.get("values") or {}).items():
                for key, value in values.items():
                    self.assertNotRegex(f"{key}={value}", bad, f"{item} ({target})")
        for name, text in pl.POST_MANIFESTS.items():
            self.assertNotRegex(text, bad, name)


# ------------------------------------------------------------------- (2) terraform outputs that cannot be read

class OutputsErrorTests(unittest.TestCase):
    def test_a_failed_output_read_is_shown_and_explained(self):
        t = _tf(_local_root())
        with mock.patch.object(tf.Terraform, "run", return_value=_cp(1, "", LOCK_MISMATCH_ERR)), \
                mock.patch.object(tf.audit, "write") as write, _captured() as out:
            self.assertEqual(t.outputs(), {})
        self.assertTrue(t.outputs_error.startswith("terraform output failed:"), t.outputs_error)
        self.assertIn("checksums", out.getvalue())                                   # terraform's own words, shown
        self.assertIn("Could not read the Terraform outputs", out.getvalue())
        self.assertIn("does not match any of the checksums", "".join(c.args[0] for c in write.call_args_list))

    def test_json_that_is_not_outputs_is_an_error_too(self):
        t = _tf(_cloud_root())
        with mock.patch.object(tf.Terraform, "run", return_value=_cp(0, "not json")), _captured():
            self.assertEqual(t.outputs(), {})
        self.assertTrue(t.outputs_error)

    def test_a_good_read_clears_the_error(self):
        t = _tf(_cloud_root())
        t.outputs_error = "old"
        with mock.patch.object(tf.Terraform, "run", return_value=_cp(0, json.dumps({"bastion_public_ip": {"value": "1.2.3.4"}}))):
            self.assertEqual(t.outputs(), {"bastion_public_ip": "1.2.3.4"})
        self.assertIsNone(t.outputs_error)

    def test_cached_outputs_survive_a_failed_read(self):
        env = paths.Env("vmware", _name("rfout"))
        env.create_dirs()
        (env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.4"}))
        t = _tf(_local_root())
        with mock.patch.object(tf.Terraform, "run", return_value=_cp(1, "", LOCK_MISMATCH_ERR)), _captured():
            self.assertEqual(cli._cache_outputs(env, t), {})
        self.assertEqual(json.loads((env.dir / "outputs.json").read_text()), {"bastion_public_ip": "192.0.2.4"})
        self.assertTrue(env.outputs_error)

    def test_no_bastion_ip_does_not_blame_the_vm_when_terraform_failed(self):
        env = paths.Env("vmware", _name("rfip"))
        env.create_dirs()
        env.outputs_error = "terraform output failed: The provider packages in .terraform no longer match"
        msg = cli._no_bastion_ip(clouds.get("vmware"), env, refreshed=True)
        self.assertNotIn("reported no address", msg)
        self.assertIn("could not read the outputs", msg)
        self.assertIn("no longer match", msg)
        self.assertIn(f"cloudseed provision vmware --env {env.name}", msg)
        env.outputs_error = None                         # outputs that were read: the VM message is right again
        (env.stack_dir).mkdir(parents=True, exist_ok=True)
        (env.stack_dir / "terraform.tfstate").write_text(json.dumps({"resources": [{"mode": "managed"}]}))
        self.assertIn("reported no address", cli._no_bastion_ip(clouds.get("vmware"), env, refreshed=True))

    def test_finish_after_an_apply_whose_outputs_cannot_be_read(self):
        env = paths.Env("vmware", _name("rffin"))
        env.create_dirs()
        cfg = {"env": env.name, "cloud": "vmware", "vars": {}}
        t = _tf(_local_root())

        def run(self_, *args, **kw):
            return _cp(1, "", LOCK_MISMATCH_ERR)
        with mock.patch.object(tf.Terraform, "run", run), _captured() as out:
            cli._finish(clouds.get("vmware"), env, cfg, t, explain_missing_ip=True)
        text = out.getvalue()
        self.assertNotIn("No outputs yet", text)
        self.assertNotIn("reported no address", text)
        self.assertIn("could not read the outputs", text)
        self.assertIn("its outputs could not be read", text)
        # the inventory does not claim "0 resources (nothing deployed)" for a state it could not read
        last = audit.load(env)["history"][-1]
        self.assertEqual(last["action"], "apply")
        self.assertNotIn("resources", last)
        self.assertIn("Required plugins are not installed", last["state_unreadable"])

    def test_an_unreadable_state_keeps_the_inventory(self):
        env = paths.Env("aws", _name("rfinv"))
        env.create_dirs()
        audit.save(env, {"history": [{"at": "x", "action": "apply", "resources": 3}],
                         "current": {"resources": [{"type": "aws_vpc", "mode": "managed"}], "count": 1, "updated_at": "x"}})
        fake = mock.Mock()
        fake.run.return_value = _cp(1, "", "Error: Failed to load plugin schemas\n")
        audit.refresh(env, fake, "apply")
        inv = audit.load(env)
        self.assertEqual(inv["current"]["count"], 1)                                  # what it knew stays
        self.assertEqual(inv["history"][-1]["state_unreadable"], "Error: Failed to load plugin schemas")
        self.assertTrue(cli._env_has_resources(env))                                   # the older count still counts


class PluginCacheTests(unittest.TestCase):
    def test_local_provider_roots_never_use_a_shared_plugin_cache(self):
        home = Path(tempfile.mkdtemp())
        (home / "terraform.rc").write_text('provider_installation {\n  filesystem_mirror {\n    path = "/p"\n'
                                          '    include = ["registry.local/*/*"]\n  }\n}\n')
        user_rc = home / "user.rc"
        user_rc.write_text('plugin_cache_dir = "/shared/cache"\ndisable_checkpoint = true\n')
        with mock.patch.object(tf.paths, "HOME", home), \
                mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/shared/cache", "TF_CLI_CONFIG_FILE": str(user_rc)}):
            vm, cloud = _tf(_local_root()), _tf(_cloud_root())
            self.assertNotIn("TF_PLUGIN_CACHE_DIR", vm._env())
            self.assertEqual(cloud._env()["TF_PLUGIN_CACHE_DIR"], "/shared/cache")     # cloud roots keep the cache
            merged = Path(vm._env()["TF_CLI_CONFIG_FILE"]).read_text()
        self.assertIsNone(re.search(r"(?m)^\s*plugin_cache_dir", merged), merged)      # the user's setting, commented out
        self.assertIn("# not for cloudseed's VMware roots", merged)
        self.assertIn("disable_checkpoint = true", merged)                              # everything else stays
        self.assertIn("registry.local", merged)

    def test_hints_for_a_local_root_do_not_blame_a_cache_it_does_not_use(self):
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/shared/cache"}):
            local = tf.explain(LOCK_MISMATCH_ERR, "output", _local_root())
            cloud = tf.explain(LOCK_MISMATCH_ERR, "output", _cloud_root())
        self.assertNotIn("/shared/cache", local)
        self.assertIn("/shared/cache", cloud)


# --------------------------------------------------------------------------- (3) vpn connect with Tailscale

class TailscaleConnectTests(unittest.TestCase):
    def _env(self):
        env = paths.Env("gcp", _name("rfts"))
        env.create_dirs()
        cfg = {"env": env.name, "cloud": "gcp", "vars": {"enable_vpn": True, "vpn_type": "tailscale"}}
        return env, cfg

    def test_no_subnet_router_yet_refuses_before_touching_tailscale(self):
        env, cfg = self._env()
        with mock.patch.object(services.deps, "find", return_value="/usr/bin/tailscale"), \
                mock.patch.object(services.subprocess, "call") as call, mock.patch.object(services.subprocess, "run") as run:
            with self.assertRaises(ui.Abort) as cm:
                services.connect(clouds.get("gcp"), env, cfg, {"vpn_type": "tailscale"}, None)
        self.assertIn("not created yet", cm.exception.msg)
        call.assert_not_called()
        run.assert_not_called()

    def test_without_a_terminal_a_logged_out_tailscale_is_refused(self):
        env, cfg = self._env()
        outputs = {"vpn_type": "tailscale", "vpn_public_ip": "203.0.113.9"}
        status = _cp(0, json.dumps({"BackendState": "NeedsLogin"}))
        with mock.patch.object(services.deps, "find", return_value="/usr/bin/tailscale"), \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.subprocess, "run", return_value=status), \
                mock.patch.object(services.subprocess, "call") as call:
            with self.assertRaises(ui.Abort) as cm:
                services.connect(clouds.get("gcp"), env, cfg, outputs, None)
        self.assertIn("not logged in", cm.exception.msg)
        call.assert_not_called()

    def test_without_a_terminal_tailscale_up_gets_a_timeout(self):
        env, cfg = self._env()
        outputs = {"vpn_type": "tailscale", "vpn_public_ip": "203.0.113.9"}
        status = _cp(0, json.dumps({"BackendState": "Stopped"}))
        with mock.patch.object(services.deps, "find", return_value="/usr/bin/tailscale"), \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.subprocess, "run", return_value=status), \
                mock.patch.object(services.subprocess, "call", return_value=0) as call, _captured():
            self.assertEqual(services.connect(clouds.get("gcp"), env, cfg, outputs, None), 0)
        cmd = call.call_args.args[0]
        self.assertEqual(cmd[:3], ["/usr/bin/tailscale", "up", "--accept-routes"])
        self.assertIn(f"--timeout={services.TAILSCALE_UP_TIMEOUT}s", cmd)
        self.assertIsNotNone(call.call_args.kwargs.get("timeout"))

    def test_a_hung_tailscale_up_is_stopped(self):
        env, cfg = self._env()
        outputs = {"vpn_type": "tailscale", "vpn_public_ip": "203.0.113.9"}
        with mock.patch.object(services.deps, "find", return_value="/usr/bin/tailscale"), \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.subprocess, "run", return_value=_cp(1, "")), \
                mock.patch.object(services.subprocess, "call", side_effect=subprocess.TimeoutExpired("tailscale", 90)), _captured():
            with self.assertRaises(ui.Abort) as cm:
                services.connect(clouds.get("gcp"), env, cfg, outputs, None)
        self.assertIn("did not finish", cm.exception.msg)


# ------------------------------------------------------------------------ (4) undo entries name the variables

class ChangedSettingsTests(unittest.TestCase):
    def test_variables_are_named(self):
        self.assertEqual(cli._changed_settings({"vars": {"workload_count": 0, "a": 1}}, {"vars": {"workload_count": 1, "a": 1}}),
                         ["workload_count"])
        self.assertEqual(cli._changed_settings({"extra_vars": {}}, {"extra_vars": {"single_nat_gateway": True}}),
                         ["single_nat_gateway"])
        self.assertEqual(cli._changed_settings({"region": "a", "vars": {"x": 1}}, {"region": "b", "vars": {"x": 2, "y": 3}}),
                         ["region", "x", "y"])

    def test_unset_values_are_no_change(self):
        self.assertEqual(cli._changed_settings({"vars": {"x": None}}, {"vars": {}}), [])
        self.assertEqual(cli._changed_settings({"vars": {"x": ""}}, {}), [])
        self.assertEqual(cli._changed_settings({"vars": {"n": 0}}, {"vars": {}}), ["n"])      # 0 is a value
        self.assertEqual(cli._changed_settings({"updated_at": "a", "vars": {}}, {"updated_at": "b", "vars": {}}), [])


# ------------------------------------------------------------------------------ (5) MCP: estimate a new environment

class McpEstimateTests(unittest.TestCase):
    def test_descriptions_say_a_dry_run_comes_first(self):
        finops, setup = mcp.TOOLS["cloudseed_finops"]["description"], mcp.TOOLS["cloudseed_setup"]["description"]
        self.assertIn("cloudseed_setup with dry_run=true first", finops)
        self.assertIn("dry_run=true first", setup)
        self.assertIn("cloudseed_finops action=estimate", setup)
        skill = (REPO / "skills" / "cloudseed-finops" / "SKILL.md").read_text()
        self.assertIn("--dry-run", skill)
        self.assertIn("dry_run=true", skill)


# -------------------------------------------------------------------- (6) troubleshoot and approval stops (exit 3)

def _rec(argv, rc, log=None):
    return {"argv": argv, "command": argv[0], "exit_code": rc, "log": log, "at": "2026-01-01T00:00:00Z", "duration_s": 1}


class ApprovalStopTests(unittest.TestCase):
    DIAG = {"troubleshoot", "inventory", "status", "output", "doctor", "help", "list", "explain"}

    def test_exit_3_is_not_a_failure(self):
        runs = [_rec(["setup", "vmware", "--env", "lab"], 0), _rec(["undo", "vmware", "--env", "lab"], 3)]
        self.assertEqual(troubleshoot._pick_failure(runs, self.DIAG), (None, None, []))
        runs = [_rec(["apply", "aws", "--env", "dev"], 1), _rec(["apply", "aws", "--env", "dev"], 3)]
        self.assertIs(troubleshoot._pick_failure(runs, self.DIAG)[0], runs[0])     # a stop settles nothing

    def test_run_reports_the_stop_as_waiting_for_approval(self):
        env = paths.Env("aws", _name("rfts"))
        env.create_dirs()
        runs = [_rec(["setup", "aws", "--env", env.name], 0), _rec(["undo", "aws", "--env", env.name], 3)]
        (env.dir / "logs" / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs))
        with mock.patch.object(deps, "missing", lambda c: ([], [])), mock.patch.object(deps, "live_credential_check", lambda c: None), \
                _captured() as out:
            troubleshoot.run(clouds.get("aws"), env, {"vars": {}}, last=10)
        text = " ".join(re.sub(r"[│╭╮╰╯─]", " ", out.getvalue()).split())      # the findings panel wraps its lines
        self.assertIn("failed: 0", text)
        self.assertIn("stopped for approval: 1", text)
        self.assertNotIn("An earlier run failed", text)
        self.assertNotIn("The last failed run", text)
        self.assertIn("stopped for approval (exit 3): nothing was changed", text)


class ClusterReadyTests(unittest.TestCase):
    """The live run of scenario 05 saw `cs setup vmware --var enable_kubernetes=true` end ("vmware-lab is ready") two
    seconds after the last worker joined, so `kubectl get nodes` showed it NotReady. The playbook now waits."""

    def setUp(self):
        self.k8s = (REPO / "ansible" / "kubernetes.yml").read_text()
        self.last_play = self.k8s[self.k8s.rindex("\n- name: "):]

    def _wait_task(self) -> str:
        m = re.search(r"^    - name: Every node is registered and Ready\n(.*?)(?=^    - name: |\Z)", self.last_play, re.M | re.S)
        self.assertIsNotNone(m, "the last play waits for the nodes")
        return m.group(0)

    def test_the_last_play_waits_for_every_node_to_be_ready(self):
        self.assertIn("hosts: control_plane[0]", self.last_play)
        task = self._wait_task()
        self.assertIn("{{ node_kubectl }} wait --for=condition=Ready", task)
        self.assertIn("groups['k8s']", task)                              # every node of the inventory
        self.assertIn("map('lower')", task)                               # node names are lower-case hostnames
        self.assertIn("changed_when: false", task)

    def test_node_add_waits_only_for_the_nodes_it_installs(self):
        task = self._wait_task()
        self.assertIn("query('inventory_hostnames', ansible_limit)", task)
        self.assertIn("if ansible_limit is defined else groups['k8s']", task)

    def test_the_wait_has_a_deadline_and_says_what_is_not_ready(self):
        task = self._wait_task()
        self.assertIn("k8s_ready_timeout | default(600)", task)
        self.assertIn("exit 1", task)
        self.assertIn("get nodes -o wide >&2", task)

    def test_it_comes_after_the_kubeconfig_and_version_are_written(self):
        order = [self.last_play.index(n) for n in ("- name: Write kubeconfig locally", "- name: Record it for cloudseed",
                                                   "- name: Every node is registered and Ready")]
        self.assertEqual(order, sorted(order))


class VeleroServerTargetTests(unittest.TestCase):
    """The live run of scenario 08: `cs dr describe backup before-change --details` ran `kubectl exec deploy/velero -c
    velero` and kubectl picked a node-agent pod ("container velero is not valid for pod node-agent-..."): the chart's
    Deployment selector matches the node-agent DaemonSet's pods too. The velero Service's selector does not."""

    def _ctx(self):
        env = paths.Env("vmware", _name("rfvel"))
        env.create_dirs()
        cfg = {"env": env.name, "name": "t", "region": "", "network_cidr": "10.100.0.0/24", "vars": {}}
        return pl.Cluster(clouds.get("vmware"), env, cfg, {"kubernetes_distro": "rke2"}, env.dir / "k8s" / "kubeconfig")

    def test_the_server_is_reached_through_its_service(self):
        self.assertEqual(dr.SERVER, "svc/velero")
        # the Service is the metrics Service: the catalog must keep it
        self.assertEqual(pl.CATALOG["velero"]["values"]["default"]["metrics.enabled"], "true")
        for mod in (dr, undo):
            src = Path(mod.__file__).read_text()
            self.assertNotIn('"exec", "deploy/velero"', src, mod.__name__)
            self.assertNotIn("'logs', 'deploy/velero'", src, mod.__name__)

    def test_describe_with_in_cluster_storage_execs_in_the_server_pod(self):
        ctx = self._ctx()
        calls = []
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "in_cluster_storage", return_value=True), \
                mock.patch.object(dr, "kubectl_path", return_value="kubectl"), mock.patch.object(dr.audit, "write"), \
                mock.patch.object(dr.subprocess, "call", lambda cmd, env=None: calls.append(list(cmd)) or 0), _captured() as out:
            self.assertEqual(dr.show(ctx, "describe", "backup", "before-change", details=True), 0)
        self.assertEqual(calls, [["kubectl", "-n", "velero", "exec", "svc/velero", "-c", "velero", "--", "/velero", "-n", "velero",
                                  "backup", "describe", "before-change", "--details"]])
        self.assertIn("exec svc/velero -c velero -- /velero backup describe before-change --details", out.getvalue())

    def test_result_errors_read_in_the_server_pod(self):
        ctx = self._ctx()
        seen = []
        with mock.patch.object(dr, "in_cluster_storage", return_value=True), \
                mock.patch.object(dr, "_kubectl", lambda c, *a, **k: seen.append(a) or _cp(0, "")):
            dr.result_errors(ctx, "restore", "r1")
        self.assertEqual(seen[0][:4], ("-n", "velero", "exec", "svc/velero"))

    def test_hints_name_the_service_and_read_nothing_from_the_cluster(self):
        ctx = self._ctx()
        with mock.patch.object(dr, "_kubectl", side_effect=AssertionError("a hint reads nothing from the cluster")):
            hint = dr.velero_hint(ctx, "backup", "delete", "b1", "--confirm")
        self.assertEqual(hint, f"cs kubectl vmware --env {ctx.env.name} -n velero exec svc/velero -c velero -- /velero backup delete b1 --confirm")
        self.assertIn("exec svc/velero -c velero", " ".join(helpmod.COMMANDS["dr"].split()))


if __name__ == "__main__":
    unittest.main()
