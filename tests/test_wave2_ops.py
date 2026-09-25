"""Regression tests for the wave-2 ops items: undo (repeat coalescing, backup cleanup, node rejoin, platform batches,
one kubectl parser), audit (authoritative inventory fields, stream redaction), troubleshoot (cloud-aware SSH hints,
network-cleanup hints, VMware checks, teed output), reconcile (Azure subscription singletons, one object per plan),
deps (GKE auth plugin, scan installers, agent sessions, Windows, Azure note) and the container runtime (files handed
back to the host user under rootful Docker). Stdlib only, no network, no cloud."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, container, deps, paths, reconcile, troubleshoot, ui, undo  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _quiet():
    buf = io.StringIO()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(buf))
    stack.enter_context(contextlib.redirect_stderr(buf))
    return stack, buf


# ---------------------------------------------------------------------------------------------------- undo

class UndoRecordTests(unittest.TestCase):
    def setUp(self):
        self.scope = "w2ops-rec"
        undo.clear(self.scope)

    def tearDown(self):
        undo.clear(self.scope)

    def test_the_same_change_twice_takes_one_slot(self):
        a = undo.record(self.scope, "vpn connect aws-x", "argv", {"argv": ["vpn", "disconnect", "aws", "--env", "x"]})
        b = undo.record(self.scope, "vpn connect aws-x", "argv", {"argv": ["vpn", "disconnect", "aws", "--env", "x"]})
        es = undo.entries(self.scope)
        self.assertEqual(len(es), 1)
        self.assertEqual(a["id"], b["id"])

    def test_different_changes_are_kept_apart(self):
        undo.record(self.scope, "vpn connect aws-x", "argv", {"argv": ["vpn", "disconnect"]})
        undo.record(self.scope, "vpn disconnect aws-x", "argv", {"argv": ["vpn", "connect"]})
        undo.record(self.scope, "vpn disconnect aws-x", "argv", {"argv": ["vpn", "connect"]}, minor=True)   # minor differs
        undo.record(self.scope, "vpn disconnect aws-x", "argv", {"argv": ["vpn", "connect", "-y"]})         # data differs
        self.assertEqual(len(undo.entries(self.scope)), 4)

    def test_repeat_is_only_merged_with_the_newest_entry(self):
        undo.record(self.scope, "a", "argv", {"argv": ["x"]})
        undo.record(self.scope, "b", "argv", {"argv": ["y"]})
        undo.record(self.scope, "a", "argv", {"argv": ["x"]})
        self.assertEqual([e["summary"] for e in undo.entries(self.scope)], ["a", "b", "a"])

    def test_coalesce_keeps_the_oldest_data(self):
        undo.record(self.scope, "env use a", "settings-restore", {"settings": {"current_env": "0"}}, coalesce="current_env")
        undo.record(self.scope, "env use b", "settings-restore", {"settings": {"current_env": "a"}}, coalesce="current_env")
        es = undo.entries(self.scope)
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0]["summary"], "env use b")
        self.assertEqual(es[0]["data"]["settings"]["current_env"], "0")


class UndoBackupCleanupTests(unittest.TestCase):
    def test_only_paths_inside_the_backup_dir_are_deleted(self):
        undo.BACKUPS.mkdir(parents=True, exist_ok=True)
        inside = undo.BACKUPS / "w2ops-purge"
        (inside / "ssh").mkdir(parents=True, exist_ok=True)
        (inside / "config.json").write_text("{}")
        outside = Path(tempfile.mkdtemp()) / "keep.json"
        outside.write_text("{}")
        tricky = str(undo.BACKUPS) + "-other"          # same prefix, not inside
        Path(tricky).mkdir(parents=True, exist_ok=True)
        undo._discard_backups({"data": {"backup_dir": str(inside), "files": {"/x": str(outside), "/y": tricky,
                                                                               "/z": str(undo.BACKUPS / "..")}}})
        self.assertFalse(inside.exists())
        self.assertTrue(outside.exists())
        self.assertTrue(Path(tricky).exists())
        self.assertTrue(undo.BACKUPS.exists())
        shutil.rmtree(tricky, ignore_errors=True)

    def test_legacy_container_paths_are_mapped_first(self):
        undo.BACKUPS.mkdir(parents=True, exist_ok=True)
        b = undo.BACKUPS / "w2ops-legacy.json"
        b.write_text("{}")
        legacy = container.LEGACY_HOME + "/undo/w2ops-legacy.json"
        if str(paths.HOME) == container.LEGACY_HOME:
            self.skipTest("the test home is the legacy container home")
        undo._discard_backups({"data": {"files": {"/somewhere": legacy}}})
        self.assertFalse(b.exists())


class UndoPlatformBatchTests(unittest.TestCase):
    def test_new_items_are_uninstalled_together_and_rollbacks_keep_their_place(self):
        from cloudseed import cli, platform as platformmod
        calls = []
        steps = [{"item": "cert-manager"}, {"item": "keda", "release": "keda", "ns": "keda", "prev_revision": 2},
                 {"item": "gateway-api"}, {"item": "envoy-gateway"}]
        entry = {"kind": "platform", "scope": "aws-w2plat", "summary": "platform install", "data": {"steps": steps}}
        with mock.patch.object(undo, "_cluster", lambda scope: (None, paths.Env("aws", "w2plat"), {}, {}, object())), \
                mock.patch.object(cli, "_approve", lambda q, auto: None), \
                mock.patch.object(platformmod, "uninstall", lambda items, ctx: calls.append(("uninstall", list(items)))), \
                mock.patch.object(platformmod, "_run", lambda argv, ctx: calls.append(("run", argv[1:]))), \
                mock.patch.object(deps, "find", lambda tool: "/bin/" + tool):
            stack, _ = _quiet()
            with stack:
                undo.perform(entry, {}, True)
        self.assertEqual(calls, [("uninstall", ["envoy-gateway", "gateway-api"]),
                                 ("run", ["rollback", "keda", "2", "-n", "keda"]),
                                 ("uninstall", ["cert-manager"])])


class UndoNodeRejoinTests(unittest.TestCase):
    def _run(self, plan_changes):
        from cloudseed import cli, provision
        env = paths.Env("vmware", "w2rejoin")
        env.create_dirs()
        cur = {"cloud": "vmware", "env": "w2rejoin", "name": "lab", "vars": {"enable_kubernetes": True, "kubernetes_workers": 1},
               "state": {"type": "local"}, "workdir": str(env.dir)}
        env.save(dict(cur))
        prev = dict(cur, vars={"enable_kubernetes": True, "kubernetes_workers": 2})

        class FakeTf:
            def __init__(self, workdir):
                pass

            def init(self, migrate=False):
                pass

            def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):
                pass

            def apply_reconciled(self, cloud_key, cfg, approve=None, **kw):
                pass

        joined = []
        outputs = {"kubernetes_control_plane_ips": ["10.0.0.20"], "kubernetes_worker_ips": ["10.0.0.40", "10.0.0.41"]}
        entry = {"kind": "config", "scope": env.id, "summary": "node remove lab-w2rejoin-wk2",
                 "data": {"prev_cfg": prev, "what": "node count", "rejoin_nodes": True}}
        with mock.patch("cloudseed.tf.Terraform", FakeTf), \
                mock.patch.object(cli, "_render", lambda c, e, cfg: False), \
                mock.patch.object(cli, "_approve", lambda q, auto: None), \
                mock.patch.object(cli, "_cache_outputs", lambda e, t: outputs), \
                mock.patch.object(cli, "_plan_changes", lambda t, planfile="tfplan": plan_changes), \
                mock.patch.object(audit, "refresh", lambda *a, **k: None), \
                mock.patch.object(clouds.get("vmware").__class__, "prepare", lambda self, cfg, dry_run=False: None), \
                mock.patch.object(provision, "provision_local_kubernetes",
                                  lambda cloud, env, cfg, outputs, limit=None, **kw: joined.append(limit)):
            stack, _ = _quiet()
            audit.begin(["undo", "vmware", "--env", "w2rejoin"])
            try:
                with stack:
                    undo.perform(entry, {}, True)          # attaches the environment's log
            finally:
                audit.end(0)                               # and closes it again
        return joined

    def test_only_recreated_node_vms_join(self):
        changes = [{"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["wk2"]', "type": "vmdesktop_vm",
                    "actions": ["create"]},
                   {"address": 'module.stack.module.kubernetes[0].random_integer.mac["wk2-0"]', "type": "random_integer",
                    "actions": ["create"]},
                   {"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["wk1"]', "type": "vmdesktop_vm",
                    "actions": ["update"]}]
        self.assertEqual(self._run(changes), [["lab-w2rejoin-wk2"]])

    def test_replaced_vm_counts_as_recreated(self):
        changes = [{"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["cp1"]', "type": "vmdesktop_vm",
                    "actions": ["delete", "create"]}]
        self.assertEqual(self._run(changes), [["lab-w2rejoin-cp1"]])

    def test_nothing_recreated_nothing_to_join(self):
        self.assertEqual(self._run([]), [])

    def test_unreadable_plan_falls_back_to_every_node(self):
        self.assertEqual(self._run(None), [None])


class KubectlParserTests(unittest.TestCase):
    def test_one_parser_for_cs_kubectl_and_undo(self):
        from cloudseed import cli
        for args in (["-n", "shop", "delete", "pod", "x"], ["delete", "ns", "a", "b"], ["apply", "-f", "x.yaml"]):
            a = cli._kube_args("kubectl", args)
            self.assertEqual(undo.kubectl_namespaces(args), cli._kubectl_scope(a["pos"][0], a["pos"], a))
        for gone in ("parse_kube_args", "kubectl_mutates", "kubectl_inverse", "helm_call"):
            self.assertFalse(hasattr(undo, gone), gone)
        self.assertIn("delete", undo.MUTATING_KUBECTL)          # still read by cli._pre_change_undo


# ---------------------------------------------------------------------------------------------------- audit

class InventoryFieldTests(unittest.TestCase):
    def test_terraform_fields_are_authoritative(self):
        out = []
        audit._walk({"resources": [
            {"address": "module.stack.google_compute_address.bastion", "type": "google_compute_address", "name": "bastion",
             "mode": "managed", "values": {"address": "34.1.2.3", "name": "cs-dev-bastion-ip", "id": "projects/p/x"}},
            {"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["cp1"]', "type": "vmdesktop_vm", "name": "node",
             "mode": "managed", "values": {"name": "lab-e2e-cp1", "vmx_path": "/v/lab-e2e-cp1.vmx"}}]}, out)
        ip, vm = out
        self.assertEqual(ip["address"], "module.stack.google_compute_address.bastion")
        self.assertEqual(ip["name"], "bastion")
        self.assertEqual(ip["ip_address"], "34.1.2.3")
        self.assertEqual(ip["cloud_name"], "cs-dev-bastion-ip")
        self.assertEqual(ip["type"], "google_compute_address")
        self.assertEqual(vm["name"], "node")
        self.assertEqual(vm["cloud_name"], "lab-e2e-cp1")
        # identifier values keep their shape (token-only redaction), like the other identifier fields
        self.assertEqual(audit.secrets_free({"cloud_name": "secret-token: x"})["cloud_name"], "secret-token: x")


class AuditStreamTests(unittest.TestCase):
    def test_one_write_with_a_whole_key_block(self):
        f = io.StringIO()
        audit.begin(["x"])
        audit._state["log"] = f
        try:
            audit.write("Traceback:\n  -----BEGIN " "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
                        "-----END OPENSSH PRIVATE KEY-----\nafter\n")
            audit.write("AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMIK7MDENG" + "bPxRfiCYEXAMPLEKEY")
        finally:
            audit._state["log"] = None
        text = f.getvalue()
        self.assertNotIn("b3BlbnNzaC1rZXkt", text)
        self.assertIn("after", text)
        self.assertNotIn("wJalrXUtnFEMIK7MDENG", text)
        self.assertIsInstance(audit._state["keys"], __import__("cloudseed.secrets", fromlist=["x"]).StreamRedactor)

    def test_begin_resets_purged_and_the_redactor(self):
        audit.begin(["x"])
        audit.mark_purged()
        k = audit._state["keys"]
        audit.begin(["y"])
        self.assertFalse(audit._state["purged"])
        self.assertIsNot(audit._state["keys"], k)


# ---------------------------------------------------------------------------------------------------- troubleshoot

class TroubleshootHintTests(unittest.TestCase):
    def _scan(self, text, cloud="aws", **kw):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text(text)
        return troubleshoot._scan_log(log, cloud, "dev", **kw)

    def test_timeout_is_cloud_aware(self):
        text = "ssh: connect to host 1.2.3.4 port 22: Operation timed out\n"
        cloud = self._scan(text)
        self.assertTrue(any("not reachable on port 22" in f.what and "update-ip aws --env dev" in f.fix for f in cloud))
        local = self._scan(text, "vmware")
        self.assertTrue(any("not reachable on port 22" in f.what for f in local))
        self.assertFalse(any("update-ip" in f.fix for f in local))
        self.assertTrue(any("powered off" in f.fix for f in local))

    def test_other_timeouts_are_not_port_22(self):
        hits = self._scan("E: Failed to fetch http://deb.debian.org/x  Could not connect to deb.debian.org:80, Connection timed out\n")
        self.assertFalse(any("port 22" in f.what for f in hits))

    def test_refused_is_not_an_ip_problem(self):
        hits = self._scan("ssh: connect to host 1.2.3.4 port 22: Connection refused\n")
        refused = [f for f in hits if "refused SSH" in f.what]
        self.assertEqual(len(refused), 1)
        self.assertNotIn("update-ip", refused[0].fix)

    def test_wait_summary_no_longer_blames_the_ip(self):
        hits = self._scan("bastion did not accept SSH within 420s. Last error: Permission denied (publickey).\n")
        wait = [f for f in hits if "never accepted SSH" in f.what]
        self.assertEqual(len(wait), 1)
        self.assertNotIn("probably changed", wait[0].fix)
        self.assertIn("may have changed", wait[0].fix)
        self.assertTrue(any("rejected the key" in f.what for f in hits))

    def test_changed_host_key_from_host_wait(self):
        hits = self._scan("bastion at 10.0.0.5 presents a different SSH host key than the one recorded in /w/ssh/known_hosts.\n")
        self.assertTrue(any("host key changed" in f.what and "ssh-keygen -R" in f.fix for f in hits))

    def test_bastion_cannot_reach_the_private_host(self):
        hits = self._scan("channel 0: open failed: connect failed: No route to host\nstdio forwarding failed\n")
        self.assertTrue(any("behind it" in f.what for f in hits))

    def test_kubernetes_leftovers_blocking_the_network(self):
        aws = self._scan("Error: deleting EC2 VPC (vpc-0abc): DependencyViolation: The vpc 'vpc-0abc' has dependencies and cannot be deleted.\n")
        self.assertTrue(any("DependencyViolation" not in f.what and "Kubernetes" in f.what and "destroy aws --env dev" in f.fix for f in aws))
        gcp = self._scan("Error: Error waiting for Deleting Network: The network resource 'projects/p/global/networks/cs-dev-vpc' "
                         "is already being used by 'projects/p/global/firewalls/k8s-fw-a1b2c3'\n", "gcp")
        self.assertTrue(any("GKE" in f.what and "destroy gcp --env dev" in f.fix for f in gcp))

    def test_helm_and_apt_conflicts_are_not_name_clashes(self):
        for text in ('Error: UPGRADE FAILED: Apply failed with 1 conflict: conflict with "Helm" using apps/v1: .spec.replicas\n',
                     "E: Conflicts: libbar\nError: something failed\n"):
            self.assertFalse(any("same name already exists" in f.what for f in self._scan(text)), text)


class TroubleshootRunTests(unittest.TestCase):
    def _run(self, cloud_key, env_name, cfg_extra=None, inventory=None, runs=None):
        env = paths.Env(cloud_key, env_name)
        env.create_dirs()
        cfg = {"cloud": cloud_key, "env": env_name, "name": "lab", "vars": {}, "workdir": str(env.dir)}
        cfg.update(cfg_extra or {})
        env.save(cfg)
        if inventory is not None:
            (env.dir / "inventory.json").write_text(json.dumps(inventory))
        if runs:
            (env.dir / "logs" / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs))
        from cloudseed import localvm
        stack, buf = _quiet()
        with stack, mock.patch.object(troubleshoot.deps, "missing", return_value=([], [])), \
                mock.patch.object(troubleshoot.deps, "live_credential_check", return_value=None), \
                mock.patch.object(troubleshoot.netutil, "detect_public_ip", return_value=None), \
                mock.patch.object(localvm, "detect_host", lambda: None), \
                mock.patch.object(localvm, "_port_open", lambda *a, **k: True):
            audit.begin(["troubleshoot", cloud_key, "--env", env_name])
            audit.attach(env)
            troubleshoot.run(clouds.get(cloud_key), env, env.load())
            log = audit._state.get("logpath")
            audit.end(0)
        return buf.getvalue(), Path(log).read_text() if log else ""

    def test_vmware_bastion_without_ip(self):
        inv = {"current": {"count": 3, "resources": [], "outputs": {"bastion_public_ip": ""}}}
        out, _ = self._run("vmware", "w2noip", inventory=inv)
        flat = " ".join(out.split())
        self.assertIn("The bastion VM has no IP address", flat)
        self.assertIn("cloudseed apply vmware --env w2noip", flat)

    def test_vmware_vm_dir_is_where_the_vms_are(self):
        home_rel = "~/w2ops-vms"
        out, _ = self._run("vmware", "w2vmdir", cfg_extra={"vars": {"vm_dir": home_rel}})
        want = clouds.get("vmware").vm_dir_path({"vars": {"vm_dir": home_rel}, "workdir": str(paths.Env("vmware", "w2vmdir").dir)})
        flat = "".join(out.split())                      # long values wrap under the value column
        self.assertIn("".join(str(want).split()), flat)
        self.assertNotIn("~/w2ops-vms", out)

    def test_recent_runs_reach_the_command_log(self):
        runs = [{"at": "2026-01-01T00:00:00", "command": "status", "argv": ["status", "aws", "--env", "w2tee", "--marker-run"],
                 "exit_code": 0, "duration_s": 1.0}]
        _, log = self._run("aws", "w2tee", runs=runs)
        self.assertIn("--marker-run", log)


# ---------------------------------------------------------------------------------------------------- reconcile

class _TF:
    def __init__(self, state=()):
        self.imports, self.state = [], list(state)

    def run(self, *args, **kw):
        if args[0] == "import":
            self.imports.append(args[2:])
        return subprocess.CompletedProcess(args, 0, "", "")

    def state_list(self):
        return self.state


def _conflict(addr: str) -> str:
    return f'Error: creating: already exists\n\n  with {addr},\n  on main.tf line 1\n'


class ReconcileTests(unittest.TestCase):
    def test_marketplace_agreement_id_and_shared_adoption(self):
        cfg = {"env": "dev", "vars": {"subscription_id": "0000-1111"}}
        c = reconcile.CloudLookups("azure", cfg)
        ident = reconcile.IMPORT_ID["azurerm_marketplace_agreement"](
            {"publisher": "canonical", "offer": "0001-com-ubuntu-pro-jammy-fips", "plan": "pro-fips-22_04-gen2"}, c)
        self.assertEqual(ident, "/subscriptions/0000-1111/providers/Microsoft.MarketplaceOrdering/agreements/canonical/"
                                "offers/0001-com-ubuntu-pro-jammy-fips/plans/pro-fips-22_04-gen2")
        self.assertIsNone(reconcile.IMPORT_ID["azurerm_marketplace_agreement"]({}, reconcile.CloudLookups("azure", {"vars": {}})))
        addr = "module.stack.azurerm_marketplace_agreement.ubuntu_pro_fips[0]"
        planned = {addr: {"type": "azurerm_marketplace_agreement",
                          "values": {"publisher": "canonical", "offer": "o", "plan": "p"}}}
        tf = _TF()
        stack, _ = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "azure", cfg, _conflict(addr), planned), [addr])   # no tags to check
        self.assertNotIn("azurerm_marketplace_agreement", reconcile.PREFLIGHT_TYPES)   # its id proves nothing before apply

    def test_defender_is_never_adopted(self):
        cfg = {"env": "dev", "vars": {"subscription_id": "0000-1111"}}
        addr = 'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["VirtualMachines"]'
        planned = {addr: {"type": "azurerm_security_center_subscription_pricing", "values": {"resource_type": "VirtualMachines", "tier": "Standard"}}}
        tf = _TF()
        stack, buf = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "azure", cfg, _conflict(addr), planned), [])
        self.assertEqual(tf.imports, [])
        self.assertIn("enable_defender=false", buf.getvalue())
        # before apply: an already-Standard pricing stops the run with the exact re-run command
        from cloudseed.tf import TerraformError
        with mock.patch.object(reconcile.CloudLookups, "_az", lambda self, *a: {"pricingTier": "Standard", "id": "/subscriptions/0000-1111/providers/Microsoft.Security/pricings/VirtualMachines"}):
            with self.assertRaises(TerraformError) as cm:
                reconcile.preflight(tf, "azure", cfg, planned)
        self.assertIn("--var enable_defender=false", str(cm.exception))
        with mock.patch.object(reconcile.CloudLookups, "_az", lambda self, *a: {"pricingTier": "Free"}):
            self.assertEqual(reconcile.preflight(tf, "azure", cfg, planned), [])

    def test_an_object_two_addresses_map_to_is_never_adopted(self):
        cfg = {"env": "production-europe-west", "vars": {}}
        v = {"project": "p", "account_id": "cloudseed-production-europe-we"}
        a1 = "module.stack.google_service_account.bastion"
        a2 = "module.stack.module.kubernetes[0].google_service_account.external_dns[0]"
        planned = {a1: {"type": "google_service_account", "values": dict(v)},
                   a2: {"type": "google_service_account", "values": dict(v)},
                   "module.stack.data.google_service_account.x": {"type": "google_service_account", "values": {"project": "p", "account_id": "other"}}}
        tf = _TF()
        stack, buf = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "gcp", cfg, _conflict(a2), planned), [])
        self.assertEqual(tf.imports, [])
        self.assertIn(a1, buf.getvalue())

    def test_ids_from_unknown_values_are_not_imported(self):
        addr = "module.stack.google_service_account.bastion"
        planned = {addr: {"type": "google_service_account", "values": {"account_id": "cs-bastion"}}}   # project unknown
        tf = _TF()
        stack, buf = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "gcp", {"vars": {}}, _conflict(addr), planned), [])
        self.assertEqual(tf.imports, [])
        self.assertIn("could not be determined", buf.getvalue())

    def test_account_id_is_asked_once(self):
        calls = []
        c = reconcile.CloudLookups("aws", {"vars": {}})
        with mock.patch.object(reconcile.CloudLookups, "_awscli", lambda self, *a: calls.append(a) or {"Account": "123456789012"}):
            self.assertEqual(c.aws_iam_policy_arn("a"), "arn:aws:iam::123456789012:policy/a")
            self.assertEqual(c.aws_iam_policy_arn("b"), "arn:aws:iam::123456789012:policy/b")
        self.assertEqual(len(calls), 1)

    def test_conflict_re_has_no_bare_conflict(self):
        self.assertIsNone(reconcile.CONFLICT_RE.search("409 Conflict: MissingSubscriptionRegistration"))
        self.assertIsNotNone(reconcile.CONFLICT_RE.search("Error: creating role: EntityAlreadyExists: Role with name x already exists"))


# ---------------------------------------------------------------------------------------------------- deps

class AgentSessionInstallTests(unittest.TestCase):
    def test_agent_session_detection(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "builtin"}):
            self.assertTrue(deps.agent_session())
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp", "CLOUDSEED_REDACT": "1"}):
            self.assertFalse(deps.agent_session())                 # MCP installs are confirm-gated
        env = {k: v for k, v in os.environ.items() if k not in ("CLOUDSEED_AGENT", "CLOUDSEED_REDACT")}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(deps.agent_session())
            os.environ["CLOUDSEED_REDACT"] = "1"
            self.assertTrue(deps.agent_session())

    def test_runtime_never_installs_for_an_agent_even_on_a_terminal(self):
        installs = []
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "codex"}), \
                mock.patch.object(deps, "missing", return_value=(["terraform"], [])), \
                mock.patch.object(deps, "describe_missing", return_value="terraform"), \
                mock.patch.object(deps, "install", side_effect=lambda t: installs.append(t) or True), \
                mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "choose", side_effect=AssertionError("must not ask")):
            stack, _ = _quiet()
            with stack, self.assertRaises(ui.Abort) as cm:
                deps.ensure_runtime("aws", "auto", {})
        self.assertEqual(installs, [])
        self.assertIn("cloudseed install terraform", cm.exception.msg)
        self.assertIn("agent session", cm.exception.msg)

    def test_vmware_tools_and_homebrew_in_an_agent_session(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "claude"}), \
                mock.patch.object(deps, "missing", return_value=(["terraform"], [])), \
                mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "confirm", side_effect=AssertionError("must not ask")):
            stack, _ = _quiet()
            with stack, self.assertRaises(ui.Abort):
                deps._ensure_vmware_tools()
            with mock.patch.object(deps, "_brew", return_value=None), \
                    mock.patch.object(deps.platform, "system", return_value="Darwin"), \
                    mock.patch.object(deps.subprocess, "call", side_effect=AssertionError("must not run")):
                self.assertFalse(deps.install_homebrew())


class GkeAuthPluginTests(unittest.TestCase):
    def test_registered_for_gcp_doctor_and_install(self):
        self.assertEqual(deps.TOOLS[deps.GKE_AUTH_PLUGIN]["clouds"], ("gcp",))
        self.assertIn(deps.GKE_AUTH_PLUGIN, deps.INSTALLERS)
        for t in ("kubescape", "trivy"):
            self.assertIn(t, deps.INSTALLERS)
            self.assertNotIn(t, deps.TOOLS)                       # installed by `cs scan` on first use; no doctor row

    def test_found_inside_the_gcloud_sdk(self):
        root = Path(os.path.realpath(tempfile.mkdtemp()))
        sdk_bin = root / "google-cloud-sdk" / "bin"
        sdk_bin.mkdir(parents=True)
        for name in ("gcloud", deps.GKE_AUTH_PLUGIN):
            (sdk_bin / name).write_text("#!/bin/sh\n")
            (sdk_bin / name).chmod(0o755)
        linkdir = root / "links"
        linkdir.mkdir()
        (linkdir / "gcloud").symlink_to(sdk_bin / "gcloud")          # like ~/.cloudseed/bin/gcloud or brew's link
        with mock.patch.object(deps, "path_env", return_value={"PATH": str(linkdir)}):
            self.assertEqual(deps.find(deps.GKE_AUTH_PLUGIN), str(sdk_bin / deps.GKE_AUTH_PLUGIN))
            (sdk_bin / deps.GKE_AUTH_PLUGIN).unlink()
            self.assertIsNone(deps.find(deps.GKE_AUTH_PLUGIN))

    def test_install_uses_gcloud_components_then_the_package(self):
        runs = []

        def fake_run(cmd, **kw):
            runs.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 1, "", "ERROR: (gcloud.components.install) You cannot perform this "
                                                          "action because the Google Cloud CLI component manager is disabled")
        state = {"found": False}
        with mock.patch.object(deps, "find", lambda t: "/usr/bin/gcloud" if t == "gcloud" else ("/usr/bin/" + t if state["found"] else None)), \
                mock.patch.object(deps.subprocess, "run", fake_run), \
                mock.patch.object(deps.platform, "system", return_value="Linux"), \
                mock.patch.object(deps.shutil, "which", lambda m: "/usr/bin/apt-get" if m == "apt-get" else None):
            stack, _ = _quiet()
            with stack:
                self.assertFalse(deps.install_gke_gcloud_auth_plugin())
        self.assertEqual(runs[0][1:], ["components", "install", deps.GKE_AUTH_PLUGIN, "--quiet"])
        self.assertEqual(runs[1], ["sudo", "apt-get", "install", "-y", "google-cloud-cli-gke-gcloud-auth-plugin"])

    def test_gcloud_install_brings_the_plugin(self):
        runs = []
        with mock.patch.object(deps, "_brew_install", return_value=True), \
                mock.patch.object(deps, "find", lambda t: "/opt/homebrew/bin/gcloud" if t == "gcloud" else None), \
                mock.patch.object(deps.subprocess, "run", lambda cmd, **kw: runs.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")):
            stack, _ = _quiet()
            with stack:
                self.assertTrue(deps.install_gcloud())
        self.assertEqual(runs, [["/opt/homebrew/bin/gcloud", "components", "install", deps.GKE_AUTH_PLUGIN, "--quiet"]])
        self.assertIn("--additional-components", Path(deps.__file__).read_text())


class DepsMiscTests(unittest.TestCase):
    def test_windows_refuses_local_ansible_clearly(self):
        with mock.patch.object(deps.os, "name", "nt"):
            with self.assertRaises(ui.Abort) as cm:
                deps.ensure_local_ansible()
        self.assertIn("WSL", cm.exception.msg)

    def test_azure_note_says_when_az_is_needed(self):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        with mock.patch.dict(os.environ, clean, clear=True):
            self.assertIn("unless", deps.optional_cli_note("azure", "az"))
            os.environ.update(ARM_CLIENT_ID="x", ARM_CLIENT_SECRET="y", ARM_TENANT_ID="z")
            self.assertIn("optional here", deps.optional_cli_note("azure", "az"))
        self.assertIn("optional", deps.optional_cli_note("aws", "aws"))

    def test_kubescape_installer_uses_the_verified_release(self):
        from cloudseed import scan
        with mock.patch.object(deps, "_brew_install", return_value=False), \
                mock.patch.object(scan, "_install_kubescape", return_value=Path("/x/kubescape")) as inst, \
                mock.patch.object(deps, "find", return_value="/x/kubescape"):
            self.assertTrue(deps.INSTALLERS["kubescape"]())
        inst.assert_called_once()


# ---------------------------------------------------------------------------------------------------- container

class ContainerOwnerTests(unittest.TestCase):
    def test_only_rootful_docker_on_linux_needs_the_handback(self):
        with mock.patch.object(container.sys, "platform", "linux"), \
                mock.patch.object(container.os, "getuid", return_value=1000, create=True), \
                mock.patch.object(container.os, "getgid", return_value=1001, create=True):
            self.assertEqual(container.host_owner("docker", " Security Options:\n  seccomp\n  cgroupns\n"), (1000, 1001))
            self.assertIsNone(container.host_owner("docker", " Security Options:\n  seccomp\n  rootless\n"))
            self.assertIsNone(container.host_owner("docker", " Security Options:\n  userns\n"))
            self.assertIsNone(container.host_owner("docker", " Operating System: Docker Desktop\n"))
            self.assertIsNone(container.host_owner("podman", ""))
        with mock.patch.object(container.sys, "platform", "darwin"):
            self.assertIsNone(container.host_owner("docker", ""))
        with mock.patch.object(container.sys, "platform", "linux"), \
                mock.patch.object(container.os, "getuid", return_value=0, create=True):
            self.assertIsNone(container.host_owner("docker", ""))

    def test_run_command_passes_owner_paths_and_entrypoint(self):
        ro = Path(tempfile.mkdtemp()) / "sa.json"
        ro.write_text("{}")
        environ = {"GOOGLE_APPLICATION_CREDENTIALS": str(ro), "CLOUDSEED_HOST_UID": "0", "PATH": "/usr/bin"}
        with mock.patch.object(container, "host_owner", return_value=(1000, 1001)), \
                mock.patch.object(container.paths, "IS_BUNDLE", False):
            cmd = container.build_run_command("docker", ["status", "aws"], environ, tty=False)
        env = {c.split("=", 1)[0]: c.split("=", 1)[1] for c in cmd if "=" in c and c.startswith("CLOUDSEED_")}
        self.assertEqual(env["CLOUDSEED_HOST_UID"], "1000")                       # never the host's own variable
        self.assertEqual(env["CLOUDSEED_HOST_GID"], "1001")
        chown = env["CLOUDSEED_CHOWN_PATHS"].split(":")
        self.assertIn(str(paths.HOME), chown)
        self.assertIn("/workspace", chown)
        self.assertNotIn(str(paths.HOME / "bin"), chown)                         # covered by the home
        self.assertFalse(any(p.startswith("/run/cloudseed/google_application") for p in chown))   # read-only mount
        self.assertEqual(cmd[cmd.index("--entrypoint") + 1], "/bin/sh")
        i = cmd.index(container.IMAGE)
        self.assertEqual(cmd[i + 1:], [container.ENTRYPOINT, "--runtime", "local", "status", "aws"])
        self.assertEqual(cmd.count("CLOUDSEED_HOST_UID"), 0)                      # not forwarded by name either

    def test_run_command_unchanged_without_owner(self):
        with mock.patch.object(container, "host_owner", return_value=None):
            cmd = container.build_run_command("docker", ["status", "aws"], {"CLOUDSEED_HOST_UID": "5", "PATH": "/usr/bin"}, tty=False)
        self.assertNotIn("--entrypoint", cmd)
        self.assertFalse(any("CLOUDSEED_HOST_UID" in c or "CLOUDSEED_CHOWN_PATHS" in c for c in cmd))
        self.assertEqual(cmd[-5:], [container.IMAGE, "--runtime", "local", "status", "aws"])


class EntrypointScriptTests(unittest.TestCase):
    SCRIPT = REPO / "scripts" / "container-entrypoint.sh"

    def _tree(self):
        root = Path(tempfile.mkdtemp())
        (root / "scripts").mkdir()
        (root / "bin").mkdir()
        shutil.copy2(self.SCRIPT, root / "scripts" / "container-entrypoint.sh")
        cs = root / "bin" / "cloudseed"
        cs.write_text('#!/bin/sh\necho "cloudseed $*"\nexit 3\n')
        cs.chmod(0o755)
        fake = root / "fakebin"
        fake.mkdir()
        return root, fake

    def _run(self, root, fake, extra_env):
        env = {"PATH": f"{fake}:/usr/bin:/bin", **extra_env}
        return subprocess.run(["/bin/sh", str(root / "scripts" / "container-entrypoint.sh"), "--runtime", "local", "status"],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_syntax_and_image_wiring(self):
        self.assertEqual(subprocess.run(["/bin/sh", "-n", str(self.SCRIPT)]).returncode, 0)
        self.assertTrue(os.access(self.SCRIPT, os.X_OK))
        docker = (REPO / "Dockerfile").read_text()
        self.assertIn('ENTRYPOINT ["/bin/sh", "/workspace/scripts/container-entrypoint.sh"]', docker)
        self.assertIn("google-cloud-cli-gke-gcloud-auth-plugin", docker)
        self.assertEqual(container.ENTRYPOINT, "/workspace/scripts/container-entrypoint.sh")

    def test_without_an_owner_it_only_runs_cloudseed(self):
        root, fake = self._tree()
        p = self._run(root, fake, {})
        self.assertEqual(p.returncode, 3)
        self.assertEqual(p.stdout.strip(), "cloudseed --runtime local status")
        p = self._run(root, fake, {"CLOUDSEED_HOST_UID": "abc"})       # not numeric: ignored
        self.assertEqual(p.returncode, 3)

    def test_as_root_it_hands_back_this_runs_files(self):
        root, fake = self._tree()
        log = root / "find.log"
        (fake / "id").write_text("#!/bin/sh\necho 0\n")
        (fake / "find").write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
        for f in ("id", "find"):
            (fake / f).chmod(0o755)
        home = root / "home"
        home.mkdir()
        p = self._run(root, fake, {"CLOUDSEED_HOST_UID": "1000", "CLOUDSEED_HOST_GID": "1001",
                                   "CLOUDSEED_CHOWN_PATHS": f"{home}:{root / 'missing'}:/work space*"})
        self.assertEqual(p.returncode, 3, p.stderr)                      # cloudseed's own exit code
        calls = log.read_text().splitlines()
        self.assertEqual(len(calls), 1)                                  # missing paths are skipped, nothing globbed
        self.assertTrue(calls[0].startswith(f"{home} -user 0 -cnewer "))
        self.assertTrue(calls[0].endswith("-exec chown -h 1000:1001 {} +"))


# ---------------------------------------------------------------------------------------------------- build files

class BuildFileTests(unittest.TestCase):
    def test_make_keeps_terraform_caches_out_of_the_tree(self):
        make = (REPO / "Makefile").read_text()
        self.assertIn("TF_DATA_DIR=", make)
        self.assertIn("terraform test", make)
        if shutil.which("make"):
            out = subprocess.run(["make", "-n", "tftest"], cwd=REPO, capture_output=True, text=True).stdout
            self.assertIn(str(REPO / "build" / "tfdata"), out)

    def test_dockerignore_and_bundle_skip_lock_files(self):
        self.assertIn("**/.terraform.lock.hcl", (REPO / ".dockerignore").read_text())
        self.assertIn('".terraform.lock.hcl"', (REPO / "scripts" / "build-bundle.sh").read_text())


if __name__ == "__main__":
    unittest.main()
