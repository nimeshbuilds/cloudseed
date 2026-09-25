"""Wave-5 regression tests for the last cross-file ops / undo items: troubleshoot's Terraform hints (the user's plugin
cache named, paths quoted in commands, provision fixes that name the environment), deps (install dirs, an install that
leaves nothing on PATH, the macOS Tailscale app, GCP credentials from variables), singletons switched off in node add /
cloud prerequisites / config undos, purge undos (custom --workdir, current environment), the kept DR drill, restores
still running, chaos and scan outputs. Stdlib only; no network, cloud, Terraform, kubectl or velero."""
from __future__ import annotations

import argparse
import contextlib
import io
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, chaos, cli, clouds, deps, dr, paths, platform as platformmod, reconcile, scan, services, tf, \
    troubleshoot, ui, undo  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)
import test_wave4_undo as w4u  # noqa: E402

_n = [0]


def _uid(prefix: str) -> str:
    while True:
        _n[0] += 1
        name = f"{prefix}{life.RUN_ID}f{_n[0]}"
        if not life._taken(name):   # not an environment an earlier run left in a reused CLOUDSEED_HOME
            return name


def _run(fn, *a, **kw):
    """fn(*a, **kw) with its output captured: (result or raised exception, output)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return fn(*a, **kw), buf.getvalue()
    except (Exception, SystemExit, KeyboardInterrupt) as e:  # noqa: BLE001 - the caller asserts on it
        return e, buf.getvalue()


def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


# ---------------------------------------------------------------------------------------------------- troubleshoot

CHECKSUM = ("Error: Required plugins are not installed\n\nThe installed provider plugins are not consistent with the "
            "packages\nselected in the dependency lock file:\n  - registry.terraform.io/hashicorp/tls: the cached "
            "package for registry.terraform.io/hashicorp/tls 4.4.1 (in .terraform/providers) does not\nmatch any of "
            "the checksums recorded in the dependency lock file\n")


class TroubleshootTests(unittest.TestCase):
    def scan(self, text, cloud="aws", env="t5", **kw):
        d = Path(tempfile.mkdtemp(prefix="cs-w5ts-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "x.log").write_text(text)
        return troubleshoot._scan_log(d / "x.log", cloud, env, **kw)

    def test_the_reword_table_is_gone_and_tf_hints_are_used(self):
        self.assertFalse(hasattr(troubleshoot, "_TF_REWORD"))
        self.assertEqual(tf.ROOT, "<workdir>/stack")

    def test_the_users_plugin_cache_is_named(self):
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/cache/tf"}):
            hits = self.scan(CHECKSUM, workdir=Path("/w/envs/aws-t5"))
        what = " ".join(f.what for f in hits)
        self.assertIn("(TF_PLUGIN_CACHE_DIR=/cache/tf)", what)
        self.assertNotIn(tf.ANY_CACHE, what)
        self.assertTrue(any("/w/envs/aws-t5/stack or /w/envs/aws-t5/bootstrap" in f.fix for f in hits))

    def test_without_a_cache_now_the_general_wording_stays(self):
        # the failed run may have had one (another shell, CI): the "no cache" variant would rule the cause out
        with mock.patch.object(tf, "plugin_cache", return_value=None):
            hits = self.scan(CHECKSUM, workdir=Path("/w/envs/aws-t5"))
        what = " ".join(f.what for f in hits)
        self.assertIn("plugin cache changed", what)
        self.assertIn(tf.ANY_CACHE, what)
        self.assertIn("another OS/CPU", what)

    def test_commands_quote_a_working_directory_with_spaces(self):
        wd = Path("/w/my envs/aws-t5")
        lock = self.scan("Error: Error acquiring the state lock\n\nLock Info:\n  ID: 3a1c9d2e-1111-2222\n", workdir=wd)
        self.assertTrue(any(f"terraform -chdir='{wd}/stack' force-unlock 3a1c9d2e-1111-2222" in f.fix for f in lock),
                        [f.fix for f in lock])
        keys = self.scan("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n", workdir=wd)
        self.assertTrue(any(f"-f '{wd}/ssh/known_hosts'" in f.fix for f in keys), [f.fix for f in keys])
        token = self.scan("level=fatal msg=\"must be in format K10<CA-HASH>::<USERNAME>:<PASSWORD>\"\n", "vmware", workdir=wd)
        self.assertTrue(any(f"delete {wd}/k8s/token so" in f.fix for f in token))     # prose: the plain path
        plain = self.scan("Error: Error acquiring the state lock\n", workdir=Path("/w/envs/aws-t5"))
        self.assertTrue(any("-chdir=/w/envs/aws-t5/stack force-unlock" in f.fix for f in plain))  # nothing to quote

    def test_the_named_root_is_quoted_too(self):
        wd = Path("/w/my envs/aws-t5")
        hits = self.scan("Error: Error acquiring the state lock\n  ✖ terraform plan failed: ... in "
                         f"{wd}/dry-run/stack/.terraform\n", workdir=wd)
        self.assertTrue(any(f"-chdir='{wd}/dry-run/stack' force-unlock" in f.fix for f in hits), [f.fix for f in hits])

    def test_provision_fixes_name_the_environment(self):
        hits = self.scan("E: Failed to fetch http://deb.debian.org/x.deb  Could not connect to deb.debian.org:80\n")
        self.assertTrue(any("`cloudseed provision aws --env t5`" in f.fix for f in hits), [f.fix for f in hits])
        for hint in troubleshoot.LOG_HINTS:
            for fix in hint[2:]:
                self.assertNotIn("provision`", fix.replace("provision <cloud> --env <env>`", ""), fix)
                self.assertNotIn("provision ...", fix)
        kubeadm = self.scan("the bootstrap token is invalid\n", "vmware", "lab", workdir=Path("/w/lab"))
        self.assertIn("cloudseed provision vmware --env lab --host k8s", kubeadm[0].fix)


# ---------------------------------------------------------------------------------------------------- deps

class DepsTests(unittest.TestCase):
    def test_install_dirs_live_in_deps(self):
        self.assertEqual(deps.INSTALL_DIRS["go"], ["go"])
        self.assertEqual(deps.INSTALL_DIRS[deps.GKE_AUTH_PLUGIN], ["google-cloud-sdk"])
        self.assertEqual(deps.INSTALL_DIRS["aws"], ["aws-cli"])
        self.assertFalse(hasattr(cli, "_INSTALL_DIRS"))
        self.assertIn("deps.INSTALL_DIRS", inspect.getsource(cli._install_tool))

    def test_an_installer_that_leaves_nothing_on_path_fails(self):
        with mock.patch.dict(deps.INSTALLERS, {"k9s": lambda: True}), mock.patch.object(deps, "find", return_value=None), \
                mock.patch.object(deps, "_brew", return_value="/opt/homebrew/bin/brew"):
            ok, out = _run(deps.install, "k9s")
        self.assertIs(ok, False)
        self.assertIn("still not found on PATH", out)
        self.assertIn("brew list k9s", out)
        with mock.patch.dict(deps.INSTALLERS, {"k9s": lambda: True}), mock.patch.object(deps, "find", return_value=None), \
                mock.patch.object(deps, "_brew", return_value=None):   # apt/dnf installed it: no brew to ask
            ok, out = _run(deps.install, "k9s")
        self.assertIs(ok, False)
        self.assertNotIn("brew list", out)
        self.assertIn("package manager's file list for k9s", " ".join(out.split()))
        found = iter([None, "/x/bin/k9s"])
        with mock.patch.dict(deps.INSTALLERS, {"k9s": lambda: True}), \
                mock.patch.object(deps, "find", side_effect=lambda t: next(found)):
            ok, out = _run(deps.install, "k9s")
        self.assertIs(ok, True, out)
        with mock.patch.dict(deps.INSTALLERS, {"k9s": lambda: False}), mock.patch.object(deps, "find", return_value=None):
            ok, out = _run(deps.install, "k9s")
        self.assertIs(ok, False)
        self.assertNotIn("still not found", out)                     # the installer said why itself

    def test_the_tailscale_hint_names_the_app(self):
        with mock.patch.dict(deps.INSTALLERS, {"tailscale": lambda: True}), mock.patch.object(deps, "find", return_value=None):
            ok, out = _run(deps.install, "tailscale")
        self.assertIs(ok, False)
        self.assertIn("Install CLI", out)
        self.assertIn(str(deps.TAILSCALE_APP), " ".join(out.split()))

    def test_the_macos_tailscale_app_is_the_cli(self):
        d = Path(tempfile.mkdtemp(prefix="cs-w5ts-app-"))
        self.addCleanup(shutil.rmtree, d, True)
        app = d / "Tailscale"
        app.write_text("#!/bin/sh\n")
        app.chmod(0o755)
        empty = d / "path"
        empty.mkdir()
        with mock.patch.object(deps, "TAILSCALE_APP", app), mock.patch.object(deps, "path_env", return_value={"PATH": str(empty)}), \
                mock.patch.object(deps.platform, "system", return_value="Darwin"):
            self.assertEqual(deps.find("tailscale"), str(app))
            self.assertIsNone(deps.find("openvpn"))
        with mock.patch.object(deps, "TAILSCALE_APP", app), mock.patch.object(deps, "path_env", return_value={"PATH": str(empty)}), \
                mock.patch.object(deps.platform, "system", return_value="Linux"):
            self.assertIsNone(deps.find("tailscale"))
        with mock.patch.object(deps, "TAILSCALE_APP", d / "missing"), \
                mock.patch.object(deps, "path_env", return_value={"PATH": str(empty)}), \
                mock.patch.object(deps.platform, "system", return_value="Darwin"):
            self.assertIsNone(deps.find("tailscale"))

    def test_gcp_live_check_is_skipped_for_credentials_from_variables(self):
        every = deps._GOOGLE_ENV_CREDENTIALS + deps._GOOGLE_PROVIDER_ONLY
        clean = {k: v for k, v in os.environ.items() if k not in every}
        self.assertEqual(set(deps._GOOGLE_ENV_CREDENTIALS), {"GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN"})
        for var in deps._GOOGLE_ENV_CREDENTIALS:
            with self.subTest(var=var), mock.patch.dict(os.environ, dict(clean, **{var: "x"}), clear=True), \
                    mock.patch.object(deps, "find", return_value="/x/gcloud"), \
                    mock.patch.object(deps.subprocess, "run", side_effect=AssertionError("gcloud must not run")):
                self.assertIsNone(deps.live_credential_check("gcp"))
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(deps, "find", return_value="/x/gcloud"), \
                mock.patch.object(deps.subprocess, "run", return_value=_cp(0, "ya29.token")) as run:
            self.assertEqual(deps.live_credential_check("gcp"), (True, "Google application-default credentials valid"))
        self.assertIn("print-access-token", run.call_args[0][0])
        with mock.patch.dict(os.environ, dict(clean, GOOGLE_CREDENTIALS="  "), clear=True), \
                mock.patch.object(deps, "find", return_value="/x/gcloud"), \
                mock.patch.object(deps.subprocess, "run", return_value=_cp(1, "", "expired")):
            self.assertFalse(deps.live_credential_check("gcp")[0])       # blank is not set: ADC is checked

    def test_gcp_keyfile_variables_still_need_adc_for_the_state_backend(self):
        # the google provider reads GOOGLE_CLOUD_KEYFILE_JSON / GCLOUD_KEYFILE_JSON, Terraform's GCS backend does not:
        # an expired ADC is still a problem there, and the message says why and what to use instead
        every = deps._GOOGLE_ENV_CREDENTIALS + deps._GOOGLE_PROVIDER_ONLY
        clean = {k: v for k, v in os.environ.items() if k not in every}
        for var in deps._GOOGLE_PROVIDER_ONLY:
            with self.subTest(var=var), mock.patch.dict(os.environ, dict(clean, **{var: "/k.json"}), clear=True), \
                    mock.patch.object(deps, "find", return_value="/x/gcloud"), \
                    mock.patch.object(deps.subprocess, "run", return_value=_cp(1, "", "reauth")) as run:
                ok, msg = deps.live_credential_check("gcp")
            self.assertIn("print-access-token", run.call_args[0][0])
            self.assertFalse(ok)
            self.assertIn(f"{var} signs in the google provider only", msg)
            self.assertIn("GOOGLE_CREDENTIALS", msg)
            with mock.patch.dict(os.environ, dict(clean, **{var: "/k.json"}), clear=True), \
                    mock.patch.object(deps, "find", return_value="/x/gcloud"), \
                    mock.patch.object(deps.subprocess, "run", return_value=_cp(0, "ya29.token")):
                self.assertEqual(deps.live_credential_check("gcp"), (True, "Google application-default credentials valid"))


# ---------------------------------------------------------------------------------------------------- singletons

class _Envs(unittest.TestCase):
    def setUp(self):
        self.settings_before = paths.load_settings()
        self.index_before = paths.WORKDIRS_INDEX.read_text() if paths.WORKDIRS_INDEX.exists() else None
        self.made: list = []
        ni = mock.patch.object(ui, "interactive", return_value=False)
        ni.start()
        self.addCleanup(ni.stop)

    def tearDown(self):
        paths.save_settings(self.settings_before)
        for e in self.made:
            undo.clear(e.id)
            shutil.rmtree(paths.ENVS_DIR / e.id, ignore_errors=True)
            shutil.rmtree(paths.HOME / "logs" / "purged" / e.id, ignore_errors=True)
        if self.index_before is None:
            paths.WORKDIRS_INDEX.unlink(missing_ok=True)
        else:
            paths.WORKDIRS_INDEX.write_text(self.index_before)
        log = audit._state.get("log")
        if log:
            log.close()
            audit._state.update(log=None, env=None)

    def env(self, cloud="aws", **extra) -> paths.Env:
        e = paths.Env(cloud, _uid("w"))
        e.create_dirs()
        cfg = {"cloud": cloud, "env": e.name, "name": "cs", "region": "us-east-1", "network_cidr": "10.30.0.0/16",
               "allowed_ssh_cidrs": ["198.51.100.7/32"], "state": {"type": "local", "backend": None}, "vars": {},
               "extra_vars": {}, "tags": {}, "ssh_public_key": "ssh-ed25519 AAAA test"}
        cfg.update(extra)
        e.save(cfg)
        self.made.append(e)
        return e


def _singleton(auto=True):
    return reconcile.SingletonExists("GuardDuty exists. Nothing was applied.", {"enable_guardduty": False}, auto,
                                     [("aws_guardduty_detector", "module.stack.x.aws_guardduty_detector.this", ["d-1"])])


class SwitchOffTests(_Envs):
    def test_save_false_leaves_the_saved_configuration_alone(self):
        e = self.env()
        cfg = e.load()
        t = SimpleNamespace(calls=0)

        def plan_for_apply(cloud_key, c, targets=()):
            t.calls += 1
            if t.calls == 1:
                raise _singleton()
        t.plan_for_apply = plan_for_apply
        rendered = []
        with mock.patch.object(cli, "_render", lambda c, env, conf: rendered.append(dict(conf["extra_vars"]))):
            res, out = _run(cli._plan_for_apply, clouds.get("aws"), e, cfg, t, save=False)
        self.assertIsNone(res, out)
        self.assertEqual(cfg["extra_vars"], {"enable_guardduty": False})      # in the command's copy
        self.assertEqual(rendered, [{"enable_guardduty": False}])             # rendered with it
        self.assertEqual(e.load()["extra_vars"], {})                          # config.json: only once the apply worked

    def test_cloud_prerequisites_switch_off_and_settle_after_the_apply(self):
        e = self.env()
        cfg = e.load()
        calls = []
        fake_tf = SimpleNamespace(init=lambda migrate=False: None, state_list=lambda: [],
                                  apply_reconciled=lambda *a, **k: calls.append("apply"))
        with mock.patch.object(cli, "_ensure_backend"), mock.patch.object(cli, "_render", return_value=False), \
                mock.patch.object(cli, "Terraform", lambda d: fake_tf), mock.patch.object(cli, "_approve"), \
                mock.patch.object(cli, "_plan_for_apply", side_effect=lambda *a, **k: calls.append(("plan", k))), \
                mock.patch.object(cli, "_settle_kept", side_effect=lambda env, c, t: calls.append("settle")), \
                mock.patch.object(cli, "_cache_outputs", return_value={}), mock.patch.object(audit, "refresh"), \
                mock.patch.object(cli, "_record_prereqs_undo"):
            res, out = _run(cli._apply_prereqs, clouds.get("aws"), e, cfg, ["velero"], True)
        self.assertEqual(res, {}, out)
        self.assertEqual(calls, [("plan", {"save": False}), "apply", "settle"])
        self.assertEqual(e.load()["platform_prereqs"], ["velero"])

    def test_node_add_uses_the_same_rule(self):
        src = inspect.getsource(cli._node_local_add)
        self.assertIn("_plan_for_apply(cloud, env, cfg, t, save=False)", src)
        self.assertNotIn("t.plan_for_apply(", src)
        self.assertLess(src.index("env.save(cfg)"), src.index("_settle_kept(env, cfg, t)"))
        self.assertNotIn("t.plan_for_apply(", inspect.getsource(cli._apply_prereqs))


class _SwitchingTf(w4u.FakeTf):
    """plan_for_apply as Terraform does it with a render: a default-on GuardDuty that exists is switched off."""
    seen: list = []

    def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):
        _SwitchingTf.seen.append(render is not None)
        if render is not None:
            _singleton().switch_off(cfg)
            render(cfg)


class ConfigUndoSwitchOffTests(w4u._Journal):
    def test_a_config_undo_switches_a_default_on_singleton_off_and_saves_it(self):
        base = {"cloud": "aws", "env": "w5cfg", "name": "lab", "region": "us-east-1", "state": {"type": "local"},
                "extra_vars": {}}
        env = self.env("aws", "w5cfg", dict(base, vars={"bastion_instance_type": "t3.small"}))
        prev = dict(base, vars={"bastion_instance_type": "t3.micro"})
        entry = undo.record(env.id, "setup (changed: vars)", "config", {"prev_cfg": prev, "what": "vars"})
        rendered, settled = [], []
        _SwitchingTf.seen = []
        with w4u._config_undo([], cloud_key="aws"), mock.patch("cloudseed.tf.Terraform", _SwitchingTf), \
                mock.patch.object(cli, "_render", lambda c, e, conf: rendered.append(dict(conf.get("extra_vars") or {})) or False), \
                mock.patch.object(cli, "_settle_kept", lambda e, conf, t: settled.append(dict(conf.get("extra_vars") or {}))):
            res, out = w4u._run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(_SwitchingTf.seen, [True])
        self.assertIn({"enable_guardduty": False}, rendered)           # the stack was rendered with the switch-off
        saved = env.load()
        self.assertEqual(saved["vars"]["bastion_instance_type"], "t3.micro")
        self.assertEqual(saved["extra_vars"], {"enable_guardduty": False})   # saved with the applied plan
        self.assertEqual(settled, [{"enable_guardduty": False}])


# ---------------------------------------------------------------------------------------------------- purge undos

class PurgeUndoTests(life.LifeBase):
    """A never-deployed environment in a custom --workdir: its purge is undone into that directory (registered again),
    and it becomes the current environment again when it was."""

    def setUp(self):
        super().setUp()
        self.settings_before = paths.load_settings()
        self.index_before = paths.WORKDIRS_INDEX.read_text() if paths.WORKDIRS_INDEX.exists() else None
        root = Path(tempfile.mkdtemp(prefix="cs-w5wd-"))
        self.addCleanup(shutil.rmtree, root, True)
        self.wd = root / "infra"
        default = self.env.dir
        self.env.set_workdir(self.wd)
        self.env.save(dict(self.cfg))
        (self.env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
        shutil.rmtree(default, ignore_errors=True)

    def tearDown(self):
        undo.clear(self.env.id)
        paths.save_settings(self.settings_before)
        if self.index_before is None:
            paths.WORKDIRS_INDEX.unlink(missing_ok=True)
        else:
            paths.WORKDIRS_INDEX.write_text(self.index_before)
        shutil.rmtree(paths.HOME / "logs" / "purged" / self.env.id, ignore_errors=True)
        super().tearDown()

    def purge(self):
        life.FakeTF.reset(state=None)
        settings = paths.load_settings()
        settings["current_env"] = self.env.id
        paths.save_settings(settings)
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge", settings=settings), 0, self.out.getvalue())
        self.assertNotIn("current_env", paths.load_settings())
        self.assertNotIn(self.env.id, paths._load_index())
        entry = undo.latest(self.env.id)
        self.assertEqual(entry["kind"], "restore-files")
        self.assertEqual(Path(entry["data"]["workdir"]), self.wd.resolve())
        self.assertEqual(entry["data"]["current_env"], self.env.id)
        return entry

    def test_the_purge_is_undone_into_its_directory_and_is_current_again(self):
        entry = self.purge()
        self.assertIn(f"in {self.wd.resolve()}", undo.describe(entry))
        settings: dict = {}
        res, out = _run(undo.perform, entry, settings, True)
        self.assertIsNone(res, out)
        back = paths.Env(self.cloud, self.env_name)
        self.assertEqual(back.dir, self.wd.resolve())
        self.assertEqual(back.load()["env"], self.env_name)
        self.assertEqual((back.ssh_dir / "id_ed25519").read_text(), "PRIVATE KEY")
        self.assertEqual(paths.load_settings().get("current_env"), self.env.id)
        self.assertEqual(settings.get("current_env"), self.env.id)
        self.assertIn("current environment again", out)

    def test_another_current_environment_chosen_since_stays(self):
        entry = self.purge()
        s = paths.load_settings()
        s["current_env"] = "aws-other"
        paths.save_settings(s)
        res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(paths.load_settings()["current_env"], "aws-other")


class RecreateUndoTests(_Envs):
    def entry(self, name, wd: Path | None, current=True):
        cfg = {"cloud": "aws", "env": name, "name": "lab", "vars": {}, "state": {"type": "local"}}
        ub = undo.BACKUPS / f"w5-{name}"
        shutil.rmtree(ub, ignore_errors=True)
        (ub / "ssh").mkdir(parents=True)
        (ub / "config.json").write_text(json.dumps(dict(cfg, workdir=str(wd) if wd else "")))
        (ub / "ssh" / "id_ed25519").write_text("KEY")
        data = {"cfg": cfg, "backup_dir": str(ub)}
        if wd is not None:
            data["workdir"] = str(wd)
        if current:
            data["current_env"] = f"aws-{name}"
        self.made.append(paths.Env("aws", name))
        return undo.record(f"aws-{name}", f"destroy aws-{name} --purge", "recreate", data)

    def workdir(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="cs-w5rc-"))
        self.addCleanup(shutil.rmtree, root, True)
        return root / "infra"

    def test_a_custom_workdir_is_registered_again_before_setup(self):
        wd = self.workdir()
        name = _uid("rc")
        entry = self.entry(name, wd)
        s = paths.load_settings()
        s.pop("current_env", None)
        paths.save_settings(s)
        ran = []
        with mock.patch.object(undo, "_run_cli", lambda argv: ran.append((argv, paths.Env("aws", name).dir))), \
                mock.patch.object(cli, "_approve"):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(ran[0][0], ["setup", "aws", "--env", name, "-y", "--auto-approve"])
        self.assertEqual(ran[0][1], wd.resolve())                      # setup found it in its own directory
        self.assertEqual(paths._load_index()[f"aws-{name}"], str(wd.resolve()))
        self.assertEqual((wd / "ssh" / "id_ed25519").read_text(), "KEY")
        self.assertFalse((paths.ENVS_DIR / f"aws-{name}" / "config.json").exists())
        self.assertEqual(paths.load_settings().get("current_env"), f"aws-{name}")

    def test_a_directory_that_is_no_longer_free_is_refused_before_the_approval(self):
        wd = self.workdir()
        wd.mkdir(parents=True)
        (wd / "notes.txt").write_text("mine")
        name = _uid("rc")
        entry = self.entry(name, wd)
        asked, ran = [], []
        with mock.patch.object(undo, "_run_cli", lambda argv: ran.append(argv)), \
                mock.patch.object(cli, "_approve", lambda q, auto: asked.append(q)):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("cannot go back into", str(res))
        self.assertEqual((asked, ran), ([], []))
        self.assertNotIn(f"aws-{name}", paths._load_index())

    def test_the_default_directory_works_as_before(self):
        name = _uid("rc")
        entry = self.entry(name, None, current=False)
        ran = []
        with mock.patch.object(undo, "_run_cli", lambda argv: ran.append(argv)), mock.patch.object(cli, "_approve"):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertTrue((paths.ENVS_DIR / f"aws-{name}" / "config.json").exists())
        self.assertEqual(len(ran), 1)


# ---------------------------------------------------------------------------------------------------- DR / chaos / scan

class DrUndoTests(_Envs):
    def cluster(self, env):
        ctx = SimpleNamespace(env=env, target="aws")
        return mock.patch.object(undo, "_cluster", return_value=(clouds.get("aws"), env, env.load(), {}, ctx))

    def test_a_kept_drill_is_removed_namespace_then_backup(self):
        e = self.env()
        entry = undo.record(e.id, f"dr test on {e.id} (drill namespace and backup kept)", "dr-drill",
                            {"namespace": dr.DRILL_NS, "backup": "dr-test-20260101"}, minor=True)
        self.assertTrue(undo.is_minor(entry))
        self.assertEqual(undo.describe(entry),
                         f"delete the kept DR drill namespace {dr.DRILL_NS} and its Velero backup dr-test-20260101")
        calls = []
        with self.cluster(e), mock.patch.object(cli, "_approve"), mock.patch.object(dr, "_phase", return_value="Completed"), \
                mock.patch.object(dr, "_kubectl", side_effect=lambda ctx, *a, **k: calls.append(("kubectl",) + a) or _cp()), \
                mock.patch.object(dr, "_velero", side_effect=lambda ctx, *a, **k: calls.append(("velero",) + a) or
                                  _cp(1, "", "An error occurred: backups.velero.io \"dr-test-20260101\" not found")):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(calls, [("kubectl", "delete", "ns", dr.DRILL_NS, "--ignore-not-found", "--wait=false"),
                                 ("velero", "backup", "delete", "dr-test-20260101", "--confirm")])

    def test_a_failed_backup_delete_keeps_the_entry(self):
        e = self.env()
        entry = undo.record(e.id, "dr test (kept)", "dr-drill", {"namespace": dr.DRILL_NS, "backup": "b1"}, minor=True)
        with self.cluster(e), mock.patch.object(cli, "_approve"), mock.patch.object(dr, "_kubectl", return_value=_cp()), \
                mock.patch.object(dr, "_phase", return_value=None), \
                mock.patch.object(dr, "_velero", return_value=_cp(1, "", "An error occurred: connection refused")):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("connection refused", str(res))
        self.assertIn("dr-drill", cli._UNDO_NEEDS_ENV)
        self.assertIn("dr-drill", cli._UNDO_TOOLCHAIN)

    def test_a_kept_backup_still_running_is_refused_before_anything(self):
        # a drill interrupted with --keep can leave its backup InProgress: Velero would accept the delete request and
        # then refuse it, so the backup would stay with the entry gone
        e = self.env()
        entry = undo.record(e.id, "dr test (kept)", "dr-drill", {"namespace": dr.DRILL_NS, "backup": "b1"}, minor=True)
        asked, ran = [], []
        with self.cluster(e), mock.patch.object(dr, "_phase", return_value="InProgress"), \
                mock.patch.object(cli, "_approve", lambda q, auto: asked.append(q)), \
                mock.patch.object(dr, "_kubectl", side_effect=lambda *a, **k: ran.append(a) or _cp()), \
                mock.patch.object(dr, "_velero", side_effect=lambda *a, **k: ran.append(a) or _cp()):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("b1 is still InProgress", str(res))
        self.assertEqual((asked, ran), ([], []))
        self.assertEqual(undo.latest(e.id)["id"], entry["id"])            # kept for a retry

    def test_a_restore_still_running_is_not_undone(self):
        e = self.env()
        entry = undo.record(e.id, "dr restore b1", "velero-restore",
                            {"backup": "pre-1", "new_namespaces": [], "restore": "b1-restore-20260101000000"})
        asked = []
        for phase in ("New", "InProgress", "Finalizing"):
            with self.subTest(phase=phase), self.cluster(e), mock.patch.object(dr, "_phase", return_value=phase), \
                    mock.patch.object(cli, "_approve", lambda q, auto: asked.append(q)):
                res, out = _run(undo.perform, entry, {}, True)
            self.assertIsInstance(res, ui.Abort)
            self.assertIn(f"b1-restore-20260101000000 is still {phase}", str(res))
        self.assertEqual(asked, [])
        for phase in ("Completed", "PartiallyFailed", None):
            with self.subTest(phase=phase), mock.patch.object(dr, "_phase", return_value=phase):
                self.assertIsNone(undo._check_restore_finished(SimpleNamespace(), entry["data"]))
        self.assertIsNone(undo._check_restore_finished(SimpleNamespace(), {"backup": "old-entry"}))   # nothing to read

    def test_dr_restore_records_the_restore_it_started(self):
        e = self.env()
        args = argparse.Namespace(name="b1", namespaces=None, no_wait=True, auto_approve=True)
        recorded = []
        common = [mock.patch.object(cli, "_restorable_backup", return_value={"spec": {}}),
                  mock.patch.object(cli, "_approve_worded"), mock.patch.object(cli, "_namespaces_now", return_value=set()),
                  mock.patch.object(undo, "velero_pre_backup", return_value="pre-1"),
                  mock.patch.object(undo, "record", side_effect=lambda *a, **k: recorded.append(a))]
        with contextlib.ExitStack() as st:
            for p in common:
                st.enter_context(p)
            st.enter_context(mock.patch.object(cli, "_velero_names", return_value=set()))
            st.enter_context(mock.patch.object(dr, "restore", return_value="b1-restore-20260101000000"))
            res, out = _run(cli._dr_restore, args, clouds.get("aws"), e, SimpleNamespace())
        self.assertEqual(res, 0, out)
        self.assertEqual(recorded[-1][2], "velero-restore")
        self.assertEqual(recorded[-1][3]["restore"], "b1-restore-20260101000000")
        # interrupted while waiting: the restore goes on in the cluster, and its name is recorded all the same
        recorded.clear()
        names = iter([set(), {"b1-restore-20260101000001"}])
        args.no_wait = False
        with contextlib.ExitStack() as st:
            for p in common:
                st.enter_context(p)
            st.enter_context(mock.patch.object(cli, "_velero_names", side_effect=lambda c, k: next(names)))
            st.enter_context(mock.patch.object(dr, "_status", return_value={"phase": "InProgress"}))
            st.enter_context(mock.patch.object(dr, "restore", side_effect=KeyboardInterrupt))
            res, out = _run(cli._dr_restore, args, clouds.get("aws"), e, SimpleNamespace())
        self.assertIsInstance(res, KeyboardInterrupt)
        self.assertEqual(recorded[-1][3]["restore"], "b1-restore-20260101000001")
        self.assertIn("(failed part-way)", recorded[-1][1])

    def test_a_restore_that_only_creates_namespaces_waits_too(self):
        # no namespace existed before, so no Velero undo point: the undo only deletes the namespaces the restore creates,
        # which would race a --no-wait restore that is still running (Velero re-creates them)
        e = self.env()
        args = argparse.Namespace(name="b1", namespaces="shop", no_wait=True, auto_approve=True)
        with mock.patch.object(cli, "_restorable_backup", return_value={"spec": {"includedNamespaces": ["shop"]}}), \
                mock.patch.object(cli, "_approve_worded"), mock.patch.object(cli, "_namespaces_now", return_value=set()), \
                mock.patch.object(undo, "velero_pre_backup", side_effect=AssertionError("nothing exists to back up")), \
                mock.patch.object(cli, "_velero_names", return_value=set()), \
                mock.patch.object(dr, "restore", return_value="b1-restore-20260101000000"):
            res, out = _run(cli._dr_restore, args, clouds.get("aws"), e, SimpleNamespace())
        self.assertEqual(res, 0, out)
        entry = undo.latest(e.id)
        self.assertEqual(entry["kind"], "argv-seq")
        self.assertEqual(entry["data"]["restore"], "b1-restore-20260101000000")
        asked, ran = [], []
        with self.cluster(e), mock.patch.object(dr, "_phase", return_value="InProgress"), \
                mock.patch.object(cli, "_approve", lambda q, auto: asked.append(q)), \
                mock.patch.object(undo, "_run_cli", side_effect=lambda argv: ran.append(argv)):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("still InProgress", str(res))
        self.assertEqual((asked, ran), ([], []))
        with self.cluster(e), mock.patch.object(dr, "_phase", return_value="Completed"), mock.patch.object(cli, "_approve"), \
                mock.patch.object(undo, "_run_cli", side_effect=lambda argv: ran.append(argv)):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(ran, [["kubectl", "aws", "--env", e.name, "delete", "ns", "shop", "--ignore-not-found"]])

    def run_dr_test(self, e, drill):
        ctx = SimpleNamespace(env=e)

        def fake_test(c, keep=False, with_volume=None):
            if drill is not None:
                c.dr_drill = drill
            return 0
        a = cli.build_parser().parse_args(["dr", "test", "--keep", "aws", "--env", e.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("aws"), e, e.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=e.dir / "kc"), \
                mock.patch.object(platformmod, "Cluster", return_value=ctx), mock.patch.object(dr, "installed", return_value=True), \
                mock.patch.object(dr, "test", side_effect=fake_test):
            return _run(cli.cmd_dr, a, {})

    def test_dr_test_keep_records_the_namespace_and_the_backup(self):
        e = self.env()
        res, out = self.run_dr_test(e, {"namespace": dr.DRILL_NS, "backup": "dr-test-20260101", "kept": True})
        self.assertEqual(res, 0, out)
        entry = undo.latest(e.id)
        self.assertEqual((entry["kind"], entry["data"]), ("dr-drill", {"namespace": dr.DRILL_NS, "backup": "dr-test-20260101"}))
        self.assertIn("drill namespace and backup dr-test-20260101 kept", entry["summary"])
        self.assertTrue(undo.is_minor(entry))
        undo.clear(e.id)
        res, out = self.run_dr_test(e, None)          # stopped before its report: only the namespace can be left
        self.assertEqual(res, 0, out)
        self.assertEqual(undo.latest(e.id)["kind"], "argv-seq")

    def test_ttl_follows_dr_ttl_duration(self):
        a = cli.build_parser().parse_args(["dr", "schedule", "n1", "--ttl", "14d"])
        res, out = _run(cli._check_dr_args, a)
        self.assertIsNone(res, out)
        self.assertEqual(a.ttl, "336h")
        self.assertIn("--ttl 14d = 336h", out)
        a = cli.build_parser().parse_args(["dr", "schedule", "n1", "--ttl", "forever"])
        res, _ = _run(cli._check_dr_args, a)
        self.assertEqual((res.code, "not a duration" in str(res)), (2, True))
        self.assertIs(cli._GO_DURATION, dr.GO_DURATION)


class ChaosScanUndoTests(_Envs):
    def test_chaos_records_the_report_its_run_saved(self):
        e = self.env("vmware")
        d = e.dir / "chaos"
        d.mkdir()
        ours = d / "report-20260102-000001.json"
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "vmware", "--env", e.name])

        def run(ctx, *args, **kw):   # a parallel run's report lands next to ours
            (d / "report-20260102-000000.json").write_text("{}")
            ours.write_text("{}")
            ctx.chaos_report = ours
            return 0
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), e, e.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=e.dir / "kc"), \
                mock.patch.object(cli, "_ensure_chaos_mesh"), mock.patch.object(chaos, "run", side_effect=run):
            res, out = _run(cli.cmd_chaos, a, {})
        self.assertEqual(res, 0, out)
        entry = undo.latest(e.id)
        self.assertEqual(entry["data"]["paths"], [str(ours), str(ours.with_suffix(".md"))])

    def test_a_scan_that_failed_part_way_leaves_its_claimed_outputs_undoable(self):
        e = self.env()
        a = cli.build_parser().parse_args(["scan", "host", "aws", "--env", e.name])
        made = []

        def host(cloud, env, cfg, outputs, hosts, profile):
            d = env.dir / "scans"
            d.mkdir(exist_ok=True)
            p, _run_id = scan.claim_run_path(d, "openscap-", "", "20260101-000000", directory=True)
            (p / "bastion.html").write_text("<html/>")
            made.append(p)
            raise ui.Abort("openscap failed on the bastion")
        with mock.patch.object(scan, "host", side_effect=host):
            res, out = _run(cli.cmd_scan, a, {})
        self.assertIsInstance(res, ui.Abort)
        entry = undo.latest(e.id)
        self.assertEqual(entry["kind"], "delete-paths")
        self.assertEqual(entry["data"]["paths"], [str(made[0])])


# ---------------------------------------------------------------------------------------------------- undo texts

class UndoTextTests(unittest.TestCase):
    def test_the_undo_header_and_help_name_the_limits_and_utc(self):
        src = inspect.getsource(cli.cmd_undo)
        self.assertIn("undo.when(entry)", src)
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        helptext = next(c.help for c in sub._choices_actions if c.dest == "undo")
        self.assertIn("the last 15 changes per environment and globally, at most 5 of one kind", helptext)
        self.assertEqual((undo.KEEP_TOTAL, undo.KEEP, undo.KEEP_LIGHT), (15, 5, 5))

    def test_docs_describe_what_an_undo_waits_for_and_puts_back(self):
        # the history limits, the drain / kept-settings / Velero-bucket notes and the dr/scan pages are the docs group's
        # (w5/docs, test_wave5_docs); these are the facts of this group's undo behaviour
        from cloudseed import explain, help as h
        root = Path(__file__).resolve().parent.parent
        flat = lambda t: " ".join(t.split())   # noqa: E731
        page = flat(h.COMMANDS["undo"])
        for part in ("`dr restore --no-wait`", "`dr test --keep` whose backup is still being written",
                     "a custom --workdir is registered again", "the current environment again when it was",
                     "shows the times in UTC", "delete the kept drill namespace and backup"):
            self.assertIn(part, page, part)
        readme = flat((root / "docs" / "guides" / "manual.md").read_text())   # the reference moved out of README.md
        for part in ("**Never racing Velero**", "a custom `--workdir` is registered again", "shows the times in UTC"):
            self.assertIn(part, readme, part)
        controls = " ".join(explain.FEATURES["undo"]["controls"])
        self.assertIn("undone only once Velero has finished", controls)
        self.assertIn("a custom --workdir is registered again", controls)
        skill = flat((root / "skills" / "cloudseed-destroy" / "SKILL.md").read_text())
        self.assertIn("Undoing a `--purge` puts the environment back into its own working directory", skill)
        mcp_src = flat(inspect.getsource(__import__("cloudseed.mcp", fromlist=["x"])))
        self.assertIn("fifteen kept per environment, at most five of one kind", mcp_src)

if __name__ == "__main__":
    unittest.main()
