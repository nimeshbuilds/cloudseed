"""Wave-4 regression tests for the VMware target: the setup questions' choices and bounds (one source for the CLI, the
prompt and the web console), MetalLB's LoadBalancer pool in the address plan, the Kubernetes pod/Service ranges, the
private-range rule and the VMs' DNS, the kubernetes_distro description, the implicit provider build reporting on stderr,
Workstation's version on Windows, and relative vmx paths recorded by older versions.
No VMware, no network, no Go: every external command is faked."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import help as h, localvm, paths, provision, ui, webui  # noqa: E402
from cloudseed.clouds import base as cloudbase  # noqa: E402
from cloudseed.clouds import vmware as vmw  # noqa: E402
from cloudseed.clouds.vmware import VMware  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "vmware"


def _tmp(test) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cs-w4vmw-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _cfg(workdir: Path, cidr: str = "192.168.160.0/24", **vars_) -> dict:
    return {"cloud": "vmware", "env": "lab", "name": "cloudseed", "network_cidr": cidr, "workdir": str(workdir),
            "ssh_public_key": "ssh-ed25519 AAAA x", "vars": dict(vars_), "extra_vars": {}, "tags": {}}


def _state(workdir: Path, names: list, tainted: tuple = ()) -> None:
    (workdir / "stack").mkdir(parents=True, exist_ok=True)
    resources = [{"mode": "managed", "type": "vmdesktop_vm", "name": "x",
                  "instances": [dict({"attributes": {"name": n}}, **({"status": "tainted"} if n in tainted else {}))]}
                 for n in names]
    (workdir / "stack" / "terraform.tfstate").write_text(json.dumps({"version": 4, "resources": resources}))


# ---------------------------------------------------------------- the questions: choices and bounds

class QuestionTests(unittest.TestCase):
    def setUp(self):
        self.c = VMware()

    def test_enumerated_answers_are_choices(self):
        self.assertEqual(self.c.question("guest_os").choices, tuple(localvm.IMAGES))
        self.assertEqual(self.c.question("kubernetes_distro").choices, ("rke2", "kubeadm"))
        # any spelling of a choice is taken as that choice; anything else names the choices
        self.assertEqual(self.c.question("guest_os").coerce("Debian-12"), "debian-12")
        self.assertEqual(self.c.question("kubernetes_distro").coerce(" RKE2 "), "rke2")
        self.assertIn("rke2, kubeadm", self.c.question("kubernetes_distro").problem("k3s"))
        self.assertIn("ubuntu-24.04", self.c.question("guest_os").problem("centos-9"))

    def test_the_web_console_gets_the_choices(self):
        qs = {q["key"]: q for q in webui.clouds_catalog()["vmware"]["questions"]}
        self.assertEqual(qs["guest_os"]["choices"], list(localvm.IMAGES))
        self.assertEqual(qs["kubernetes_distro"]["choices"], ["rke2", "kubeadm"])

    def test_help_lists_the_choices_once(self):
        page = h.variables_page("vmware")
        self.assertEqual(page.count("ubuntu-24.04, ubuntu-22.04, debian-12"), 1)   # the prompt already names them
        self.assertNotIn("one of: ubuntu", page)

    def test_counts_have_their_bounds(self):
        bounds = {q.key: (q.minimum, q.maximum) for q in self.c.questions}
        self.assertEqual(bounds["kubernetes_control_planes"], (1, vmw.MAX_CONTROL_PLANES))
        self.assertEqual(bounds["kubernetes_workers"], (0, None))    # 0: the control planes run the workloads
        self.assertEqual(bounds["workload_count"], (0, None))
        cps = self.c.question("kubernetes_control_planes")
        for bad in ("0", "21", 21):
            self.assertEqual(cps.problem(bad), f"must be 1-{vmw.MAX_CONTROL_PLANES}")
        self.assertIsNone(cps.problem("20"))
        self.assertIn("must be >= 0", self.c.question("kubernetes_workers").problem("-1"))

    def test_sizes_have_their_floors_as_minimums_with_the_unit_in_the_message(self):
        floors = {"bastion_cpus": 1, "workload_cpus": 1, "kubernetes_cpus": 1, "bastion_memory_mb": 512,
                  "workload_memory_mb": 512, "kubernetes_memory_mb": 512, "bastion_disk_gb": 10, "workload_disk_gb": 10,
                  "kubernetes_disk_gb": 20}
        for key, floor in floors.items():
            q = self.c.question(key)
            self.assertEqual(q.minimum, floor, key)
            self.assertIsNone(q.problem(str(floor)), key)
            self.assertIn(f"must be at least {floor}", q.problem(str(floor - 1)), key)   # not the generic ">= N"
            self.assertIn(f"must be at least {floor}", q.problem("-4"), key)
        self.assertIn("(MB)", self.c.question("bastion_memory_mb").problem("100"))
        self.assertIn("multiple of 4", self.c.question("bastion_memory_mb").problem("2050"))
        self.assertIn("base image", self.c.question("bastion_disk_gb").problem("5"))
        # not a number at all: as_int's own message
        for bad in ("abc", 1.5, True):
            self.assertIn("expected a whole number", self.c.question("bastion_cpus").problem(bad), bad)

    def test_a_json_number_gets_the_same_message(self):
        # the web console and MCP send JSON numbers: 100.0 is 100, never "a whole number"
        mem = self.c.question("bastion_memory_mb")
        self.assertIn("must be at least 512 (MB)", mem.problem(100.0))
        self.assertIn("multiple of 4", mem.problem(2050.0))
        self.assertIsNone(mem.problem(2048.0))
        self.assertEqual(self.c.question("kubernetes_control_planes").problem(21.0), f"must be 1-{vmw.MAX_CONTROL_PLANES}")

    def test_a_bad_value_is_still_refused_through_the_cli_path(self):
        with self.assertRaises(ui.Abort) as e:
            cloudbase.coerce_answer(self.c.question("bastion_memory_mb"), "100", "--var bastion_memory_mb")
        self.assertIn("must be at least 512 (MB)", e.exception.msg)


# ---------------------------------------------------------------- MetalLB's LoadBalancer pool (vmware#3 residual)

class LoadBalancerPoolTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()
        vmw._WARNED.clear()

    def test_workers_stop_below_the_pool(self):
        k8s = {"enable_kubernetes": True}
        self.assertEqual(self.c.address_problems(_cfg(self.d, **k8s, kubernetes_workers=60)), [])   # .40-.99
        problems = self.c.address_problems(_cfg(self.d, **k8s, kubernetes_workers=61))
        self.assertEqual(len(problems), 1)
        self.assertIn("kubernetes_workers=61: at most 60", problems[0])
        self.assertIn(".100-.127 are kept for LoadBalancer addresses (MetalLB)", problems[0])
        self.assertIn("fix: --var kubernetes_workers=60", problems[0])
        self.assertIn("at most 60", self.c.address_problems(_cfg(self.d, **k8s, kubernetes_workers=200))[0])
        # without a cluster the workers are not created: no rule
        self.assertEqual(self.c.address_problems(_cfg(self.d, kubernetes_workers=200)), [])

    def test_the_pool_matches_the_platform(self):
        from cloudseed import platform as pl
        settings = {"enable_kubernetes": True, "kubernetes_workers": 60}
        with mock.patch.object(pl, "_vmnet_dhcp", return_value=None):
            pool = pl._lb_range("192.168.160.0/24", {}, "vmware", settings)
        self.assertEqual(pool, "192.168.160.100-192.168.160.127")
        self.assertEqual(vmw.MAX_STATIC_HOST - vmw.LB_POOL_SIZE, 99)

    def test_small_networks_keep_their_limits(self):
        cfg = _cfg(self.d, "10.0.0.0/26", enable_kubernetes=True, kubernetes_workers=23)   # .40-.62
        self.assertEqual(self.c.address_problems(cfg), [])
        cfg["vars"]["kubernetes_workers"] = 24
        self.assertIn("below VMware's DHCP pool", self.c.address_problems(cfg)[0])

    def test_workers_an_existing_cluster_already_has_there_are_only_warned_about(self):
        _state(self.d, ["cloudseed-lab-bastion", "cloudseed-lab-cp1"] + [f"cloudseed-lab-wk{i}" for i in range(1, 71)])
        cfg = _cfg(self.d, enable_kubernetes=True, kubernetes_workers=70)
        with mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self.c.address_problems(cfg), [])
            self.assertEqual(self.c.address_problems(cfg), [])
        warn.assert_called_once()                                   # once per run
        self.assertIn("wk61-wk70", warn.call_args[0][0])
        self.assertIn("MetalLB", warn.call_args[0][0])
        self.assertIn("cloudseed node remove cloudseed-lab-wk70 vmware --env lab", warn.call_args[0][0])
        # growing it further is refused (node add passes the wanted count)
        cfg["vars"]["kubernetes_workers"] = 71
        problems = self.c.address_problems(cfg)
        self.assertIn("kubernetes_workers=71: at most 70", problems[0])
        self.assertIn("already has 70 workers, so it keeps them but cannot grow", problems[0])
        # and VMware's DHCP pool stays a hard limit
        cfg["vars"]["kubernetes_workers"] = 89
        self.assertIn("at most 70", self.c.address_problems(cfg)[0])

    def test_tainted_workers_do_not_count(self):
        _state(self.d, ["cloudseed-lab-bastion", "cloudseed-lab-wk61"], tainted=("cloudseed-lab-wk61",))
        self.assertTrue(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_workers=61)))

    def test_node_add_is_refused_before_anything_changes(self):
        from cloudseed import cli
        env = paths.Env("vmware", "lab", self.d)
        cfg = _cfg(self.d, enable_kubernetes=True, kubernetes_workers=60)
        args = types.SimpleNamespace(count=1, role="worker", auto_approve=True)
        with mock.patch.object(cli, "_render") as render:
            with self.assertRaises(ui.Abort) as e:
                cli._node_local_add(args, self.c, env, cfg)
        self.assertIn("no room for 1 more worker", e.exception.msg)
        self.assertIn("MetalLB", e.exception.msg)
        render.assert_not_called()
        self.assertEqual(cfg["vars"]["kubernetes_workers"], 60)


# ---------------------------------------------------------------- the cluster's pod and Service ranges (a2-ansible#2)

class ClusterRangeTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()
        vmw._WARNED.clear()

    def test_a_new_environment_on_a_cluster_range_is_refused(self):
        for cidr, distro, kind, other in (("10.42.0.0/24", "rke2", "pod", "kubeadm"), ("10.43.7.0/24", "rke2", "Service", "kubeadm"),
                                          ("10.244.1.0/24", "kubeadm", "pod", "rke2"), ("10.96.0.0/24", "kubeadm", "Service", "rke2")):
            problems = self.c.address_problems(_cfg(self.d, cidr, enable_kubernetes=True, kubernetes_distro=distro))
            self.assertEqual(len(problems), 1, (cidr, problems))
            self.assertIn(f"the {kind} range of the {distro} cluster", problems[0])
            self.assertIn("--cidr 10.123.0.0/24", problems[0])
            self.assertIn(f"--var kubernetes_distro={other}", problems[0])   # the other distribution fits there
            # the consequence of that range only
            self.assertEqual("pod routes would shadow the nodes" in problems[0], kind == "pod", problems[0])
            self.assertEqual("Service IPs would land on hosts" in problems[0], kind == "Service", problems[0])
        both = self.c.address_problems(_cfg(self.d, "10.42.0.0/15", enable_kubernetes=True))[0]
        self.assertIn("pod routes would shadow the nodes and Service IPs would land on hosts", both)
        # the same network without a cluster, or with the distribution whose ranges it misses, is fine
        self.assertEqual(self.c.address_problems(_cfg(self.d, "10.42.0.0/24")), [])
        self.assertEqual(self.c.address_problems(_cfg(self.d, "10.42.0.0/24", enable_kubernetes=True,
                                                      kubernetes_distro="kubeadm")), [])
        self.assertEqual(self.c.address_problems(_cfg(self.d, "10.100.0.0/24", enable_kubernetes=True)), [])

    def test_turning_kubernetes_on_is_refused_too(self):
        _state(self.d, ["cloudseed-lab-bastion"])   # an environment with VMs, but no cluster yet
        problems = self.c.address_problems(_cfg(self.d, "10.42.0.0/24", enable_kubernetes=True))
        self.assertTrue(any("pod range of the rke2 cluster" in p for p in problems), problems)

    def test_a_cluster_that_already_runs_there_is_only_warned_about(self):
        _state(self.d, ["cloudseed-lab-bastion", "cloudseed-lab-cp1", "cloudseed-lab-wk1"])
        with mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self.c.address_problems(_cfg(self.d, "10.42.0.0/24", enable_kubernetes=True)), [])
        self.assertIn("pod range of the rke2 cluster", warn.call_args[0][0])
        vmw._WARNED.clear()
        # a control plane whose replacement failed (tainted) is still that cluster's
        _state(self.d, ["cloudseed-lab-bastion", "cloudseed-lab-cp1"], tainted=("cloudseed-lab-cp1",))
        cfg = _cfg(self.d, "10.42.0.0/24", enable_kubernetes=True)
        cfg["provisioned"] = {"kubernetes": {"at": "2026-01-01T00:00:00Z"}}
        with mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self.c.address_problems(cfg), [])
        warn.assert_called_once()

    def test_turning_kubernetes_on_again_is_a_new_cluster(self):
        # provisioned.kubernetes stays after Kubernetes was turned off (its VMs destroyed): turning it on again creates a
        # new cluster, so the record alone must not make it an existing one
        _state(self.d, ["cloudseed-lab-bastion"])
        cfg = _cfg(self.d, "10.42.0.0/24", enable_kubernetes=True)
        cfg["provisioned"] = {"kubernetes": {"at": "2026-01-01T00:00:00Z"}}
        with mock.patch.object(ui, "warn") as warn:
            problems = self.c.address_problems(cfg)
        self.assertTrue(any("pod range of the rke2 cluster" in p for p in problems), problems)
        warn.assert_not_called()

    def test_the_ranges_are_provisions(self):
        # one source: the refusal at setup is the rule provisioning applies
        cfg = _cfg(self.d, "10.244.0.0/24", enable_kubernetes=True, kubernetes_distro="kubeadm")
        for clash in provision.local_k8s_range_problems("10.244.0.0/24", "kubeadm"):
            self.assertIn(clash, self.c.address_problems(cfg)[0])

    def test_suggestions_use_a_range_no_distribution_claims(self):
        for cidr in ("not-a-cidr", "fd00::/64"):
            text = " ".join(self.c.address_problems(_cfg(self.d, cidr)))
            self.assertIn("e.g. 10.123.0.0/24", text)
            self.assertNotIn("10.100.0.0/24", text)
        for distro in ("rke2", "kubeadm"):
            self.assertEqual(provision.local_k8s_range_problems("10.123.0.0/24", distro), [])


# ---------------------------------------------------------------- private ranges and the VMs' DNS (a2-vmware#10)

class PrivateRangeTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()
        vmw._WARNED.clear()

    def _explicit(self, cidr):
        cfg = _cfg(self.d, cidr)
        cfg["cidr_explicit"] = True
        return cfg

    def test_a_range_holding_a_dns_server_says_so(self):
        for cidr, dns in (("8.8.8.0/24", "8.8.8.8"), ("1.1.1.0/24", "1.1.1.1")):
            problem = self.c.address_problems(self._explicit(cidr))[0]
            self.assertIn("not a private (RFC 1918) range", problem)
            self.assertIn(f"DNS server {dns}", problem)
            self.assertIn(f"(e.g. {dns})", problem)
        problem = self.c.address_problems(self._explicit("9.9.9.0/24"))[0]
        self.assertNotIn("DNS", problem)
        self.assertIn("(e.g. 9.9.9.1)", problem)
        both = self.c.public_range_problem(__import__("ipaddress").ip_network("0.0.0.0/1"))
        self.assertIn("DNS servers 1.1.1.1, 8.8.8.8", both)

    def test_subnet_of_the_private_ranges_only(self):
        for cidr in ("100.64.0.0/24", "172.32.0.0/24", "192.169.0.0/24", "11.0.0.0/24"):
            self.assertTrue(self.c.address_problems(self._explicit(cidr)), cidr)
        for cidr in ("10.123.0.0/24", "172.31.9.0/24", "192.168.99.0/24"):
            self.assertEqual(self.c.address_problems(self._explicit(cidr)), [], cidr)

    def test_an_existing_environment_is_warned_once_at_setup_and_apply(self):
        _state(self.d, ["cloudseed-lab-bastion"])
        cfg = self._explicit("8.8.8.0/24")
        with mock.patch.object(ui, "warn") as warn, mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [])), \
                mock.patch.object(localvm, "list_vmnets", return_value=[]):
            self.assertEqual(self.c.address_problems(cfg), [])
            self.c._check_network(cfg, {}, None)
        warn.assert_called_once()
        self.assertIn("DNS server 8.8.8.8", warn.call_args[0][0])

    def test_guest_dns_is_what_the_modules_configure(self):
        for module in ("workloads", "kubernetes"):
            text = (TF / "modules" / module / "main.tf").read_text()
            m = re.search(r"nameservers\s*=\s*\{\s*addresses\s*=\s*\[([^\]]*)\]", text)
            self.assertIsNotNone(m, module)
            self.assertEqual(tuple(re.findall(r'"([^"]+)"', m.group(1))), vmw.GUEST_DNS, module)


# ---------------------------------------------------------------- terraform/vmware variable descriptions (docs)

class VariableDescriptionTests(unittest.TestCase):
    def test_cis_is_opt_in_in_the_distro_description(self):
        text = (TF / "variables.tf").read_text()
        block = re.search(r'variable "kubernetes_distro" \{.*?\n\}', text, re.S).group(0)
        self.assertNotIn("CIS-hardened", block)
        self.assertIn("opt-in via kubernetes_cis_profile", block)
        page = h.variables_page("vmware")
        self.assertNotIn("CIS-hardened", page)
        self.assertIn("kubernetes_cis_profile", page)

    def test_the_workers_description_names_the_pool(self):
        text = (TF / "variables.tf").read_text()
        block = re.search(r'variable "kubernetes_workers" \{.*?\n\}', text, re.S).group(0)
        self.assertIn("at most 60 on a /24", block)
        self.assertIn("MetalLB", block)


# ---------------------------------------------------------------- the implicit provider build reports on stderr

class ProviderBuildOutputTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.src = self.d / "repo" / "providers" / "vmdesktop"
        self.src.mkdir(parents=True)
        (self.src / "go.mod").write_text("module x\n")
        (self.src / "main.go").write_text("package main\n")
        self.binary = self.d / "p" / "0.1.0" / "darwin_arm64" / "terraform-provider-vmdesktop_v0.1.0"
        self.binary.parent.mkdir(parents=True)
        self.calls = []
        for p in (mock.patch.object(localvm.paths, "REPO_ROOT", self.d / "repo"),
                  mock.patch.object(localvm, "provider_binary", lambda: self.binary),
                  mock.patch.object(localvm, "write_terraform_rc"),
                  mock.patch.object(localvm.deps, "find", return_value="/usr/bin/go"),
                  mock.patch.object(localvm.deps, "version_of", return_value="1.25.0"),   # new enough for go.mod
                  mock.patch.object(localvm.deps, "path_env", return_value={}),
                  mock.patch.object(localvm.subprocess, "run", self._build)):
            p.start()
            self.addCleanup(p.stop)

    def _build(self, cmd, **kw):
        self.calls.append(kw)
        Path(cmd[cmd.index("-o") + 1]).write_text("fresh build")
        return subprocess.CompletedProcess(cmd, 0)

    def _run(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(localvm.ensure_provider(**kw), self.binary)
        return out.getvalue(), err.getvalue()

    def test_the_implicit_build_keeps_stdout_clean(self):
        out, err = self._run(stale_ok=True)          # what prepare() runs before `output --json`
        self.assertEqual(out, "")
        self.assertIn("Building terraform-provider-vmdesktop", err)
        self.assertIn("Provider installed", err)
        self.assertIn("●", err)
        self.assertIn("✔", err)
        self.assertEqual(self.binary.read_text(), "fresh build")

    def test_the_install_command_reports_on_stdout(self):
        out, err = self._run(rebuild=True)           # cloudseed install vmware-provider --rebuild
        self.assertIn("Building terraform-provider-vmdesktop", out)
        self.assertIn("Provider installed", out)
        self.assertEqual(err, "")
        self.assertIsNone(self.calls[-1].get("stdout"))

    def test_go_writes_to_stderr_during_the_implicit_build(self):
        with mock.patch.object(localvm, "_stderr_fd", return_value=2):
            self._run()
        self.assertEqual(self.calls[-1].get("stdout"), 2)

    def test_stderr_fd_without_a_real_stream(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(localvm._stderr_fd())

    def test_the_lock_wait_notice_follows_the_build(self):
        with mock.patch.object(ui, "info") as info, mock.patch.object(ui, "eprint") as eprint:
            localvm._note("Waiting for another cloudseed run (VMware provider build)...", stderr=True)
            localvm._note("x")
        self.assertIn("Waiting for another cloudseed run", eprint.call_args[0][0])
        info.assert_called_once_with("x")


# ---------------------------------------------------------------- Workstation's version on Windows

class WindowsVersionTests(unittest.TestCase):
    def _winreg(self, values: dict):
        class Key:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def open_key(hive, path):
            if path not in values:
                raise FileNotFoundError(path)
            return Key(path)

        def query(key, name):
            if name != "ProductVersion":
                raise FileNotFoundError(name)
            return values[key.path], 1

        return types.SimpleNamespace(HKEY_LOCAL_MACHINE=object(), OpenKey=open_key, QueryValueEx=query)

    def _detect(self, values: dict) -> dict:
        with mock.patch.dict(sys.modules, {"winreg": self._winreg(values)}), \
                mock.patch.object(localvm.platform, "system", return_value="Windows"), \
                mock.patch.object(localvm.platform, "machine", return_value="AMD64"), \
                mock.patch.dict(os.environ, {"VMWARE_HOME": ""}):
            return localvm.detect_host()

    def test_the_version_is_read_from_the_registry(self):
        wow, native = localvm._WORKSTATION_KEYS
        self.assertEqual(self._detect({wow: "17.5.2.23775571"})["version"], "17.5.2.23775571")
        self.assertEqual(self._detect({native: "17.6.1.24319023"})["version"], "17.6.1.24319023")
        self.assertEqual(self._detect({})["version"], "unknown")
        host = self._detect({wow: "16.2.5.20904516"})
        self.assertEqual(host["product"], "workstation")
        self.assertIn("too old", localvm.version_problem(host))       # now refusable for a new environment
        self.assertIsNone(localvm.version_problem(self._detect({wow: "17.0.2.21581411"})))

    def test_no_winreg_is_no_version(self):
        with mock.patch.dict(sys.modules, {"winreg": None}):
            self.assertIsNone(localvm._windows_workstation_version())

    def test_the_provider_reads_the_same_keys(self):
        go = (ROOT / "providers" / "vmdesktop" / "internal" / "vmware" / "host.go").read_text()
        for key in localvm._WORKSTATION_KEYS:
            self.assertIn("HKLM\\" + key, go)
        self.assertIn("windowsWorkstationVersion()", go)


# ---------------------------------------------------------------- relative vmx paths recorded by older versions

class RecordedPathTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.work = self.d / "envs" / "vmware-lab"
        self.vm_dir = self.work / "stack" / "vms"
        self.bundle = self.vm_dir / "renamed.vmwarevm"   # not named like the environment's VMs: found by its vmx only
        self.bundle.mkdir(parents=True)
        (self.bundle / "renamed.vmx").write_text("x")
        self.elsewhere = self.d / "cwd"
        self.elsewhere.mkdir()

    def test_recorded_vmx_path(self):
        rel = "vms/renamed.vmwarevm/renamed.vmx"
        self.assertEqual(localvm.recorded_vmx_path(rel, self.work), os.path.realpath(self.bundle / "renamed.vmx"))
        self.assertEqual(localvm.recorded_vmx_path("/abs/x.vmx", self.work), os.path.realpath("/abs/x.vmx"))
        self.assertEqual(vmw._recorded_path({"workdir": str(self.work)}, rel), localvm.recorded_vmx_path(rel, self.work))

    def test_sweep_resolves_them_from_the_working_directory_not_the_cwd(self):
        host = {"vmrun": "/nonexistent/vmrun", "product": "fusion"}
        rel = ["vms/renamed.vmwarevm/renamed.vmx"]
        cwd = os.getcwd()
        os.chdir(self.elsewhere)
        self.addCleanup(os.chdir, cwd)
        with mock.patch.object(localvm, "vmrun_list", return_value=[]), \
                mock.patch.object(localvm.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            self.assertEqual(localvm.sweep_vms(host, self.vm_dir, prefix="cloudseed-lab", known_vmx=rel), [])
            self.assertTrue(self.bundle.exists())                      # without the working directory: not found
            self.assertEqual(localvm.sweep_vms(host, self.vm_dir, prefix="cloudseed-lab", known_vmx=rel,
                                               workdir=self.work), ["renamed.vmwarevm"])
        self.assertFalse(self.bundle.exists())


if __name__ == "__main__":
    unittest.main()
