"""Undo: every action cloudseed performs leaves a journal entry with what is needed to revert it; `cs undo` pops the
newest entry and performs the inverse. Up to fifteen changes are kept per environment (and fifteen global ones), at
most five of one kind: a burst of one kind of change (ten kubectl edits) only pushes out older changes of that kind,
never the environment's platform installs, backups or its creation, so a working session stays undoable. Report and
info entries (finops/scan/chaos reports, "nothing to revert") have five slots of their own, so running reports never
pushes a real change out of the history. Entries are ordered by a sequence number given under the journal lock, so
"newest" holds even for changes recorded within the same second.

kind                what was recorded                         undo does
config              previous config.json                      re-apply the stack with it (config.json is only rewritten once that
                                                               worked); local cluster nodes the plan deletes are drained and taken
                                                               out of the cluster first, account-wide settings it would delete are
                                                               only dropped from the state (as a destroy does), the Velero bucket
                                                               is never removed
created             (first setup)                              destroy the environment (working directory kept)
recreate            config + keys snapshot of a destroyed env  put the files back (into its custom --workdir, registered
                                                               again) and run setup again (fresh hosts, same settings)
platform            per item: new / previous revision, or the  uninstall exactly what the run installed, roll
                    chart version + values of what was removed upgraded releases back / re-install what was removed
helm                release, namespace, previous revision      helm rollback / helm uninstall
velero-restore      pre-change Velero backup, the namespaces  delete what the change created, then restore the
                    and objects the change created (and the    backup (refused while that restore still runs:
                    restore a `dr restore` started)            --no-wait, or an interrupted --wait)
provision-prev      previous provisioning flags (or none)      re-provision with them / re-create the host unprovisioned
vpn-revoke / vpn-add   client name                             revoke / re-issue the client certificate
dr-delete           backup or schedule name                    delete it
dr-drill            what `cs dr test --keep` left: the drill   delete the namespace, then the backup (one that is
                    namespace and its backup                   already gone is fine; refused while it still runs)
argv / argv-seq     inverse command(s)                         run them
settings-restore    previous values of the keys it changed     write back those keys only (settings changed since stay)
creds-unset / creds-restore   keys / values                    remove / put back stored credentials
delete-paths        files created (reports, tools, skills)     delete them (a directory also holding files created
                                                               later is kept)
restore-files       {path: backup} of files overwritten/added  put the backups back, delete what was added; a
                                                               `k8s kubeconfig` merge only takes out the entries it
                                                               merged (other contexts stay); a purged environment
                                                               goes back into its working directory (a custom one is
                                                               registered again)
info                explanation                                nothing automatic; prints how to revert by hand

restore-files / delete-paths entries also carry a fingerprint of each file as cloudseed left it (files outside
cloudseed's home: project files, skills, kubeconfig). A file changed since is copied aside before the undo replaces
or deletes it, and the prompt says so.

The same journal serves the CLI (`cs undo`), the MCP server (cloudseed_undo), agents (skill) and the web console,
which can all run at the same time: every read-modify-write of the journal holds an exclusive lock and the file is
replaced atomically, so parallel commands never lose each other's entries.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import secrets as _secrets
import shutil
import subprocess
import tempfile
import textwrap
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import paths, ui

JOURNAL = paths.HOME / "undo.json"
LOCK = paths.HOME / "undo.lock"
BACKUPS = paths.HOME / "undo"
KEEP = 5            # real changes of one kind per scope
KEEP_TOTAL = 15     # real changes per scope (five in all were used up by one ordinary session: e2e#23)
KEEP_LIGHT = 5      # report / info entries per scope (they never evict a real change)
LIGHT_KINDS = ("info", "delete-paths")
GLOBAL = "global"
VELERO_TTL = "168h0m0s"          # pre-change backups expire on their own when their journal entry is gone
VELERO_LABEL = "cloudseed.io/undo-point=true"
# left out of whole-cluster undo points: Velero itself, and the MinIO that stores the backups (it would back itself up)
VELERO_POINT_EXCLUDED = ("velero", "minio")
_FS_BACKUP_OFF = "--default-volumes-to-fs-backup=false"

_tls = threading.local()


# ---------------------------------------------------------------- journal storage

@contextlib.contextmanager
def _locked():
    """Exclusive lock around a read-modify-write of the journal (other processes and threads wait). The lock is a
    separate file: undo.json itself is replaced on every write, so a lock on it would guard a stale inode."""
    if getattr(_tls, "depth", 0):
        _tls.depth += 1
        try:
            yield
        finally:
            _tls.depth -= 1
        return
    paths.ensure_home()
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows: best effort without a lock
        fcntl = None  # type: ignore[assignment]
    fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT, 0o600)
    _tls.depth = 1
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        _tls.depth = 0
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _load(for_write: bool = False) -> dict:
    try:
        text = JOURNAL.read_text()
    except OSError:
        return {}
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not an object")
        return data
    except ValueError:
        if not text.strip():
            return {}
        if for_write:
            # never silently overwrite a journal we cannot read: keep it for inspection, start a new one
            keep = JOURNAL.with_name(f"undo.json.corrupt-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}")
            try:
                shutil.copy2(JOURNAL, keep)
                ui.warn(f"The undo journal was unreadable; kept it as {keep} and started a new one.")
            except OSError:
                pass
        else:
            ui.warn(f"The undo journal {JOURNAL} is unreadable (it is kept aside on the next change).")
        return {}


def _save(data: dict) -> None:
    paths.ensure_home()
    fd, tmp = tempfile.mkstemp(dir=str(JOURNAL.parent), prefix=".undo.", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, JOURNAL)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_minor(entry: dict) -> bool:
    """Report / info entries: undoable, but never worth evicting a real change for."""
    return isinstance(entry, dict) and (bool(entry.get("minor")) or entry.get("kind") in LIGHT_KINDS)


def _trim(stack: list[dict]) -> list[dict]:
    """Keep the newest KEEP real changes of each kind, the newest KEEP_TOTAL real changes in all and the newest
    KEEP_LIGHT report/info entries; returns what was dropped (the stack is oldest first)."""
    heavy = [e for e in stack if not is_minor(e)]
    light = [e for e in stack if is_minor(e)]
    drop = {id(e) for e in light[:-KEEP_LIGHT]}
    by_kind: dict = {}
    for e in heavy:
        by_kind.setdefault(str(e.get("kind")), []).append(e)
    for same in by_kind.values():
        drop |= {id(e) for e in same[:-KEEP]}
    drop |= {id(e) for e in [e for e in heavy if id(e) not in drop][:-KEEP_TOTAL]}
    dropped = [e for e in stack if id(e) in drop]
    stack[:] = [e for e in stack if id(e) not in drop]
    return dropped


def _next_seq(j: dict) -> int:
    """The next entry's sequence number: one more than any entry in the journal (only the order matters, so numbers
    freed by undone or trimmed entries may come back)."""
    return 1 + max((e["seq"] for st in j.values() if isinstance(st, list) for e in st
                    if isinstance(e, dict) and isinstance(e.get("seq"), int)), default=0)


def record(scope: str, summary: str, kind: str, data: dict | None = None, *, minor: bool = False,
           coalesce: str | None = None) -> dict:
    """scope: environment id (aws-dev) or 'global'.

    minor=True   the entry only reverts a report/bookkeeping file: it has its own KEEP_LIGHT slots and never pushes a
                 real change out of the history (kinds info and delete-paths are always minor).
    coalesce=KEY a run of entries with the same key (env switches, repeated ssh commands) takes one slot: the newest
                 summary is shown, the OLDEST data is kept, so one undo goes back to before the whole run.

    The same change recorded twice in a row (same kind, summary and data: `vpn connect` twice, `enable ui` twice ...)
    also takes one slot: its inverse reverts both, and a second copy would only push an older change out.

    restore-files / delete-paths entries get a fingerprint of each file as it is now (cloudseed has just written it),
    so the undo can tell when someone changed it since."""
    if os.environ.get("CLOUDSEED_UNDOING"):
        return {}   # actions performed by an undo do not create new entries (no redo chains)
    data = copy.deepcopy(data or {})
    if kind in ("restore-files", "delete-paths") and "written" not in data:
        written = _written(kind, data)
        if written:
            data["written"] = written
    dropped: list[dict] = []
    with _locked():
        j = _load(for_write=True)
        # stamped under the lock: the order of `at` and seq is the order in which entries reached the journal
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        seq = _next_seq(j)
        stack = j.get(scope)
        if not isinstance(stack, list):
            stack = j[scope] = []
        top = stack[-1] if stack and isinstance(stack[-1], dict) else None
        if coalesce and top is not None and top.get("coalesce") == coalesce and top.get("kind") == kind:
            entry = top
            entry.update(at=now, summary=summary, seq=seq)
            _refresh_written(entry, data)
        elif not coalesce and top is not None and _same_change(top, summary, kind, data, minor):
            entry = top
            entry.update(at=now, seq=seq)
            _refresh_written(entry, data)
        else:
            entry = {"id": time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + _secrets.token_hex(3), "at": now,
                     "seq": seq, "scope": scope, "summary": summary, "kind": kind, "data": data}
            if minor:
                entry["minor"] = True
            if coalesce:
                entry["coalesce"] = coalesce
            stack.append(entry)
            dropped = _trim(stack)
        _save(j)
    for old in dropped:
        _discard_backups(old)
    return entry


def _refresh_written(entry: dict, data: dict) -> None:
    """A merged repeat: the files now look as the newest run left them."""
    if data.get("written"):
        entry.setdefault("data", {}).setdefault("written", {}).update(data["written"])


def update_data(entry: dict) -> None:
    """Write an entry's (changed) data back to the journal, e.g. what a failed undo still has to do on its retry."""
    with _locked():
        j = _load(for_write=True)
        stack = j.get(entry.get("scope"))
        for e in stack if isinstance(stack, list) else []:
            if isinstance(e, dict) and e.get("id") == entry.get("id"):
                e["data"] = copy.deepcopy(entry.get("data") or {})
                _save(j)
                return


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def _sans_written(data: dict) -> dict:
    return {k: v for k, v in (data or {}).items() if k != "written"}


def _same_change(entry: dict, summary: str, kind: str, data: dict, minor: bool) -> bool:
    """Is `entry` exactly this change (a repeat of the same command with the same inverse)?"""
    return (entry.get("kind") == kind and entry.get("summary") == summary and not entry.get("coalesce")
            and bool(entry.get("minor")) == bool(minor)
            and _canon(_sans_written(entry.get("data") or {})) == _canon(_sans_written(data)))


def backup_file(path: Path | str) -> str | None:
    """Copy a file (or directory) aside so an undo can put it back. Returns the backup path, or None when it does not exist."""
    p = Path(path).expanduser()
    if not p.exists():
        return None
    BACKUPS.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BACKUPS, 0o700)
    except OSError:
        pass
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    while True:   # unique even for two files with the same name backed up in the same second
        dest = BACKUPS / f"{stamp}-{_secrets.token_hex(4)}-{p.name}"
        if not dest.exists() and not dest.is_symlink():
            break
    if p.is_dir():
        shutil.copytree(p, dest, symlinks=True)
    else:
        shutil.copy2(p, dest)
    return str(dest)


def _under_backups(p: Path) -> bool:
    """p lies inside BACKUPS (p itself is not resolved: a link there is removed, never what it points to)."""
    if p.name in ("", ".", ".."):
        return False
    root = Path(os.path.realpath(BACKUPS))
    return root in (Path(os.path.realpath(p.parent)) / p.name).parents


def _discard_backups(entry: dict) -> None:
    """Delete the copies only this entry kept (file backups, a purged environment's config/keys/state record). Only
    paths inside BACKUPS are ever touched; paths recorded by the container runtime are mapped to this machine first."""
    d = (entry.get("data") if isinstance(entry, dict) else None) or {}
    if not isinstance(d, dict):
        return
    for b in list((d.get("files") or {}).values()) + [d.get("backup_dir")]:
        if not b:
            continue
        p = _local(b)
        if not _under_backups(p):
            continue
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
    # Velero pre-change backups are not deleted here (that needs the cluster, and trimming happens inside unrelated
    # commands): they carry a TTL and the cloudseed.io/undo-point label, so Velero expires them on its own.


def clear(scope: str) -> None:
    with _locked():
        j = _load(for_write=True)
        gone = j.pop(scope, []) or []
        _save(j)
    for e in gone if isinstance(gone, list) else []:
        _discard_backups(e)


def scopes() -> list[str]:
    """Every scope that has history (environment ids, 'global'), including environments that no longer exist."""
    return [s for s, st in _load().items() if st and isinstance(st, list)]


def _in_scope(s: str, scope) -> bool:
    if scope is None:
        return True
    if isinstance(scope, (list, tuple, set, frozenset)):
        return s in scope
    return s == scope


def _order(e: dict) -> tuple:
    """Oldest first: by sequence number (entries written before there was one come first, by time)."""
    seq = e.get("seq")
    return (seq if isinstance(seq, int) else 0, str(e.get("at") or ""))


def entries(scope=None) -> list[dict]:
    """Entries of one scope, a collection of scopes, or all (None), oldest first."""
    j = _load()
    return sorted([e for s, st in j.items() if _in_scope(s, scope) and isinstance(st, list) for e in st if isinstance(e, dict)],
                  key=_order)


def latest(scope=None) -> dict | None:
    e = entries(scope)
    return e[-1] if e else None


def pop(entry: dict) -> None:
    with _locked():
        j = _load(for_write=True)
        stack = j.get(entry["scope"])
        kept = [e for e in stack if not (isinstance(e, dict) and e.get("id") == entry["id"])] if isinstance(stack, list) else []
        if kept:
            j[entry["scope"]] = kept
        else:
            j.pop(entry["scope"], None)
        _save(j)


def drop(entry: dict) -> None:
    """Forget an entry without undoing it (and delete the file backups only it referenced)."""
    pop(entry)
    _discard_backups(entry)


def describe(entry: dict) -> str:
    k, d = entry["kind"], entry["data"]
    return {
        "config": lambda: f"restore the previous configuration of {entry['scope']} and re-apply the stack (Terraform converges back: {d.get('what', 'settings')})",
        "created": lambda: f"destroy everything in {entry['scope']} (it did not exist before); the working directory is kept",
        "recreate": lambda: f"put the saved configuration and keys of {entry['scope']} back and run setup again (fresh hosts, same settings, provisioning included)",
        "platform": lambda: _describe_platform(d),
        "helm": lambda: (f"helm rollback {d['release']} to revision {d['revision']} in {d['ns']}" if d.get("revision") else f"helm uninstall {d['release']} in {d['ns']}"),
        "velero-restore": lambda: _describe_velero_restore(d),
        "provision-prev": lambda: _describe_provision(d),
        "argv": lambda: "run: cloudseed " + " ".join(d["argv"]),
        "argv-seq": lambda: "run: " + "  then  ".join("cloudseed " + " ".join(a) for a in d["argvs"]),
        "vpn-revoke": lambda: f"revoke the VPN client certificate '{d['name']}'",
        "vpn-add": lambda: f"re-issue a VPN client certificate and profile for '{d['name']}'",
        "dr-delete": lambda: f"delete Velero {d['what']} '{d['name']}'",
        "dr-drill": lambda: _describe_drill(d),
        "settings-restore": lambda: "restore the previous settings (" + (", ".join(d.get("what") or []) or "all of them") + ")",
        "creds-unset": lambda: "remove stored credential(s): " + ", ".join(d["keys"]),
        "creds-restore": lambda: _creds_text(d),
        "delete-paths": lambda: "delete: " + ", ".join(str(Path(p).name) for p in d["paths"][:6]) + (" …" if len(d["paths"]) > 6 else ""),
        "restore-files": lambda: (_kube_text(entry) if _kube_target(entry) is not None else
                                  _purge_text(entry) if _purge_target(entry) is not None else _files_text(d)),
        "info": lambda: "nothing automatic (" + d.get("advice", "no automatic inverse") + ")",
    }.get(k, lambda: k)()


def _describe_drill(d: dict) -> str:
    """A kept DR drill (`cs dr test --keep`): its namespace and, when it got that far, its backup."""
    ns = d.get("namespace") or "cloudseed-dr-test"   # (dr.DRILL_NS; dr is not imported for a describe)
    return f"delete the kept DR drill namespace {ns}" + (f" and its Velero backup {d['backup']}" if d.get("backup") else "")


def _creds_text(d: dict) -> str:
    """A creds-restore entry: previous values to put back and/or keys (new at the time) to remove."""
    parts = (["put back the previous value of stored credential(s): " + ", ".join(d["values"])] if d.get("values") else []) + \
            (["remove stored credential(s): " + ", ".join(d["unset"])] if d.get("unset") else [])
    return "; ".join(parts) or "nothing"


def _files_text(d: dict) -> str:
    """'put back a, b; delete c, d; then run: cloudseed ...' for a restore-files entry (None backup = file was new).
    Paths in cloudseed's home are named relative to it (bin/go, go/: a bare 'go' cannot tell the link from the Go
    toolchain next to it), others by their name; a directory ends in /."""
    back = [(p, b) for p, b in d["files"].items() if b]
    new = [(p, None) for p, b in d["files"].items() if not b]
    names = _shown_paths(back + new)
    short = lambda xs: ", ".join(xs[:6]) + (" …" if len(xs) > 6 else "")  # noqa: E731
    parts = (["put back " + short(names[:len(back)])] if back else []) + \
            (["delete " + short(names[len(back):])] if new else []) + \
            ["then run: cloudseed " + " ".join(a) for a in _then(d)]
    return "; ".join(parts) or "nothing"


def _shown_paths(pairs: list) -> list[str]:
    """How restore-files paths ((path, backup) pairs) are named to the user: relative to cloudseed's home, else by name;
    a name that two paths share (two clients' mcp.json) is given from ~ or in full instead."""
    shown = []
    for p, backup in pairs:
        pp = _local(p)
        try:
            is_dir = (pp.is_dir() and not pp.is_symlink()) or (backup is not None and _local(backup).is_dir())
        except OSError:
            is_dir = False
        rel = _relative_to(pp, paths.HOME)
        shown.append([rel if rel is not None else pp.name, pp, "/" if is_dir else "", rel is not None])
    counts: dict = {}
    for name, _pp, _slash, _in_home in shown:
        counts[name] = counts.get(name, 0) + 1
    out = []
    for name, pp, slash, in_home in shown:
        if counts[name] > 1 and not in_home:
            home = _relative_to(pp, Path.home())
            name = "~/" + home if home is not None else str(pp)
        out.append(name + slash)
    return out


def _relative_to(pp: Path, root) -> str | None:
    """pp relative to root as a/b, None when it is not inside it (or is root itself). Its directory is resolved, its
    last part is not: the link bin/go is named bin/go, not the go/bin/go it points to."""
    try:
        real = Path(os.path.realpath(pp.parent)) / pp.name
        rel = real.relative_to(os.path.realpath(root))
    except (ValueError, OSError, RuntimeError):
        return None
    return rel.as_posix() if str(rel) not in ("", ".") else None


def _new_namespaces(d: dict) -> list[str]:
    """The namespaces a change created (a velero-restore entry's new_namespaces), anything malformed left out."""
    return [n for n in d.get("new_namespaces") or [] if isinstance(n, str) and n and not n.startswith("-")]


def _describe_velero_restore(d: dict) -> str:
    """The inverse of a cluster change backed by a Velero undo point: what the change created goes, the rest comes back
    from the backup (a restore never deletes objects that are not in it)."""
    new_ns = _new_namespaces(d)
    groups = _created_objects(d, skip_ns=new_ns)
    refs = [f"{r} in {ns}" if ns else r for ns, rs in groups.items() for r in rs]
    parts = []
    if refs:
        parts.append(f"delete the {len(refs)} object(s) the change created ({', '.join(refs[:4])}{', …' if len(refs) > 4 else ''})")
    if new_ns:
        parts.append(f"delete the namespace(s) it created ({', '.join(new_ns)})")
    head = f"restore Velero backup {d['backup']} (taken right before the change)"
    return (" and ".join(parts) + ", then " + head) if parts else head


_NS_KINDS = ("namespace", "namespaces", "ns")


def _created_objects(d: dict, skip_ns=()) -> dict:
    """{namespace or None: ['kind[.group]/name', ...]} of the objects a kubectl change created (data['created']), minus
    the namespaces in skip_ns themselves (they are deleted as namespaces). Objects inside those namespaces stay listed:
    a cluster-scoped object applied with -n carries that namespace too, and deleting the namespace would not take it
    away. Anything malformed (or shaped like a flag) is left out."""
    out: dict = {}
    for c in d.get("created") or []:
        if not isinstance(c, dict):
            continue
        ref, ns = c.get("ref"), c.get("ns") or None
        if not isinstance(ref, str) or "/" not in ref or ref.startswith("-") or \
                (ns is not None and (not isinstance(ns, str) or ns.startswith("-"))):
            continue
        kind, name = ref.split("/", 1)
        if kind.lower() in _NS_KINDS and name in skip_ns:
            continue
        refs = out.setdefault(ns, [])
        if ref not in refs:
            refs.append(ref)
    return out


def _then(d: dict) -> list[list[str]]:
    """Commands a restore-files entry runs after the files are back: one argv or a list of argvs."""
    then = d.get("then") or []
    return [list(a) for a in then] if then and isinstance(then[0], (list, tuple)) else ([list(then)] if then else [])


# provisioned-host key (cfg["provisioned"]) -> (`cloudseed provision --host` value, Terraform module of the host)
PROVISION_HOSTS = {"bastion": ("bastion", "bastion"), "vpn": ("vpn", "vpn"), "kubernetes": ("k8s", "kubernetes")}


def _provision_hosts(d: dict) -> dict:
    """{host key: its provisioning flags before the change, or None}. Entries written before one entry covered every
    provisioned host carry a single label/prev; their label 'k8s' is the key 'kubernetes'."""
    if d.get("hosts") is not None:
        return dict(d["hosts"])
    label = d.get("label") or "bastion"
    return {"kubernetes" if label == "k8s" else label: d.get("prev")}


def _describe_provision(d: dict) -> str:
    parts = []
    for host, prev in _provision_hosts(d).items():
        module = PROVISION_HOSTS.get(host, (host, host))[1]
        if prev and module == "kubernetes":
            parts.append("Kubernetes: nothing automatic (re-running the install reverts nothing)")
        elif prev:
            flags = [f for f, on in (("--no-harden", not prev.get("harden", True)), ("--no-firewall", not prev.get("firewall", True)),
                                     ("--no-tools", not prev.get("tools", True))) if on]
            parts.append(f"re-provision the {host} with its previous settings ({' '.join(flags) or 'defaults'})")
        else:
            parts.append(f"re-create the {host} unprovisioned (destroy --target module.stack.module.{module}, then apply)")
    return "; ".join(parts) or "nothing"


def _describe_platform(d: dict) -> str:
    if d.get("steps"):
        back = [f"roll {s['release']} back to revision {s['prev_revision']}" for s in d["steps"] if s.get("prev_revision")]
        gone = [s["item"] for s in d["steps"] if not s.get("prev_revision")]
        return "; ".join(back + ([f"uninstall platform item(s): {', '.join(reversed(gone))}"] if gone else []))
    if d.get("restore") is not None:
        objects = sum(int((d["restore"].get(i) or {}).get("count") or 0) for i in d["items"]
                      if (d["restore"].get(i) or {}).get("objects"))
        return (f"re-install platform item(s): {', '.join(d['items'])} (same chart version and values)"
                + (f", then create the {objects} custom resource(s) the forced removal deleted" if objects else ""))
    return f"{d['inverse']} platform item(s): {', '.join(d['items'])}"


def _env(scope: str):
    from . import clouds
    cloud_key, env_name = scope.split("-", 1)
    return clouds.get(cloud_key), paths.Env(cloud_key, env_name)


def _run_cli(argv: list[str]) -> None:
    """Run the inverse command in-process. It gets its own audit record (tagged parent=undo) and must not leave the
    outer `cs undo` with its state: the audit session, and the non-interactive flag a nested `-y` sets."""
    from . import audit, cli
    os.environ["CLOUDSEED_UNDOING"] = "1"
    non_interactive = ui.NON_INTERACTIVE
    try:
        with audit.nested("undo"):
            rc = cli.main(list(argv))
    finally:
        os.environ.pop("CLOUDSEED_UNDOING", None)
        ui.NON_INTERACTIVE = non_interactive
    if rc != 0:
        raise ui.Abort(f"`cloudseed {' '.join(argv)}` failed (exit {rc}); the undo entry is kept so you can retry")


def _cluster(scope: str):
    from . import cli, platform as platformmod, services
    cloud, env = _env(scope)
    cfg = env.load()
    outputs = cli._cached_outputs(env)
    return cloud, env, cfg, outputs, platformmod.Cluster(cloud, env, cfg, outputs, services.ensure_kubeconfig(cloud, env, cfg, outputs))


# a local cluster node VM in the vmware stack: module.stack.module.kubernetes[0].vmdesktop_vm.node["wk2"]
_NODE_VM = re.compile(r'vmdesktop_vm\.node\["((?:cp|wk)\d+)"\]$')


def _plan_nodes(changes: list[dict], cfg: dict, want) -> list[str]:
    """Node names (<name>-<env>-wk2 ...) whose VM change in the plan passes want(actions)."""
    out: list[str] = []
    for c in changes:
        m = _NODE_VM.search(str(c.get("address") or ""))
        if m and want(list(c.get("actions") or [])):
            out.append(f"{cfg['name']}-{cfg['env']}-{m.group(1)}")
    return out


def _created_nodes(changes: list[dict] | None, cfg: dict) -> list[str] | None:
    """Node names whose VM the saved plan creates or replaces: those need to join the cluster, with a fresh host key.
    None when the plan cannot be read."""
    if changes is None:
        return None
    return _plan_nodes(changes, cfg, lambda a: "create" in a)


def _local(p: str | Path) -> Path:
    """A path recorded by this or another runtime (the container used to record /root/.cloudseed/...)."""
    from . import container
    return container.host_path(p)


def _audit_start(entry: dict) -> None:
    """The undo's own trail: which entry it reverts, written to the environment's log (not only the global one)."""
    from . import audit
    audit.tag(undo={"id": entry.get("id"), "kind": entry.get("kind"), "scope": entry.get("scope"), "summary": entry.get("summary")})
    if entry.get("scope") and entry["scope"] != GLOBAL:
        try:
            _cloud, env = _env(entry["scope"])
            if env.dir.exists():
                audit.attach(env)
        except Exception:  # noqa: BLE001 - an unknown scope must not stop the undo itself
            pass
    audit.write(f"undo: starting '{entry.get('summary')}' ({entry.get('kind')}): {describe(entry)}")


def perform(entry: dict, settings: dict, auto: bool) -> None:
    from . import cli, creds, platform as platformmod, services
    _audit_start(entry)
    k, d = entry["kind"], entry["data"]
    if k == "created":
        cli._approve(f"Destroy everything in {entry['scope']}?", auto)
        cloud_key, env_name = entry["scope"].split("-", 1)
        _run_cli(["destroy", cloud_key, "--env", env_name, "-y", "--auto-approve"])
    elif k == "config":
        _undo_config(entry, auto)
    elif k == "recreate":
        cloud, env = _env(entry["scope"])
        target = _recreate_workdir(entry, env)      # a custom --workdir: checked before anything is asked or changed
        cli._approve(f"Re-create {env.id} from its saved configuration (new hosts, billable resources)?", auto)
        if d.get("backup_dir") and not env.exists():
            if target is not None:
                env = _register_workdir(target)     # the purge forgot it: files put back there must be found again
            env.create_dirs()
            b = _local(d["backup_dir"])
            for name in ("config.json", "outputs.json"):
                if (b / name).exists():
                    shutil.copy2(b / name, env.dir / name)
            if (b / "ssh").exists():
                shutil.copytree(b / "ssh", env.ssh_dir, dirs_exist_ok=True)
                for p in env.ssh_dir.iterdir():
                    os.chmod(p, 0o600)
            if (b / "bootstrap").exists():   # the record of the state storage the destroy kept: --purge-state can delete it
                shutil.copytree(b / "bootstrap", env.bootstrap_dir, dirs_exist_ok=True)
        if not env.exists():
            env.create_dirs()
            env.save(d["cfg"])
        _run_cli(["setup", cloud.key, "--env", env.name, "-y", "--auto-approve"])
        _restore_current_env(entry, settings)
    elif k == "platform":
        cloud, env, cfg, outputs, ctx = _cluster(entry["scope"])
        cli._approve(f"{_describe_platform(d)} on {env.id}?", auto)
        if d.get("steps"):   # undo an install: newest first, exactly what that run changed (never older dependencies)
            from . import deps
            platformmod.ensure_tools()   # helm and kubectl (installed only with consent): a rollback runs helm itself
            helm = deps.find("helm")
            new: list[str] = []      # consecutive new items go to uninstall() together: it orders them by dependency
            for s in reversed(d["steps"]):
                if s.get("prev_revision"):
                    if new:
                        platformmod.uninstall(new, ctx)
                        new = []
                    platformmod._run([helm, "rollback", s["release"], str(s["prev_revision"]), "-n", s["ns"]], ctx)
                elif s.get("item") not in new:
                    new.append(s["item"])
            if new:
                platformmod.uninstall(new, ctx)
        elif d["inverse"] == "uninstall":
            platformmod.uninstall(d["items"], ctx)
        elif d.get("restore") is not None:   # undo an uninstall: the removed items with their chart version and values
            platformmod.ensure_tools()
            if d.get("mode"):
                ctx.options["mode"] = d["mode"]
            releases = platformmod.installed_releases(ctx)
            for item in d["items"]:
                r = d["restore"].get(item) or {}
                values = r.get("values") if r.get("values") and Path(r["values"]).exists() else None
                platformmod.install_one(item, ctx, True, r.get("version"), None, releases, values_file=values)
            # the custom resources a --force removal of CRD charts deleted: once every item (controllers, webhooks) is back
            for item in d["items"]:
                objects = (d["restore"].get(item) or {}).get("objects")
                if objects and Path(objects).exists():
                    platformmod.restore_crd_objects(ctx, objects)
        else:   # an entry of an older version: install the items again (undo prints its own result, no closing panel)
            platformmod.install(d["items"], ctx, wait=True, summary=False)
    elif k == "helm":
        cloud, env, cfg, outputs, ctx = _cluster(entry["scope"])
        args = ["rollback", d["release"], str(d["revision"]), "-n", d["ns"]] if d.get("revision") else ["uninstall", d["release"], "-n", d["ns"]]
        cli._approve(f"helm {' '.join(args)}?", auto)
        helm = services.ensure_tool("helm", "to undo the helm change")
        status = subprocess.run([helm, "status", d["release"], "-n", d["ns"]], env=ctx.procenv(), capture_output=True, text=True)
        if status.returncode != 0 and "not found" in (status.stderr + status.stdout).lower():
            if not d.get("revision"):
                ui.warn(f"helm release {d['release']} is already gone from {d['ns']}; nothing to uninstall.")
                return
            raise ui.Abort(f"helm release {d['release']} no longer exists in {d['ns']}, so it cannot be rolled back.")
        platformmod._run([helm, *args], ctx)
    elif k == "velero-restore":
        from . import dr
        cloud, env, cfg, outputs, ctx = _cluster(entry["scope"])
        _check_restore_finished(ctx, d)
        new_ns = _new_namespaces(d)
        created = _created_objects(d, skip_ns=new_ns)
        what = _describe_velero_restore(d)
        cli._approve(what[:1].upper() + what[1:] + "?", auto)
        for ns in new_ns:
            dr._kubectl(ctx, "delete", "ns", ns, "--ignore-not-found", "--wait=false")
        # objects the change created are not in the backup, so the restore would leave them in place (e2e2#1)
        _delete_created(ctx, created)
        dr.restore(ctx, d["backup"], None, wait=True)
        _verify_restored(ctx, d["backup"], new_ns)
        # the backup itself is kept (it expires through its TTL): if the restore turns out incomplete it is still there
    elif k == "provision-prev":
        cloud, env = _env(entry["scope"])
        for host, prev in _provision_hosts(d).items():
            flag, module = PROVISION_HOSTS.get(host, (host, host))
            if prev and module == "kubernetes":
                ui.warn("Kubernetes: re-running the install reverts nothing, so nothing is done for it. To remove the "
                        f"cluster: cloudseed setup {cloud.key} --env {env.name} --var enable_kubernetes=false")
                continue
            if prev:
                argv = ["provision", cloud.key, "--env", env.name, "--host", flag] + \
                    (["--no-harden"] if not prev.get("harden", True) else []) + \
                    (["--no-firewall"] if not prev.get("firewall", True) else []) + \
                    (["--no-tools"] if not prev.get("tools", True) else [])
                cli._approve(f"Re-provision the {host} with its previous settings?", auto)
                _run_cli(argv)
                continue
            what = "every Kubernetes node VM (workloads running on them are lost)" if module == "kubernetes" else f"the {host} host"
            cli._approve(f"Re-create {what} without provisioning? This destroys module.stack.module.{module}, then "
                         "re-applies the whole stack.", auto)
            _run_cli(["destroy", cloud.key, "--env", env.name, "--target", f"module.stack.module.{module}", "-y", "--auto-approve"])
            _run_cli(["apply", cloud.key, "--env", env.name, "-y", "--auto-approve"])
            cfg = env.load()        # the re-created host is unprovisioned: status/troubleshoot must say so
            if host in (cfg.get("provisioned") or {}):
                cfg["provisioned"].pop(host)
                env.save(cfg)
            env.forget_host_keys()
    elif k == "argv":
        cli._approve("Run `cloudseed " + " ".join(d["argv"]) + "`?", auto)
        # the question above was the approval (it raised otherwise): the recorded argv carries -y, so the nested
        # command cannot ask again; entries that need an approval get --auto-approve
        _run_cli(list(d["argv"]) + (["--auto-approve"] if d.get("approve") and "--auto-approve" not in d["argv"] else []))
    elif k == "argv-seq":
        if d.get("restore"):   # the namespaces a `dr restore` creates: deleted only once that restore has finished
            _check_restore_finished(_cluster(entry["scope"])[4], d)
        cli._approve("Run: " + "  then  ".join("cloudseed " + " ".join(a) for a in d["argvs"]) + " ?", auto)
        for a in d["argvs"]:
            _run_cli(list(a))
    elif k == "vpn-revoke":
        cloud, env = _env(entry["scope"])
        cli._approve(f"Revoke VPN client '{d['name']}'?", auto)
        services.revoke_user(cloud, env, env.load(), cli._cached_outputs(env), d["name"])
    elif k == "vpn-add":
        cloud, env = _env(entry["scope"])
        cli._approve(f"Issue a new VPN certificate for '{d['name']}'?", auto)
        path = services.add_user(cloud, env, env.load(), cli._cached_outputs(env), d["name"])
        ui.ok(f"Profile saved: {path}")
    elif k == "dr-delete":
        from . import dr
        cloud, env, cfg, outputs, ctx = _cluster(entry["scope"])
        cli._approve(f"Delete Velero {d['what']} '{d['name']}'?", auto)
        dr._velero(ctx, d["what"], "delete", d["name"], "--confirm")
    elif k == "dr-drill":
        _undo_drill(entry, auto)
    elif k == "settings-restore":
        _restore_settings(d)
        ui.ok("Settings restored.")
    elif k == "creds-unset":
        cli._approve(f"Remove the stored credential(s) {', '.join(d['keys'])}?", auto)
        for key in d["keys"]:
            creds.unset(key)
    elif k == "creds-restore":            # values: previous values to put back; unset: keys that did not exist before
        cli._approve(f"Change the credential vault: {_creds_text(d)}?", auto)
        for key, val in (d.get("values") or {}).items():
            if creds.valid_key(key):
                creds.set_(key, val)
            else:
                ui.warn(f"{key} not restored: the vault no longer accepts that variable name")
        for key in d.get("unset") or []:
            creds.unset(key)
    elif k == "delete-paths":
        pairs = [(str(p), _local(p)) for p in d["paths"]]
        changed = _changed(d, pairs)
        question = f"Delete {len(pairs)} file(s)/dir(s) created by '{entry['summary']}'?"
        if changed:
            _warn_changed(entry, changed, "deletes")
            question = question[:-1] + " (copies of the changed files are kept)?"
        cli._approve(question, auto)
        _keep_copies(changed)
        _delete_paths([pp for _key, pp in pairs])
    elif k == "restore-files":
        target = _kube_target(entry)
        if target is None or not _unmerge_kubeconfig(entry, target, auto):
            _restore_files(entry, auto)
            if _purge_target(entry) is not None:
                _restore_current_env(entry, settings)
        for argv in _then(d):               # e.g. restart a server so it loads the restored token
            _run_cli(argv)
    elif k == "info":
        ui.warn(d.get("advice", "no automatic inverse"))
    else:
        raise ui.Abort(f"unknown undo kind {k}")


# Velero restore phases of a restore that is still running (it may still create or update objects)
_RESTORE_RUNNING = ("New", "InProgress", "WaitingForPluginOperations", "WaitingForPluginOperationsPartiallyFailed",
                    "Finalizing", "FinalizingPartiallyFailed")


def _check_restore_finished(ctx, d: dict) -> None:
    """A `dr restore --no-wait` (or an interrupted --wait) leaves its Restore running in the cluster: undoing it now
    would delete and restore objects while Velero still writes them. Refused until it has finished; a phase that
    cannot be read (None) does not stop the undo."""
    name = d.get("restore")
    if not name or not isinstance(name, str):
        return
    from . import dr
    phase = dr._phase(ctx, "restore", name)
    if phase in _RESTORE_RUNNING:   # a restore still writing objects would put back what the undo deletes
        raise ui.Abort(f"Restore {name} is still {phase}; undo it once it has finished "
                       f"(follow it: {dr.velero_hint(ctx, 'restore', 'describe', name)}). The undo entry is kept.")


def _undo_drill(entry: dict, auto: bool) -> None:
    """Remove what `cs dr test --keep` left: the drill namespace first (so nothing writes into it any more), then its
    backup (Velero deletes the backup's data in the bucket too). A namespace or backup that is already gone is fine;
    one that could not be removed keeps the entry."""
    from . import cli, dr
    from . import secrets as _sec
    d = entry["data"]
    _cloud, _env_, _cfg, _outputs, ctx = _cluster(entry["scope"])
    backup = d.get("backup") if isinstance(d.get("backup"), str) and not d["backup"].startswith("-") else ""
    if backup:
        # a drill interrupted with --keep can leave its backup running: Velero accepts the delete request, then refuses
        # it while the backup is in progress, and the backup would stay (no TTL) with the entry gone
        phase = dr._phase(ctx, "backup", backup)
        if phase is None:   # no velero CLI here (the delete below then runs in the velero pod): the Backup object says it
            got = dr._kubectl(ctx, "-n", "velero", "get", "backups.velero.io", backup, "-o", "jsonpath={.status.phase}",
                              timeout=60)
            phase = (got.stdout or "").strip() if got.returncode == 0 else ""
            phase = phase or None   # (no phase read: unknown, which does not stop the undo)
        if phase is not None and phase not in dr.BACKUP_DONE:
            raise ui.Abort(f"Velero backup {backup} is still {phase}, and Velero does not delete a backup in progress; "
                           "undo it once it has finished (cs dr backups). The undo entry is kept.")
    what = _describe_drill(d)
    cli._approve(what[:1].upper() + what[1:] + "?", auto)
    ns = str(d.get("namespace") or dr.DRILL_NS)
    if not ns.startswith("-"):
        proc = dr._kubectl(ctx, "delete", "ns", ns, "--ignore-not-found", "--wait=false")
        if proc.returncode != 0:
            why = _sec.redact((proc.stderr or proc.stdout or "").strip())[-300:] or f"exit {proc.returncode}"
            raise ui.Abort(f"Could not delete namespace {ns}: {why}. The undo entry is kept; run the same `cs undo` again "
                           "once the cluster answers.")
    if not backup:
        return
    try:
        proc = dr._velero(ctx, "backup", "delete", backup, "--confirm", check=False, quiet=True)
    except ui.Abort:   # no velero CLI here (none is fetched in this run): the velero pod has one
        proc = dr._kubectl(ctx, "-n", "velero", "exec", dr.SERVER, "-c", "velero", "--", "/velero", "-n", "velero",
                           "backup", "delete", backup, "--confirm", timeout=120)
    out = (proc.stderr or "") + (proc.stdout or "")
    gone = "not found" in out.lower() or any(g in out for g in _GONE_KIND)   # the backup (or Velero with it) is gone
    if proc.returncode != 0 and not gone:
        raise ui.Abort(f"The drill namespace is being deleted, but Velero backup {backup} could not be: "
                       f"{dr.velero_error(proc)}. The undo entry is kept; run the same `cs undo` again (a backup already "
                       "gone is fine then).")


# ---------------------------------------------------------------- config: re-apply the previous configuration

def _undo_config(entry: dict, auto: bool) -> None:
    """Re-apply the configuration from before the change. config.json is only rewritten once the apply worked; a
    declined, failed or interrupted run puts the rendered root back as it was."""
    from . import audit, cli
    from .tf import Terraform
    d = entry["data"]
    cloud, env = _env(entry["scope"])
    if not env.exists():
        raise ui.Abort(f"{entry['scope']} no longer exists; nothing to undo.")
    cfg = env.load()
    prev = _config_to_restore(cloud, env, cfg, d)
    t = Terraform(env.stack_dir)
    rebuilt: list[str] | None = None
    leaving: list[str] = []
    prepared = False
    try:
        # local adapters: the provider, vmrest and images; GCP: the OS Login key is registered again when the previous
        # configuration uses OS Login (a rotation or `OS Login off` removed it from the Google account)
        if cloud.local or cloud.key == "gcp":
            cloud.prepare(prev)
            prepared = True
        ui.info(f"Planning {env.id} with its configuration from before: {entry['summary']}")
        backend_changed = cli._render(cloud, env, prev)
        t.init(migrate=backend_changed)
        # a singleton the previous configuration only had on by default and that exists now (a GuardDuty detector
        # someone else enabled since) is left alone instead of stopping the undo: switched off in prev, which is saved
        # below with the applied plan
        t.plan_for_apply(cloud.key, prev, render=lambda c: cli._render(cloud, env, c))
        changes = cli._plan_changes(t)
        leaving = _leaving_nodes(cloud, env, cfg, prev, changes, auto)
        if cloud.local and d.get("rejoin_nodes"):
            rebuilt = _created_nodes(changes, prev)
        keep = _kept_settings(cloud, cfg, changes)
        if keep:   # the plan above lists them as deleted: say that they are not
            ui.warn("Kept in place (account/subscription-wide, only dropped from the state, as a destroy does): "
                    + cli._kept_types(keep))
        cli._approve(_config_question(cloud, env, cfg, prev, leaving), auto)
        if cloud.local and d.get("rejoin_nodes"):
            rebuilt = _remember_rejoin(entry, rebuilt)
        gone_ips = _leave_nodes(cloud, env, cfg, leaving) if leaving else []
        if keep:
            _forget_kept(t, keep, changes)
        t.apply_reconciled(cloud.key, prev, approve=lambda q: cli._approve(q, auto))
    except BaseException:
        # declined, failed or interrupted: config.json was never touched; put the rendered root back to match it
        try:
            cli._render(cloud, env, cfg)
        except Exception:  # noqa: BLE001 - keep the original error
            pass
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        if prepared and cloud.key == "gcp":
            # an OS Login key prepare() registered for nothing: the configuration in effect is cfg (a prepare that
            # failed registered nothing, and prev may still hold the record of a key released long ago)
            _release_os_login(cloud, prev, cfg)
        raise
    env.save(prev)
    ui.info(f"Configuration of {env.id} restored to before: {entry['summary']}")
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    cli._settle_kept(env, prev, t)      # kept shared settings that are back in the state are no longer "kept"
    outputs = cli._cache_outputs(env, t)
    audit.refresh(env, t, "undo", {"of": entry["summary"]})
    if cloud.local and outputs:   # e.g. undoing `--var enable_kubernetes=true`: the record of its cluster goes with it
        cli._forget_removed_cluster(env, prev, outputs)
    _release_os_login(cloud, cfg, prev)      # e.g. undoing `OS Login on`: the key it registered is removed again
    if gone_ips:
        from . import provision as prov
        for ip in gone_ips:   # a VM created later on this fixed address has a new host key
            prov.forget_host_key(env, ip)
        ui.ok(f"{', '.join(leaving)} left the cluster and {'its VM was' if len(leaving) == 1 else 'their VMs were'} deleted.")
        if _node_count(prev, "kubernetes_workers", 2) <= 0 < _node_count(cfg, "kubernetes_workers", 2):
            ui.info(f"No workers left: let the control plane(s) run workloads with: cs provision {cloud.key} --env {env.name} --host k8s")
    if cloud.local and outputs.get("kubernetes_control_plane_ips") and d.get("rejoin_nodes"):
        from . import provision as prov
        harden = cli._saved_harden(prev)   # new nodes join the way the cluster was provisioned (setup --no-harden)
        if rebuilt is not None:  # a node of a failed earlier attempt that is gone again has nothing left to join
            rebuilt = [n for n in rebuilt if n in _node_names(prev, outputs)]
        try:
            if rebuilt is None:      # the plan could not be read: re-run the (idempotent) install on every node
                prov.provision_local_kubernetes(cloud, env, prev, outputs, harden=harden)
            elif rebuilt:            # only the node VMs this apply (re)created join; their old host keys are forgotten
                prov.provision_local_kubernetes(cloud, env, prev, outputs, limit=rebuilt, harden=harden)
        except ui.Abort as e:
            again = f"joins {', '.join(rebuilt)}" if rebuilt else "runs the Kubernetes install on every node again"
            raise ui.Abort(f"{(e.msg or 'Kubernetes installation failed').rstrip('. ')}. The configuration of {env.id} is already "
                           f"restored; the undo entry is kept, and running the same `cs undo` again {again}.",
                           code=e.code) from None


def _is_prereqs_entry(d: dict) -> bool:
    """The entry of a platform item's cloud prerequisites: the one change that edits platform_prereqs."""
    return d.get("prereqs") is not None or str(d.get("what") or "").startswith("cloud prerequisites")


def _config_to_restore(cloud, env, cfg: dict, d: dict) -> dict:
    """The configuration a config undo applies: the recorded one, with what the reverted change did not make carried
    over from the current configuration."""
    prev = copy.deepcopy(d["prev_cfg"])
    # local facts of the environment are not part of the change being reverted; the state backend stays where it is
    # too (undo never migrates state; re-run setup to move it). os_login records the OS Login registration of the SSH
    # key, which is carried over, so it follows the key (prepare() checks it again).
    for key in ("workdir", "ssh_public_key", "ssh_private_key_path", "provisioned", "state", "os_login"):
        if key in cfg:
            prev[key] = copy.deepcopy(cfg[key])
    # cloud prerequisites of platform items (the Velero bucket, Karpenter's roles) change only through their own entry:
    # undoing an older update-ip / node / setup entry must not take them away with it (a2-platform-logic#11)
    have = [p for p in cfg.get("platform_prereqs") or [] if isinstance(p, str)]
    if not _is_prereqs_entry(d):
        want = list(have)
    else:
        # Velero's bucket follows the current configuration either way: every backup lives in it (force_destroy
        # deletes them all), so an undo never removes it, nor brings back one that was deliberately dropped since
        want = [p for p in prev.get("platform_prereqs") or [] if isinstance(p, str) and (p != "velero" or p in have)]
    if "velero" in have and "velero" not in want:   # only an entry of an older version still asks for its removal
        want.append("velero")
        ui.info(f"The Velero {'storage account' if cloud.key == 'azure' else 'bucket'} and its identity stay: they hold "
                f"the backups. To delete them deliberately, remove velero from platform_prereqs in {env.config_path}, "
                f"then: cs apply {cloud.key} --env {env.name}")
    if want or "platform_prereqs" in cfg or "platform_prereqs" in prev:
        prev["platform_prereqs"] = want
    return prev


def _release_os_login(cloud, old: dict, new: dict) -> None:
    """GCP: remove from the Google account an OS Login key `old` registered that `new` no longer uses (never one
    cloudseed did not add, nor one another environment uses). Best effort; other clouds have nothing to release."""
    release = getattr(cloud, "release_os_login", None)
    if release is None:
        return
    try:
        release(old, new)
    except Exception:  # noqa: BLE001 - it warns on its own; an undo that worked must not fail over it
        pass


def _on(value) -> bool:
    from .clouds.base import as_bool
    try:
        return as_bool(value)
    except ValueError:
        return False


def _node_count(cfg: dict, key: str, default: int) -> int:
    value = (cfg.get("vars") or {}).get(key, default)
    try:
        return int(str(default if value in (None, "") else value).strip())
    except (TypeError, ValueError):
        return default


_NODE_ROLES = (("wk", "kubernetes_workers", 2), ("cp", "kubernetes_control_planes", 1))


def _node_key(name: str) -> tuple:
    """Sort key: workers before control planes, the highest number first (VMs go from the highest number down)."""
    m = re.search(r"-(cp|wk)(\d+)$", name)
    return (m.group(1) == "cp", -int(m.group(2))) if m else (True, 0)


def _leaving_nodes(cloud, env, cfg: dict, prev: dict, changes: list[dict] | None, auto: bool) -> list[str]:
    """Numbered node VMs (<name>-<env>-wk3 ...) the plan deletes while the cluster itself stays. Like `cs node remove`,
    the undo drains them and takes them out of the cluster (a kubeadm control plane's etcd member too) before their VM
    goes; deleted without that, a control plane would stay an etcd member and cost the cluster its quorum. When the
    plan cannot be read: the nodes numbered above the previous counts, refused under --auto-approve (nobody reviews
    the plan then). Never the last control plane."""
    from . import cli
    if not cloud.local or not (_on((cfg.get("vars") or {}).get("enable_kubernetes")) and
                               _on((prev.get("vars") or {}).get("enable_kubernetes"))):
        return []    # no cluster now, or the undo takes the whole cluster away: there is nothing left to drain into
    if not cli._cached_outputs(env).get("kubernetes_control_plane_ips"):
        return []    # no node VM was created yet: nothing can be deleted
    base = f"{cfg.get('name')}-{cfg.get('env')}"
    if changes is None:
        names = [f"{base}-{role}{i}" for role, key, default in _NODE_ROLES
                 for i in range(_node_count(prev, key, default) + 1, _node_count(cfg, key, default) + 1)]
        if names and auto:
            raise ui.Abort(f"The plan of this undo could not be read, and the configuration it restores has fewer nodes: "
                           f"{', '.join(names)} would be deleted without leaving the cluster first. Nothing was changed. "
                           f"Take them out first with cs node remove <name> {cloud.key} --env {env.name}, or run the "
                           "undo at a terminal without --auto-approve to review the plan.")
    else:
        names = _plan_nodes(changes, cfg, lambda a: "delete" in a and "create" not in a)
    names = sorted(dict.fromkeys(names), key=_node_key)
    if f"{base}-cp1" in names:
        raise ui.Abort(f"This undo would delete every control plane of {env.id} ({', '.join(n for n in names if '-cp' in n)}), "
                       "which destroys the cluster and everything running in it. Nothing was changed. To remove the "
                       f"cluster on purpose: cs setup {cloud.key} --env {env.name} --var enable_kubernetes=false; to skip "
                       "this step: cs undo --drop.")
    return names


def _config_question(cloud, env, cfg: dict, prev: dict, leaving: list[str]) -> str:
    if not leaving:
        return "Apply this plan (undo)?"
    them = "it" if len(leaving) == 1 else "them"
    q = f"Drain {', '.join(leaving)}, take {them} out of the cluster and delete {them} with this plan (undo)?"
    if any("-wk" in n for n in leaving) and _node_count(prev, "kubernetes_workers", 2) <= 0:
        ui.warn(f"No worker is left afterwards: pods have nowhere to go until the control plane(s) run workloads "
                f"(cs provision {cloud.key} --env {env.name} --host k8s lets them).")
    return q


def _node_ip(outputs: dict, name: str) -> str | None:
    m = re.search(r"-(cp|wk)(\d+)$", name)
    if not m:
        return None
    ips = outputs.get("kubernetes_control_plane_ips" if m.group(1) == "cp" else "kubernetes_worker_ips") or []
    idx = int(m.group(2))
    return ips[idx - 1] if 0 < idx <= len(ips) else None


def _leave_nodes(cloud, env, cfg: dict, names: list[str]) -> list[str]:
    """Take `names` out of the cluster before the apply deletes their VMs, highest number first, with the current
    configuration (the one the nodes were built with). A node that never registered only gets a kubeadm control
    plane's reset. Stops (nothing applied, the undo entry kept) when a step fails. Returns the nodes' IPs."""
    from . import cli, deps, services
    outputs = cli._cached_outputs(env)
    ips = [ip for ip in (_node_ip(outputs, n) for n in names) if ip]
    if not services.kubeconfig_path(env).exists():
        # provisioning writes it once the cluster is up: without it no node ever joined (cs provision ... --host k8s)
        ui.info(f"{env.id} has no kubeconfig yet (Kubernetes was never installed on its node VMs), so "
                f"{', '.join(names)} {'has' if len(names) == 1 else 'have'} no cluster to leave.")
        return ips
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    kubectl = services.ensure_tool("kubectl", "to take the removed nodes out of the cluster")
    kenv = dict(deps.path_env(), KUBECONFIG=str(kc))
    for name in names:
        registered = cli._node_json_or_none(kubectl, kenv, name) is not None
        ui.info(f"Taking {name} out of the cluster before its VM is deleted")
        cli._leave_local_node(cloud, env, cfg, outputs, kubectl, kenv, name, registered=registered)
    return ips


def _kept_settings(cloud, cfg: dict, changes: list[dict] | None) -> list[tuple[str, str]]:
    """Account/subscription/project-wide settings (cloud.keep_on_destroy: the AWS S3 public-access block and EBS
    encryption default, Azure Defender plans, GCP log retention ...) that the plan deletes outright, e.g. undoing
    `--var enable_account_baseline=true`. As in a destroy they are only dropped from the state: deleting them would
    switch the protection off for everything else in the account (aws#20). Nothing when the plan cannot be read.
    cfg: the configuration in effect, which made them (its values fill the notices, e.g. the retention it set)."""
    if not changes:
        return []
    gone = [c["address"] for c in changes if "delete" in (c.get("actions") or []) and "create" not in (c.get("actions") or [])
            and c.get("mode", "managed") != "data" and c.get("address")]
    return list(cloud.keep_on_destroy(cfg, gone)) if gone else []


def _forget_kept(t, keep: list[tuple[str, str]], changes: list[dict] | None) -> None:
    """Drop the kept settings from the state (the objects stay) and plan again: the saved plan would still delete them,
    and Terraform refuses a plan whose state changed. The new plan may only delete less than the reviewed one."""
    from . import cli
    for addr, _ in keep:
        t.run("state", "rm", addr, capture=True)     # a failure stops here: nothing is deleted that must be kept
    t.run("plan", "-input=false", "-out=tfplan", "-no-color", capture=True)
    reviewed = {c["address"] for c in changes or [] if "delete" in (c.get("actions") or [])}
    now = t._deleting("tfplan")
    extra = sorted(now - reviewed) if now is not None else None
    if extra is None or extra:
        why = ("could not be read (terraform show -json tfplan failed), so it cannot be checked for deletions"
               if extra is None else f"would also delete {', '.join(extra)}, which the plan you approved did not")
        raise ui.Abort(f"After dropping {cli._kept_types(keep)} from the state (the settings themselves stay in place), "
                       f"the new plan {why}. Nothing was applied and config.json is unchanged; the undo entry is kept.")
    ui.info("Left in place (account/subscription-wide settings, now unmanaged): " + cli._kept_types(keep))
    for notice in dict.fromkeys(n for _, n in keep if n):
        ui.info(notice)


# ---------------------------------------------------------------- config: nodes still to join

def _node_names(cfg: dict, outputs: dict) -> set:
    """Names of the local cluster's node VMs as the playbook's inventory names them (<name>-<env>-cp1 ... -wk2)."""
    base = f"{cfg.get('name')}-{cfg.get('env')}"
    return ({f"{base}-cp{i + 1}" for i in range(len(outputs.get("kubernetes_control_plane_ips") or []))} |
            {f"{base}-wk{i + 1}" for i in range(len(outputs.get("kubernetes_worker_ips") or []))})


def _remember_rejoin(entry: dict, rebuilt: list[str] | None) -> list[str] | None:
    """The node VMs this apply (re)creates, plus those an earlier attempt created but could not join: their VM exists
    by now, so the plan no longer shows them. Saved in the entry before the apply, so a retry after a failed join (or
    an interrupted run) still joins them; the list goes away with the entry once the undo worked. None (the install
    runs on every node): the plan could not be read, now or on an earlier attempt whose install did not finish."""
    d = entry["data"]
    if rebuilt is None or d.get("rejoin_all"):
        if not d.get("rejoin_all"):
            d["rejoin_all"] = True
            update_data(entry)
        return None
    pending = [n for n in d.get("pending_rejoin") or [] if isinstance(n, str)]
    out = list(dict.fromkeys(pending + list(rebuilt)))
    if out != pending:
        d["pending_rejoin"] = out
        update_data(entry)
    if pending:
        ui.info(f"Also joining the node(s) an earlier attempt of this undo re-created: {', '.join(pending)}")
    return out


# ---------------------------------------------------------------- settings

def _restore_settings(d: dict) -> None:
    """Write back only the keys the entry changed (a key that did not exist before is removed again): settings changed
    since - runtime, agent, mcp/ui, the current environment ... - stay as they are. An entry without a key list
    (written by hand or by an old version) restores its whole snapshot."""
    snap = d.get("settings") or {}
    what = [k for k in d.get("what") or [] if isinstance(k, str)]
    if not what:
        paths.save_settings(copy.deepcopy(snap))
        return
    cur = paths.load_settings()
    for key in what:
        if key in snap:
            cur[key] = copy.deepcopy(snap[key])
        else:
            cur.pop(key, None)
    paths.save_settings(cur)
    env_id = cur.get("current_env") if "current_env" in what else None
    if env_id and env_id not in {e.id for e in paths.Env.list_all()}:
        ui.warn(f"The current environment is {env_id} again, but it no longer exists. Choose another with "
                "`cs env use <id>`, or `cs env clear`.")


# ---------------------------------------------------------------- files: fingerprints, restore, delete

_HASH_MAX = 8 << 20          # bigger files are compared by size + modification time instead of their content
_IGNORED = (".DS_Store",)    # Finder writes these into any folder it shows: never a change of the user's


def _inside_home(p: Path) -> bool:
    """p lies in cloudseed's home: its own state (tokens, envs, tools), which the user does not edit by hand."""
    home = os.path.realpath(paths.HOME)
    real = os.path.realpath(p)
    return real == home or real.startswith(home.rstrip(os.sep) + os.sep)


def _fingerprint(p: Path) -> str | None:
    """What a file, link or directory tree holds now (None when it does not exist or cannot be read)."""
    try:
        if p.is_symlink():
            return "link:" + os.readlink(p)
        if p.is_file():
            st = p.stat()
            if st.st_size > _HASH_MAX:
                return f"stat:{st.st_size}:{st.st_mtime_ns}"
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            return "sha256:" + h.hexdigest()
        if p.is_dir():
            h = hashlib.sha256()
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for name in sorted(dirs + files):
                    if name in _IGNORED:
                        continue
                    full = Path(root) / name
                    sub = "dir" if full.is_dir() and not full.is_symlink() else _fingerprint(full)
                    h.update(f"{full.relative_to(p).as_posix()}\0{sub}\0".encode())
            return "tree:" + h.hexdigest()
    except OSError:
        return None
    return None


def _written(kind: str, data: dict) -> dict:
    """{recorded path: fingerprint} of the files a restore-files / delete-paths entry would replace or delete, as the
    command just left them. Files in cloudseed's home are left out (cloudseed itself rewrites those, e.g. a token
    before a restart), and so is a directory of a recursive listing (only emptied, never deleted whole)."""
    keys = [str(k) for k in ((data.get("files") or {}) if kind == "restore-files" else (data.get("paths") or []))]
    out: dict = {}
    for key in keys:
        pp = _local(key)
        if _inside_home(pp):
            continue
        if kind == "delete-paths" and pp.is_dir() and not pp.is_symlink() and _in_listing(key, keys):
            continue
        fp = _fingerprint(pp)
        if fp:
            out[key] = fp
    return out


def _has_listed_child(key: str, keys) -> bool:
    prefix = str(key).rstrip(os.sep) + os.sep
    return any(str(k).startswith(prefix) for k in keys)


def _in_listing(key: str, keys) -> bool:
    """A recorded directory that is part of a recursive listing (a scan's rglob of scans/): files in it, or the folder
    it sits in, were recorded too. Such a folder - also one that was still empty when it was recorded - is only removed
    once nothing else is in it; files a later run put there stay."""
    k = str(key).rstrip(os.sep)
    return _has_listed_child(k, keys) or os.path.dirname(k) in {str(x).rstrip(os.sep) for x in keys}


def _changed(d: dict, pairs) -> list[Path]:
    """Files (of (recorded path, local path) pairs) that someone changed after the command recorded them."""
    written = d.get("written") or {}
    out: list[Path] = []
    for key, pp in pairs:
        before = written.get(key)
        if not before:
            continue
        now = _fingerprint(pp)
        if now is not None and now != before:
            out.append(pp)
    return out


def _warn_changed(entry: dict, changed: list[Path], verb: str = "replaces or deletes") -> None:
    shown = ", ".join(str(p) for p in changed[:4]) + (" …" if len(changed) > 4 else "")
    ui.warn(f"Changed since '{entry['summary']}': {shown}. Undoing it {verb} "
            f"{'that file' if len(changed) == 1 else 'those files'}, so a copy of your version is kept first.")


def _keep_copy(pp: Path) -> Path:
    """Copy a changed file aside before the undo replaces or deletes it: next to it (<name>.cloudseed-undo-<time>),
    or, for a directory (a skill folder would be read as a second skill), into ~/.cloudseed/undo-kept."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if pp.is_dir() and not pp.is_symlink():
        root = paths.HOME / "undo-kept"
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        dest = root / f"{stamp}-{_secrets.token_hex(2)}-{pp.name}"
        shutil.copytree(pp, dest, symlinks=True)
        return dest
    dest, n = pp.with_name(f"{pp.name}.cloudseed-undo-{stamp}"), 1
    while dest.exists() or dest.is_symlink():
        dest, n = pp.with_name(f"{pp.name}.cloudseed-undo-{stamp}-{n}"), n + 1
    shutil.copy2(pp, dest, follow_symlinks=False)
    return dest


def _keep_copies(changed: list[Path]) -> None:
    for pp in changed:
        try:
            kept = _keep_copy(pp)
        except OSError as e:
            raise ui.Abort(f"Could not keep a copy of {pp} ({e.strerror or e}); nothing was undone. The undo entry is kept.") from None
        ui.info(f"Your version of {pp} is kept as {kept}")


def _delete_paths(pps: list[Path]) -> None:
    """Delete what a command created. A recorded directory of a recursive listing (a scan's scans/raw/ with its files
    and sub-folders) is only removed once those are gone and nothing else is left in it: files a later run put there
    stay. A directory recorded on its own (a tool or skill folder) goes as a whole."""
    listed = [str(pp) for pp in pps]
    gone: list[str] = []
    dirs: list[Path] = []
    for pp in pps:
        if pp.is_dir() and not pp.is_symlink():
            dirs.append(pp)
        elif pp.exists() or pp.is_symlink():
            pp.unlink(missing_ok=True)
        else:
            gone.append(str(pp))
    kept: list[str] = []
    for pp in sorted(dirs, key=lambda x: len(x.parts), reverse=True):
        if not _in_listing(str(pp), listed):
            shutil.rmtree(pp, ignore_errors=True)
            continue
        try:
            left = list(pp.iterdir())
            if left and all(x.name in _IGNORED for x in left):
                for x in left:
                    x.unlink(missing_ok=True)
            pp.rmdir()
        except OSError:
            if pp.exists():
                kept.append(str(pp))
    if gone:
        ui.warn(f"{len(gone)} of {len(pps)} path(s) were already gone: " + ", ".join(gone[:4]) + (" …" if len(gone) > 4 else ""))
    if kept:
        ui.info(f"Kept {len(kept)} folder(s) that also hold files this step did not create: " + ", ".join(kept[:4]) +
                (" …" if len(kept) > 4 else ""))


def _same_path(a, b) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except (OSError, ValueError, TypeError):
        return False


def _purge_target(entry: dict) -> tuple[paths.Env, Path] | None:
    """(the environment, the working directory it lived in) of a `destroy --purge` entry that puts a never-deployed
    environment back; None for any other entry. The directory is the recorded workdir (a custom --workdir), else the
    one its config.json is mapped back into. It need not be where the environment id points now: the environment
    may have been set up again elsewhere since (_check_purge_restore refuses that)."""
    d = entry.get("data") or {}
    scope = str(entry.get("scope") or "")
    if not d.get("backup_dir") or scope == GLOBAL or "-" not in scope or not isinstance(d.get("files"), dict):
        return None
    cloud_key, name = scope.split("-", 1)
    targets = [_local(p) for p in d["files"]]
    where = _local(d["workdir"]) if d.get("workdir") else next((p.parent for p in targets if p.name == "config.json"), None)
    if where is None:
        return None
    try:
        env = paths.Env(cloud_key, name, where)
    except Exception:  # noqa: BLE001 - an odd scope is simply not an environment
        return None
    return env, where


def _default_dir(env: paths.Env, where: Path) -> bool:
    return _same_path(where, paths.ENVS_DIR / env.id)


def _purge_text(entry: dict) -> str:
    env, where = _purge_target(entry)   # type: ignore[misc]  (only called for a purge entry)
    at = "" if _default_dir(env, where) else f" in {where}"
    return (f"put {entry['scope']} back as it was before the purge{at}: its configuration, SSH keys and history "
            "(nothing is deployed)")


def _recreate_workdir(entry: dict, env: paths.Env) -> tuple[paths.Env, Path] | None:
    """(the environment, its directory) when a `recreate` entry puts a purged environment back into a custom --workdir
    (data['workdir']), which the purge dropped from workdirs.json; None for the default directory, when nothing is put
    back (it exists again) or for an older entry without it. Refused here, before anything is asked, when that
    directory cannot be the environment's any more (another environment's now, or files that are not cloudseed's)."""
    d = entry.get("data") or {}
    if not d.get("backup_dir") or not d.get("workdir") or env.exists():
        return None
    where = _local(d["workdir"])
    target = paths.Env(env.cloud, env.name, where)
    if _default_dir(target, where):
        return None
    problem = paths.workdir_problem(where, env.id)
    if problem:
        raise ui.Abort(f"{env.id} cannot go back into {where}: {problem} The undo entry is kept.")
    return target, where


def _restore_current_env(entry: dict, settings: dict | None) -> None:
    """A purge that unset the environment as the current one recorded it (data['current_env']): once the environment
    is back it is current again - unless another one was chosen in the meantime."""
    want = (entry.get("data") or {}).get("current_env")
    if not want or want != entry.get("scope"):
        return
    cur = paths.load_settings()
    if cur.get("current_env"):
        return
    cur["current_env"] = want
    paths.save_settings(cur)
    if isinstance(settings, dict):
        settings["current_env"] = want
    ui.info(f"{want} is the current environment again (as before the purge).")


def _check_purge_restore(target: tuple, items: list) -> None:
    """Before anything is asked or changed: may the purged environment go back into its directory? Not when it was
    set up again since (there or in another directory), nor into a directory that meanwhile went to another
    environment or holds files that are not cloudseed's. The config the undo itself already put back (a retry after a
    failure part-way) is fine."""
    env, where = target
    cur = paths.Env(env.cloud, env.name)          # where the id points now (workdirs.json)
    if cur.exists() and not _same_path(cur.dir, where):
        raise ui.Abort(f"{env.id} was set up again since it was purged (in {cur.dir}), so its old configuration is not "
                       "put back. The undo entry is kept.")
    now = where / "config.json"
    if now.exists():
        owner = paths.config_owner(now)
        if owner and owner != env.id:
            raise ui.Abort(f"{where} now holds the configuration of {owner}, so {env.id} cannot go back there. The undo "
                           "entry is kept.")
        backup = next((b for _key, pp, b in items if b is not None and _same_path(pp, now)), None)
        try:
            same = backup is not None and backup.read_bytes() == now.read_bytes()
        except OSError:
            same = False
        if not same:
            raise ui.Abort(f"{env.id} was set up again since it was purged, so its files are not overwritten with the "
                           "old ones. The undo entry is kept.")
    if not _default_dir(env, where):
        problem = paths.workdir_problem(where, env.id)
        if problem:
            raise ui.Abort(f"{env.id} cannot go back into {where}: {problem} The undo entry is kept.")


def _register_workdir(target: tuple) -> paths.Env:
    """Point the environment id at its directory again and create it (private). The purge dropped a custom working
    directory from workdirs.json, and files put back into it without that stay invisible to every command; a claim
    left elsewhere would hide one put back into the default directory."""
    env, where = target
    cur = paths.Env(env.cloud, env.name)
    if not _default_dir(env, where):
        cur.set_workdir(where)
    elif env.id in paths._load_index():
        cur.set_workdir(None)
    else:
        cur.create_dirs()        # private (0700), like every directory cloudseed creates; ssh/ too
    return cur


def _restore_history(env: paths.Env, d: dict) -> None:
    """A purged environment's inventory history and audit trail come back with it (copies: the kept trail in
    logs/purged/<id> stays), unless the restore brought them already."""
    kept = paths.HOME / "logs" / "purged" / env.id
    backup = _local(d["backup_dir"]) if d.get("backup_dir") else None
    for rel in ("inventory.json", "logs/audit.jsonl"):
        dest = env.dir / rel
        if dest.exists():
            continue
        for src in ([backup / rel] if backup is not None else []) + [kept / Path(rel).name]:
            if not src.is_file():
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                os.chmod(dest, 0o600)
            except OSError as e:
                ui.warn(f"Could not put {dest.name} back ({e.strerror or e}); a copy is in {src.parent}")
            break


def _restore_files(entry: dict, auto: bool) -> None:
    from . import cli
    d = entry["data"]
    items = [(str(p), _local(p), _local(b) if b else None) for p, b in d["files"].items()]
    lost = [str(pp) for _key, pp, b in items if b is not None and not b.exists()]
    if lost:
        # a backup that should exist but does not: refuse rather than delete the user's current file
        raise ui.Abort(f"The backup of {', '.join(lost)} is missing from {BACKUPS}; not touching those files. "
                       "The undo entry is kept.")
    target = _purge_target(entry)
    if target is not None:
        _check_purge_restore(target, items)
    changed = _changed(d, [(key, pp) for key, pp, _b in items])
    back = sum(1 for _key, _pp, b in items if b is not None)
    added = len(items) - back
    if back:
        question = f"Put back {back} file(s)/dir(s) as they were before '{entry['summary']}'" + \
            (f" and delete the {added} it added?" if added else "?")
    else:
        question = f"Delete the {added} file(s)/dir(s) '{entry['summary']}' added?"
    if changed:
        new = {pp for _key, pp, b in items if b is None}
        _warn_changed(entry, changed, "deletes" if all(p in new for p in changed) else
                      "puts back the previous version of" if not any(p in new for p in changed) else "replaces or deletes")
        question = question[:-1] + " (copies of the changed files are kept)?"
    cli._approve(question, auto)
    _keep_copies(changed)
    env = _register_workdir(target) if target is not None else None
    for _key, pp, b in items:
        if b is not None:
            pp.parent.mkdir(parents=True, exist_ok=True)
            if b.is_dir():
                if pp.is_symlink() or pp.is_file():
                    pp.unlink()
                else:
                    shutil.rmtree(pp, ignore_errors=True)
                shutil.copytree(b, pp, symlinks=True)
            else:
                shutil.copy2(b, pp)
        elif pp.is_dir() and not pp.is_symlink():   # the file did not exist before the change: remove it
            shutil.rmtree(pp, ignore_errors=True)
        else:
            pp.unlink(missing_ok=True)
    if env is not None:
        _restore_history(env, d)
        from . import audit
        try:
            audit.attach(env)    # the rest of this undo's trail goes to the environment's own log again
        except OSError:
            pass
        if not _default_dir(env, env.dir):
            ui.info(f"{env.id} is registered again with its working directory {env.dir}")


# ---------------------------------------------------------------- kubeconfig (`cs k8s kubeconfig`)

_KUBE_KINDS = ("contexts", "clusters", "users")


def _kube_target(entry: dict) -> Path | None:
    """The kubeconfig a `cs k8s kubeconfig` entry merged into, or None for any other entry."""
    d = entry.get("data") or {}
    files = d.get("files") or {}
    if entry.get("kind") != "restore-files" or len(files) != 1:
        return None
    if d.get("kubeconfig") is None and not (str(entry.get("summary") or "").startswith("k8s kubeconfig ")
                                            and entry.get("scope") not in (None, GLOBAL)):
        return None
    return _local(next(iter(files)))


def _kube_text(entry: dict) -> str:
    target = _kube_target(entry)
    names = ((entry.get("data") or {}).get("kubeconfig") or {}).get("names") or {}
    what = ", ".join(names.get("contexts") or []) or "the cluster entries it merged"
    return (f"take {what} out of {target} again (entries it replaced get their previous version back; contexts added "
            "since by other tools are kept)")


def _kube_view(kubectl: str, path: Path) -> dict | None:
    try:
        proc = subprocess.run([kubectl, "config", "view", "--raw", "-o", "json", "--kubeconfig", str(path)],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _kube_names(entry: dict, kubectl: str) -> dict:
    """{kind: names} cloudseed merged into the kubeconfig for this environment: as recorded by the merge, else the
    environment's merge record (merged.json), its vmware-<env> names, and the names of its own kubeconfig."""
    kc = (entry.get("data") or {}).get("kubeconfig") or {}
    if isinstance(kc.get("names"), dict):
        return {k: {n for n in kc["names"].get(k) or [] if isinstance(n, str)} for k in _KUBE_KINDS}
    names: dict = {k: set() for k in _KUBE_KINDS}
    scope = str(entry.get("scope") or "")
    if "-" not in scope:
        return names
    cloud_key, env_name = scope.split("-", 1)
    env = paths.Env(cloud_key, env_name)
    try:
        rec = json.loads((env.dir / "k8s" / "merged.json").read_text())
    except (OSError, ValueError):
        rec = {}
    for k in _KUBE_KINDS:
        names[k] |= {n for n in (rec.get(k) or [] if isinstance(rec, dict) else []) if isinstance(n, str)}
    if cloud_key == "vmware":        # local clusters are always merged as vmware-<env>
        for k in _KUBE_KINDS:
            names[k].add(f"vmware-{env_name}")
    else:                            # a managed cluster is merged under the names of its own kubeconfig
        own = env.dir / "k8s" / "kubeconfig"
        mine = _kube_view(kubectl, own) if own.exists() else None
        for k in _KUBE_KINDS:
            names[k] |= {x.get("name") for x in (mine or {}).get(k) or [] if isinstance(x, dict) and x.get("name")}
    return names


def _write_private(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_kubeconfig(kubectl: str, target: Path, data: dict) -> None:
    """Write a kubeconfig (JSON in) as kubectl's own YAML, atomically and private. The JSON goes to a file next to the
    target, so relative certificate paths keep meaning the same files."""
    from . import secrets as _sec
    real = Path(os.path.realpath(target))
    try:
        fd, tmp = tempfile.mkstemp(dir=str(real.parent), prefix=".cloudseed-kubeconfig.", suffix=".json")
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh)
            proc = subprocess.run([kubectl, "config", "view", "--raw", "--kubeconfig", tmp], capture_output=True,
                                  text=True, timeout=60)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if proc.returncode != 0 or not proc.stdout.strip():
            raise ui.Abort(f"Could not write {target}: {_sec.redact(proc.stderr.strip())[-300:] or 'kubectl failed'}. "
                           "Nothing was changed; the undo entry is kept.")
        _write_private(real, proc.stdout)
    except (OSError, subprocess.SubprocessError) as e:
        raise ui.Abort(f"Could not write {target} ({getattr(e, 'strerror', None) or e}). Nothing was changed; the undo "
                       "entry is kept.") from None


def _unmerge_kubeconfig(entry: dict, target: Path, auto: bool) -> bool:
    """Undo `cs k8s kubeconfig` entry by entry: take out the contexts/clusters/users it merged, give the ones it replaced
    their previous version back and switch back to the previous current context. Everything else in the file - contexts
    other tools (aws eks, gcloud, kubectl) added since - stays. Returns False when kubectl is not available: the file
    as a whole is put back then (a copy of the current one is kept when it changed since)."""
    from . import cli, deps
    kubectl = deps.find("kubectl")
    if not kubectl:
        return False
    d = entry["data"]
    backup_s = next(iter(d["files"].values()))
    backup = _local(backup_s) if backup_s else None
    if backup is not None and not backup.exists():
        raise ui.Abort(f"The backup of {target} is missing from {BACKUPS}; not touching it. The undo entry is kept.")
    if not target.exists():
        ui.info(f"{target} does not exist any more; nothing to take out of it.")
        return True
    now = _kube_view(kubectl, target)
    before = _kube_view(kubectl, backup) if backup is not None else {}
    if now is None or before is None:
        raise ui.Abort(f"kubectl cannot read {target if now is None else backup}; nothing was changed. The undo entry is kept.")
    names = _kube_names(entry, kubectl)
    if not any(names.values()):
        ui.info(f"There is no record of what `{entry['summary']}` merged (the cluster files of {entry['scope']} are gone), "
                f"so nothing in {target} is touched.")
        return True
    prev = {k: {x.get("name"): x for x in before.get(k) or [] if isinstance(x, dict) and x.get("name")} for k in _KUBE_KINDS}
    new = copy.deepcopy(now)
    removed: list[str] = []
    restored: list[str] = []
    used: set = set()
    for kind in _KUBE_KINDS:          # contexts first: a cluster or user a remaining context still uses stays
        out = []
        for x in now.get(kind) or []:
            n = x.get("name") if isinstance(x, dict) else None
            if n not in names[kind]:
                out.append(x)
            elif n in prev[kind]:
                if x != prev[kind][n]:
                    restored.append(f"{kind[:-1]} {n}")
                out.append(copy.deepcopy(prev[kind][n]))
            elif kind != "contexts" and n in used:
                out.append(x)
            else:
                removed.append(f"{kind[:-1]} {n}")
        new[kind] = out
        if kind == "contexts":
            used = {(c.get("context") or {}).get(f) for c in out if isinstance(c, dict) for f in ("cluster", "user")}
    cur = now.get("current-context") or ""
    kc = d.get("kubeconfig") or {}
    switch = None
    if cur and (cur in names["contexts"] or cur == kc.get("set_current")):
        back = kc["prev_current"] if "prev_current" in kc else (before.get("current-context") or "")
        back = back if back in {c.get("name") for c in new["contexts"] if isinstance(c, dict)} else ""
        if back != cur:
            new["current-context"] = back
            switch = f"switch the current context back to {back}" if back else "unset the current context"
    empty = not any(new.get(k) for k in _KUBE_KINDS)
    plan = ((["remove " + ", ".join(removed)] if removed else []) + (["put back the previous " + ", ".join(restored)] if restored else []) +
            ([switch] if switch else []))
    if backup is None and empty:
        plan = [f"delete {target} (it did not exist before, and nothing else is in it now)"]
    if not plan:
        ui.info(f"{target} holds nothing {entry['scope']} merged into it any more; nothing to take out.")
        return True
    cli._approve(f"In {target}: {'; '.join(plan)}?", auto)
    if backup is None and empty:
        target.unlink(missing_ok=True)
        ui.ok(f"Deleted {target} (it did not exist before `{entry['summary']}`)")
    else:
        _write_kubeconfig(kubectl, target, new)
        ui.ok(f"Updated {target}: " + "; ".join(plan))
    return True


def when(entry: dict) -> str:
    """When an entry was recorded, as '2026-09-24 06:32 UTC' (entries are stamped in UTC; a bare time would read as
    local time next to tools that print theirs in the local zone)."""
    at = str((entry or {}).get("at") or "")
    try:
        dt = datetime.fromisoformat(at[:-1] + "+00:00" if at.endswith("Z") else at)   # 3.9 does not read a Z suffix
    except ValueError:
        return at[:16].replace("T", " ") or "-"
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def print_list(scope) -> None:
    textw = ui.width() - 6                   # the panel's text columns
    rows = []
    for e in reversed(entries(scope)):
        when_ = when(e)
        scope_col = str(e.get("scope") or "").ljust(14)
        head = f"{when_}  {scope_col} "
        summary = str(e.get("summary") or "")
        if textw - ui.vis_len(head) >= 30 or ui.vis_len(summary) <= textw - ui.vis_len(head):
            rows.append(f"{ui.style(when_, 'muted')}  {ui.style(scope_col, 'text')} "
                        f"{ui.clip(summary, max(20, textw - ui.vis_len(head)))}")
        else:              # narrow terminal: the summary gets its own line instead of a 20-column stub
            rows.append(f"{ui.style(when_, 'muted')}  {ui.style(scope_col.rstrip(), 'text')}")
            rows.append(f"  {ui.clip(summary, textw - 2)}")
        lead, ident = "      ↳ undo: ", "id " + str(e.get("id"))
        room = textw - ui.vis_len(lead) - ui.vis_len(ident) - 2
        try:
            what = describe(e)
        except Exception:  # noqa: BLE001 - one malformed entry must not hide the others
            what = str(e.get("kind") or "?")
        # the commands of a sequence (describe() joins them with "  then  ") stay told apart: "; then" on one line,
        # each on its own line when wrapped
        steps = [" ".join(s.split()) for s in what.split("  then  ")]
        what = "; then ".join(steps)
        if ui.vis_len(what) <= room:       # fits next to its id
            rows.append(f"      {ui.style('↳ undo:', 'seed')} {what}  {ui.dim(ident)}")
        else:
            # wrapped under its label, so every command of a sequence shows (up to four lines, two per command of a
            # longer sequence, the last cut at a word); the id, which --id takes, stays whole below
            avail = max(20, textw - ui.vis_len(lead))
            lines = []                    # (the line, the text from its start on: what a cut last line shows)
            for i, step in enumerate(steps):
                text, pos = ("then " if i else "") + step, 0
                for piece in ui._wrap(text, avail):
                    at = text.find(piece, pos)
                    at = pos if at < 0 else at
                    lines.append((piece, text[at:] + "".join("; then " + s for s in steps[i + 1:])))
                    pos = at + len(piece)
            most = max(4, 2 * len(steps))
            if len(lines) > most:           # a word broken across lines is not split by a space here
                lines = lines[:most - 1] + [(ui.clip(lines[most - 1][1], avail), "")]
            pieces = [line for line, _rest in lines]
            rows.append(f"      {ui.style('↳ undo:', 'seed')} {pieces[0]}")
            rows += [" " * ui.vis_len(lead) + p for p in pieces[1:]]
            rows.append(f"        {ui.dim(ident)}")
    ui.panel("Undo history (newest first)", rows or [ui.dim("nothing to undo")])
    for hint in (f"kept per environment (and for global actions): {KEEP_TOTAL} changes, at most {KEEP} of one kind, "
                 f"plus {KEEP_LIGHT} reports",
                 "cs undo [<cloud> --env NAME | --global | --id ID] [--auto-approve]   ·   cs undo --list",
                 "skip a step that cannot be undone: cs undo ... --drop"):
        for line in textwrap.wrap(hint, max(30, ui.width() - 4), break_on_hyphens=False):
            print(ui.dim("  " + line))


# ---------------------------------------------------------------- helpers for the CLI hooks

def snapshot_settings(what: list[str]) -> dict:
    """The current values of the settings a command is about to change (a key missing here did not exist: the undo
    removes it again). Only those keys are kept and restored; an empty list keeps the whole file."""
    cur = paths.load_settings()
    snap = {k: copy.deepcopy(cur[k]) for k in what if k in cur} if what else copy.deepcopy(cur)
    return {"settings": snap, "what": list(what)}


def new_files_since(root: Path, before: set[str]) -> list[str]:
    try:
        return [str(p) for p in root.rglob("*") if str(p) not in before]
    except OSError:
        return []


def listing(root: Path) -> set[str]:
    try:
        return {str(p) for p in root.rglob("*")}
    except OSError:
        return set()


# ---------------------------------------------------------------- kubectl / helm

# kubectl verbs that change the cluster (`cs kubectl` takes an undo point before them; cli._kubectl_mutates reads the
# arguments flag-aware and leaves out rollout status/history, --dry-run, label/annotate --list and --local)
MUTATING_KUBECTL = {"apply", "create", "delete", "patch", "scale", "edit", "replace", "rollout", "label", "annotate", "taint", "drain", "cordon", "uncordon", "set", "expose", "run", "autoscale"}


def kubectl_namespaces(args: list[str]) -> list[str] | None:
    """Namespaces a kubectl command line touches (None = the whole cluster), read exactly as `cs kubectl` reads it for
    its Velero undo point (one parser: cli._kube_args / cli._kubectl_scope)."""
    from . import cli
    a = cli._kube_args("kubectl", list(args))
    pos = a["pos"]
    return cli._kubectl_scope(pos[0] if pos else "", pos, a)


# ---------------------------------------------------------------- Velero undo points

def velero_pre_backup(ctx, label: str, namespaces: list[str] | None, *, volumes: bool | None = None) -> str | None:
    """A quick Velero backup before a mutating cluster change, when Velero is installed. Returns the backup name.

    A namespace-scoped point keeps the server's volume setting (a `kubectl delete` of a PVC or namespace is undone with
    its data). A whole-cluster point leaves out Velero's own namespace and the MinIO that stores the backups (MinIO
    would back itself up into itself: minutes of silence for an undo point, e2e2#2), and holds object state only: no
    pod volume is copied. volumes=True keeps the server's volume setting for a whole-cluster point too, for a change
    that deletes data (`kubectl delete ns -l ...`, `delete pvc --all -A`); False leaves volumes out of any point."""
    from . import dr
    if not dr.installed(ctx):
        return None
    name = f"pre-{label}-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{_secrets.token_hex(2)}"[:63]
    args = ["backup", "create", name, "--wait", "--ttl", VELERO_TTL, "--labels", VELERO_LABEL]
    if namespaces:
        args += ["--include-namespaces", ",".join(namespaces)]
    else:
        args += ["--exclude-namespaces", ",".join(VELERO_POINT_EXCLUDED)]
    objects_only = (not namespaces) if volumes is None else not volumes
    if objects_only:
        args.append(_FS_BACKUP_OFF)
    what = ", ".join(namespaces) if namespaces else "the whole cluster (velero and minio left out)"
    if objects_only:
        what += " (objects only, no volume data)"
    text = f"Velero: backing up {what} before the change (undo point {name})"
    try:  # best effort: an unreachable GitHub or a failing Velero must never block the change itself
        with _ticking(text) as sp:
            proc = dr._velero(ctx, *args, check=False, quiet=True)
            if proc.returncode != 0 and _FS_BACKUP_OFF in args and "unknown flag" in (proc.stderr or "") + (proc.stdout or ""):
                args.remove(_FS_BACKUP_OFF)   # a Velero older than 1.10 has no such flag (nor file-system backups)
                proc = dr._velero(ctx, *args, check=False, quiet=True)
            if proc.returncode == 0:
                sp.done_text = f"Velero undo point {name} taken ({_elapsed(sp.started)})"
        if proc.returncode != 0:
            from . import secrets as _sec
            detail = _sec.redact(" ".join(dr.velero_error(proc).split()))[-300:]
            ui.warn(f"Velero pre-change backup {name} failed ({detail or f'exit {proc.returncode}'}); the change goes "
                    "ahead without an undo point.")
            discard_velero_backup(ctx, name)
            return None
        if not dr.backup_usable(ctx, name):   # Failed/FailedValidation: it has already warned; drop the useless backup
            discard_velero_backup(ctx, name)
            return None
        return name
    except (Exception, ui.Abort) as e:  # noqa: BLE001
        ui.warn(f"Velero pre-change backup skipped: {getattr(e, 'msg', '') or e}")
        return None


def _elapsed(start: float) -> str:
    s = int(time.monotonic() - start)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


@contextlib.contextmanager
def _ticking(text: str):
    """ui.Spinner whose line shows the time spent so far: `velero backup create --wait` prints nothing until it is done,
    which can take minutes. The spinner gets a `started` attribute (time.monotonic())."""
    stop = threading.Event()
    with ui.Spinner(text) as sp:
        sp.started = time.monotonic()

        def tick() -> None:
            while not stop.wait(1.0):
                sp.update(f"{text} - {_elapsed(sp.started)}")

        th = threading.Thread(target=tick, daemon=True)
        th.start()
        try:
            yield sp
        finally:
            stop.set()
            th.join()


# kubectl's answer for an object whose kind the cluster no longer serves (its CRD was removed since): it is gone too
_GONE_KIND = ("doesn't have a resource type", "no matches for kind", "could not find the requested resource")


def _delete_created(ctx, groups: dict) -> None:
    """Delete the objects a kubectl change created ({namespace or None: refs}) before its undo point is restored.
    Namespaced objects go first, cluster-scoped ones (a CRD) last, so custom resources go before their definition. An
    object whose kind no longer exists is gone already: without that, one removed CRD would block the undo for good."""
    from . import dr, secrets as _sec

    def delete(ns, refs: list[str]):
        return dr._kubectl(ctx, *(["-n", ns] if ns else []), "delete", *refs, "--ignore-not-found", timeout=300)

    def gone_kind(proc) -> bool:
        return any(g in (proc.stderr or "") + (proc.stdout or "") for g in _GONE_KIND)

    for ns, refs in sorted(groups.items(), key=lambda g: g[0] is None):
        if not refs:
            continue
        where = f" in {ns}" if ns else ""
        ui.info(f"Deleting what the change created{where}: {', '.join(refs)}")
        proc = delete(ns, refs)
        failed = refs if proc.returncode != 0 else []
        if failed and gone_kind(proc) and len(refs) > 1:   # one by one: which of them has a kind that is gone
            failed = []
            for ref in refs:
                one = delete(ns, [ref])
                if one.returncode != 0 and not gone_kind(one):
                    failed, proc = failed + [ref], one
        elif failed and gone_kind(proc):
            failed = []
        if failed:
            detail = _sec.redact((proc.stderr or proc.stdout or "").strip())[-300:] or f"exit {proc.returncode}"
            raise ui.Abort(f"Could not delete {', '.join(failed)}{where}: {detail}. The backup was not restored; the undo "
                           "entry is kept, so run the same `cs undo` again once the cause is fixed.")


def discard_velero_backup(ctx, name: str | None) -> None:
    """Delete an undo-point backup that is no longer needed (the change failed, or it was undone). Best effort."""
    if not name:
        return
    from . import dr
    try:
        dr._velero(ctx, "backup", "delete", name, "--confirm", check=False, quiet=True, timeout=120)
    except (Exception, ui.Abort):  # noqa: BLE001 - the TTL removes it anyway (ensure_cli can Abort when offline)
        pass


def _verify_restored(ctx, backup: str, created: list[str]) -> None:
    """After an undo restore: the namespaces the backup covered must exist again, or the undo did not work."""
    from . import dr
    proc = dr._kubectl(ctx, "-n", "velero", "get", "backup", backup, "-o", "json", timeout=60)
    try:
        info = json.loads(proc.stdout or "{}")
    except ValueError:
        return
    included = [n for n in (info.get("spec") or {}).get("includedNamespaces") or [] if n and n != "*" and n not in created]
    if not included or not ((info.get("status") or {}).get("progress") or {}).get("itemsBackedUp"):
        return   # whole-cluster backup, or nothing was there to restore
    missing = [n for n in included if dr._kubectl(ctx, "get", "ns", n, timeout=60).returncode != 0]
    if missing:
        raise ui.Abort(f"Velero finished, but namespace(s) {', '.join(missing)} from backup {backup} are not back. The undo "
                       f"entry is kept; details: {dr.velero_hint(ctx, 'backup', 'describe', backup, '--details')}")
