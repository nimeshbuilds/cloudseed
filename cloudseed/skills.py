"""Install the bundled SKILL.md skills into agent CLIs (Claude Code, Codex, Gemini, or any directory). Agents that
cannot load skills from a directory (Grok) get them in the task prompt instead (prompt_bundle).

Safety rules for installs:
  * every name is resolved (short names like `aws` mean `cloudseed-aws`) and checked before anything is written;
  * an existing directory is only replaced when it is a previous install of the same skill (its SKILL.md names it);
    anything else is refused (automatic installs skip it with a warning), and replaced installs can be backed up for
    `cloudseed undo`; a symlink (e.g. a developer linking a checkout) is left alone;
  * the bundled source tree itself is never a target (no `--dir` that points at, into, or above skills/);
  * each installed skill carries a content hash (MARKER) so outdated copies are refreshed automatically.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path

from . import agents, paths, ui

SKILLS_SRC = paths.REPO_ROOT / "skills"
MARKER = ".cloudseed-version"
PREFIX = "cloudseed-"


def available() -> list[Path]:
    if not SKILLS_SRC.exists():
        return []
    return sorted(p for p in SKILLS_SRC.iterdir() if (p / "SKILL.md").exists())


def frontmatter(skill_dir: Path) -> dict:
    """name / description from a SKILL.md front matter (line based, tolerant of imperfect YAML)."""
    try:
        text = (Path(skill_dir) / "SKILL.md").read_text(errors="replace")
    except OSError:
        return {}
    out: dict = {}
    if text.startswith("---"):
        head = text.split("---", 2)[1] if text.count("---") >= 2 else ""
        for line in head.splitlines():
            key, sep, val = line.partition(":")
            if sep and key.strip() in ("name", "description") and key.strip() not in out:
                out[key.strip()] = val.strip().strip("\"'")
    return out


# Words in a task that call for a skill besides the core one (the built-in agent's system prompt, and the prompt of
# agents that cannot load skills from a directory).
TASK_WORDS = {
    "cloudseed-vmware": {"vmware", "fusion", "workstation", "vm", "vms", "vmrun", "vmnet", "lab"},
    "cloudseed-platform": {"platform", "cluster", "clusters", "kubernetes", "k8s", "node", "nodes", "helm", "kubectl",
                           "k9s", "basek8s", "karpenter", "velero", "dr", "backup", "backups", "restore", "chaos",
                           "scan", "scans", "fips", "cis", "stig", "kagent", "istio", "argocd", "grafana",
                           "prometheus", "monitoring", "scaling", "devsecops", "catalog", "health", "network", "diagnostics", "drift", "upgrade", "recovery"},
    "cloudseed-finops": {"cost", "costs", "finops", "bill", "billing", "spend", "spending", "save", "savings", "price",
                         "pricing", "cheaper", "cheap", "expensive", "budget", "opencost"},
    "cloudseed-managed": {"databricks", "snowflake"},
    "cloudseed-architecture": {"how", "why", "where", "explain", "architecture", "implemented", "implementation",
                               "internals", "design", "works", "architected", "assessment", "assess", "pillars", "operations", "profile", "specification", "guardrails", "acceptance", "provenance"},
    "cloudseed-destroy": {"destroy", "delete", "tear", "teardown", "remove", "clean", "cleanup", "purge",
                          "decommission", "undo"},
}


def for_task(task: str) -> list[str]:
    """The skills a task needs: the core skill, the ones its words call for, and the cloud skills (all three when no
    cloud, local VM or managed platform is named)."""
    low = str(task or "").lower()
    words = set(re.findall(r"[a-z0-9]+", low))
    wanted = ["cloudseed"]
    for name, keys in TASK_WORDS.items():
        if words & keys:
            wanted.append(name)
    if "local vm" in low:
        wanted.append("cloudseed-vmware")
    clouds_named = [c for c in ("aws", "gcp", "azure") if c in words or (c == "gcp" and "google" in words)]
    wanted += [f"cloudseed-{c}" for c in clouds_named]
    if not clouds_named and not ({"cloudseed-vmware", "cloudseed-managed"} & set(wanted)):
        wanted += ["cloudseed-aws", "cloudseed-gcp", "cloudseed-azure"]
    return list(dict.fromkeys(wanted))


def prompt_bundle(task: str, tool: str = "`cloudseed skill show <name>`", max_chars: int | None = None) -> str:
    """The skills as prompt text: the ones the task needs in full (<skill name="..."> blocks) and an index of the others,
    which the agent reads with `tool` when it needs one. With max_chars, only the core skill is included in full when
    the whole bundle would be longer (an agent CLI gets its prompt as one argument, which Linux caps at 128 KiB)."""
    wanted = for_task(task)
    for keep in (wanted, wanted[:1]):
        parts: list[str] = []
        for name in keep:
            p = SKILLS_SRC / name / "SKILL.md"
            try:
                parts += [f"<skill name=\"{name}\">", p.read_text(errors="replace"), "</skill>", ""]
            except OSError:
                continue
        others = [p for p in available() if p.name not in keep]
        if others:
            parts.append("<skill-index>")
            parts.append(f"Other skills (read one with {tool} when the task needs it):")
            for p in others:
                parts.append(f"- {p.name}: {frontmatter(p).get('description', '')}")
            parts += ["</skill-index>", ""]
        text = "\n".join(parts)
        if max_chars is None or len(text) <= max_chars:
            break
    return text


def short_name(p: Path | str) -> str:
    name = Path(p).name
    return name[len(PREFIX):] if name.startswith(PREFIX) else name


def short_names() -> list[str]:
    return [short_name(p) for p in available()]


def _lookup(name: str) -> Path | None:
    n = str(name).strip().lower()
    if not n or "/" in n or "\\" in n or n.startswith("."):
        return None
    by_name = {p.name: p for p in available()}
    return by_name.get(n) or by_name.get(PREFIX + n)


def is_skill_name(name: str) -> bool:
    return _lookup(name) is not None


def resolve(name: str) -> Path:
    """`aws` -> skills/cloudseed-aws, `cloudseed` -> skills/cloudseed; unknown names abort with the list."""
    p = _lookup(name)
    if p is None:
        raise ui.Abort(f"Unknown skill '{name}'. Available: {', '.join(short_names())} "
                       f"(short names or full names such as cloudseed-aws; see: cloudseed skill list)", code=2)
    return p


def resolve_names(names: list[str] | None) -> list[Path]:
    """Every requested skill, validated up front (none / 'all' = all of them)."""
    if not names or any(str(n).strip().lower() == "all" for n in names):
        return available()
    return list(dict.fromkeys(resolve(n) for n in names))


def target_dir(agent_key: str | None, custom: str | None, project: bool) -> Path:
    if custom:
        return Path(custom).expanduser()
    key = agent_key or "claude"
    spec = agents.get(key)
    if spec.get("builtin"):   # the built-in agent reads the repo copy; installs go to its fallback, Claude Code
        key, spec = "claude", agents.get("claude")
    if not spec.get("skills_dir"):   # (a project directory ./.<agent>/skills would not be read either)
        if spec.get("skills_in_prompt"):
            raise ui.Abort(f"{spec.get('display', key)} cannot load skills from a directory; cloudseed sends the skills "
                           f"in each task's prompt instead. To copy them somewhere anyway, use --dir.")
        raise ui.Abort(f"Agent '{spec['key']}' has no skills directory (skills_dir in agents.json); use --dir.")
    if project:
        return Path.cwd() / f".{key}" / "skills"
    return Path(spec["skills_dir"]).expanduser()


def resolve_target(agent_key: str | None, custom: str | None, project: bool) -> tuple[str, Path]:
    """(agent key the skills are for, directory). The built-in agent maps to Claude Code (with a notice)."""
    key = agent_key or "claude"
    spec = agents.get(key)
    if not custom and spec.get("builtin"):
        ui.info("The built-in agent loads skills straight from cloudseed; installing them for Claude Code "
                "(its fallback) instead. Use --agent or --dir to choose another target.")
        key = "claude"
    elif not custom and spec.get("skills_in_prompt") and not spec.get("skills_dir"):
        ui.info(f"{spec.get('display', key)} cannot load skills from a directory (cloudseed sends them in each task's "
                "prompt); installing them for Claude Code instead. Use --agent or --dir to choose another target.")
        key = "claude"
    return key, target_dir(key, custom, project)


def src_hash(src: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(Path(src).rglob("*")):
        if f.is_file() and f.name not in (MARKER, ".DS_Store") and "__pycache__" not in f.parts:
            h.update(str(f.relative_to(src)).encode())
            h.update(b"\0")
            h.update(f.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def _within(a: Path, b: Path) -> bool:
    """a is b or inside b."""
    return a == b or b in a.parents


def _ours(target: Path, name: str) -> bool:
    """A directory we may replace: a previous install of the same skill."""
    return target.is_dir() and (target / "SKILL.md").is_file() and frontmatter(target).get("name") == name


def _linked(target: Path, src: Path) -> bool:
    try:
        return target.is_symlink() and target.resolve() == src.resolve()
    except OSError:
        return False


def install(names: list[str] | None, dest: Path | str, backups: dict | None = None,
            skip_foreign: bool = False) -> list[Path]:
    """Install skills into dest/<skill>. Returns the installed directories.

    When `backups` is a dict it is filled with {target: backup path or None (new)} for a `restore-files` undo
    entry; replaced installs are then backed up first (undo.backup_file). A directory under a skill's name that is not
    a cloudseed install stops the whole install (nothing is written), unless skip_foreign: then it is left alone with a
    warning and the other skills are installed (the automatic installs of `use`, `enable agentic` and `agentic`)."""
    wanted = resolve_names(names)
    dest = Path(dest).expanduser()
    src_root = SKILLS_SRC.resolve()
    plan: list[tuple[Path, Path, str]] = []   # (src, target, action: new | replace | linked)
    for src in wanted:
        target = dest / src.name
        if _linked(target, src):
            plan.append((src, target, "linked"))
            continue
        if target.is_symlink():   # linked by hand (e.g. to another checkout): the user manages it, never touch it
            ui.warn(f"Left {target} alone: it is a symlink to {os.readlink(target)} (remove the link to get "
                    f"cloudseed's copy of {src.name}).")
            continue
        t_r = target.resolve()
        if _within(t_r, src_root) or _within(src_root, t_r):
            raise ui.Abort(f"Refusing to install into {target}: that is (or contains) cloudseed's own skills source "
                           f"{SKILLS_SRC}. Choose another --dir.")
        if target.exists():
            if not _ours(target, src.name):
                if skip_foreign:
                    ui.warn(f"Left {target} alone: it is not a cloudseed skill install (move it away to get "
                            f"cloudseed's {src.name}).")
                    continue
                raise ui.Abort(f"{target} already exists and is not a cloudseed skill install; nothing was changed. "
                               f"Move it away or choose another --dir.")
            plan.append((src, target, "replace"))
        else:
            plan.append((src, target, "new"))
    done: list[Path] = []
    if not plan:
        return done
    dest.mkdir(parents=True, exist_ok=True)
    for src, target, action in plan:
        if action == "linked":
            done.append(target)
            continue
        if action == "replace":
            if backups is not None:
                from . import undo
                backups[str(target)] = undo.backup_file(target)
            shutil.rmtree(target)
        elif backups is not None:
            backups[str(target)] = None
        shutil.copytree(src, target, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store", MARKER))
        (target / MARKER).write_text(src_hash(src) + "\n")
        done.append(target)
    return done


def state(agent_key: str) -> str:
    """builtin | n/a (agent has no skills directory) | missing | stale (some skill absent or outdated) | current |
    partial (current, except skills whose directory belongs to someone else: install(skip_foreign) leaves those)"""
    spec = agents.get(agent_key)
    if spec.get("builtin"):
        return "builtin"
    if not spec.get("skills_dir"):
        return "n/a"
    dest = Path(spec["skills_dir"]).expanduser()
    core = dest / "cloudseed"
    if not core.is_symlink() and not core.exists():
        return "missing"
    foreign = False
    for src in available():
        target = dest / src.name
        if target.is_symlink():   # linked to this checkout, or by hand elsewhere: install() never replaces it
            continue
        if target.exists() and not _ours(target, src.name):
            foreign = True        # not ours to replace: reinstalling would only warn about it again
            continue
        try:
            if (target / MARKER).read_text().strip() != src_hash(src):
                return "stale"
        except OSError:
            return "stale"
    return "partial" if foreign else "current"


def foreign(agent_key: str) -> list[str]:
    """Skill names whose directory in the agent's skills dir is not a cloudseed install (left alone)."""
    spec = agents.get(agent_key)
    if spec.get("builtin") or not spec.get("skills_dir"):
        return []
    dest = Path(spec["skills_dir"]).expanduser()
    return [src.name for src in available()
            if not (dest / src.name).is_symlink() and (dest / src.name).exists() and not _ours(dest / src.name, src.name)]


def pending(agent_key: str) -> list[str]:
    """Skill names an install would (re)write in the agent's skills dir: absent or outdated. Symlinks and directories
    that are not cloudseed's are not counted (install() never replaces them)."""
    spec = agents.get(agent_key)
    if spec.get("builtin") or not spec.get("skills_dir"):
        return []
    dest = Path(spec["skills_dir"]).expanduser()
    out = []
    for src in available():
        target = dest / src.name
        if target.is_symlink() or (target.exists() and not _ours(target, src.name)):
            continue
        try:
            if (target / MARKER).read_text().strip() == src_hash(src):
                continue
        except OSError:
            pass
        out.append(src.name)
    return out


def state_text(agent_key: str) -> str:
    """One line on an agent's skills for `cs skill list` / `cs install list`: what state() found, in words, with the
    directory and what to run. 'partial' names the directories that were left alone; an agent that gets the skills in
    its prompt (Grok) says so instead of pointing at --dir."""
    spec = agents.get(agent_key)
    st = state(agent_key)
    if st == "builtin":
        return "read from cloudseed at run time (the core skill and the ones a task needs; the rest on demand)"
    if st == "n/a":
        if spec.get("skills_in_prompt"):
            return "sent in each task's prompt (it cannot load skills from a directory)"
        return "n/a (no skills_dir in agents.json; install into any folder with --dir)"
    where = f"({agents._home_path(target_dir(agent_key, None, False))})"
    if st in ("missing", "stale"):
        what = "not installed" if st == "missing" else "outdated"
        theirs = foreign(agent_key)
        if not theirs:
            return f"{what} - run: cloudseed skill install --agent {agent_key}  {where}"
        # installing all of them would stop at a directory that is not cloudseed's (nothing is written): name the
        # skills that need it instead, so that directory is left alone and the rest is installed
        names = " ".join(short_name(n) for n in pending(agent_key))
        return (f"{what} - run: cloudseed skill install {names} --agent {agent_key}  {where}; "
                f"{', '.join(theirs)} there is not cloudseed's (left alone)")
    if st == "partial":
        return (f"installed, except {', '.join(foreign(agent_key))} (a directory there is not cloudseed's: left "
                f"alone)  {where}")
    return f"installed  {where}"


def installed(agent_key: str) -> bool:
    """True when nothing needs installing: the agent reads the repo copy, has no skills directory, or has every
    bundled skill at the current version (so callers that install when this is False also refresh stale copies);
    skills whose directory is someone else's are skipped ("partial")."""
    return state(agent_key) in ("builtin", "n/a", "current", "partial")
