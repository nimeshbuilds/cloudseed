"""Headliner: a compact, secret-free research brief prepended to agent prompts.

The CLI does the discovery (environments, outputs, tool status, command cheat-sheet) deterministically so
the agent does not burn tokens exploring. Toggle with `cloudseed enable|disable headliner`.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone

from . import __version__, clouds, deps, explain, paths, secrets
from . import platform as platformmod

CHEATSHEET = """\
cloudseed setup <aws|gcp|azure|vmware> --env <name> [--name X --region R --state remote|local --cidr C --allow-ip IP --var k=v --dry-run --plan-only --auto-approve]
cloudseed plan|apply|status|output <cloud> --env <name>            # apply needs --auto-approve to change anything
cloudseed destroy <cloud> --env <name> [--select | --target ADDR] [--purge-state --purge --auto-approve]
cloudseed undo [<cloud> --env <name>] [--list]                     # revert the last change (--list shows history)
cloudseed update-ip <cloud> --env <name> [--allow-ip IP]
cloudseed ssh <cloud> --env <name>                                  # interactive: for the human
cloudseed provision <cloud> --env <name> [--host bastion|vpn|k8s]   # copy repo + Ansible hardening
cloudseed k8s info|kubeconfig|tunnel|untunnel <cloud> --env <name>  # when enable_kubernetes=true
cloudseed vpn status|add-user|users|revoke|connect|disconnect|provision <cloud> --env <name> [name]   # when enable_vpn=true
cloudseed env [use <id> | clear] · cloudseed node add|list|remove|scale [cloud --env] [--count N --min N --max N]   # current cluster, scaling
cloudseed platform list|status|info|plan|install|uninstall [group|item ...] [cloud --env NAME]   # groups: """ + \
    " ".join(platformmod.GROUPS) + """
cloudseed platform ui · cloudseed platform template gitlab-ci      # expose installed UIs · write a CI template into the current dir
cloudseed kubectl|helm|k9s [cloud --env NAME] <args>                              # tools on the current cluster
cloudseed finops estimate|cloud|k8s|report [cloud --env NAME]                      # costs
cloudseed chaos list|run|status|stop|report · cloudseed dr status|backups|backup|restore|schedule|test|describe|logs
cloudseed scan cis|kube|images|host|stig|cloud|fips|all|reports [cloud --env NAME]
cloudseed databricks|snowflake status|test|connect|<cli args>                     # managed data platforms
cloudseed troubleshoot <cloud> --env <name> [--log] · cloudseed inventory <cloud> --env <name>
cloudseed explain <feature|target|command|item> [--json] · cloudseed help <command|topic> · cloudseed skill list|show <name>
cloudseed list | doctor [cloud] | deps status | agents · cloudseed creds (masked list; the user stores secrets)"""


def enabled(settings: dict) -> bool:
    return settings.get("headliner", True)


def _env_line(env_id: str, cfg: dict, out: dict) -> str:
    """One environment of the brief. Every field is read by its type: a hand-edited config.json (null, a string where a
    list belongs, a list where a mapping belongs) must not break the brief of every agent task."""
    state = cfg.get("state")
    state = state if isinstance(state, dict) else {}
    cidrs = cfg.get("allowed_ssh_cidrs")
    cidrs = [str(c) for c in cidrs] if isinstance(cidrs, list) else ([cidrs] if isinstance(cidrs, str) and cidrs else [])
    env_vars = cfg.get("vars")
    env_vars = env_vars if isinstance(env_vars, dict) else {}
    shown = {k: v for k, v in env_vars.items() if k != "profile"}
    return (f"- {env_id}: name={cfg.get('name')} region={cfg.get('region')} cidr={cfg.get('network_cidr')} "
            f"state={state.get('type')} ssh_from={','.join(cidrs)} "
            f"bastion_ip={out.get('bastion_public_ip') or 'n/a'} vars={shown}")


def build(task: str, settings: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# cloudseed headliner brief ({now})",
        f"cloudseed {__version__} on {platform.system()} {platform.machine()}; home={paths.HOME}",
        "The `cloudseed` CLI is on PATH. Drive infrastructure ONLY through it (never raw terraform).",
        "Non-interactive: put -y BEFORE the command (`cloudseed -y <command> ...`, never after passthrough args of "
        "kubectl/helm/ssh); changes are only applied with --auto-approve.",
        "",
        "## Commands",
        CHEATSHEET,
        "",
        "## Environments",
    ]
    envs = paths.Env.list_all()
    if not envs:
        lines.append("(none yet)")
    for e in envs:
        try:
            cfg = e.load()
        except Exception:  # noqa: BLE001 - one broken environment must not break the brief
            cfg = None
        if not isinstance(cfg, dict):
            lines.append(f"- {e.id}: (config.json unreadable: {e.dir / 'config.json'})")
            continue
        out = {}
        try:
            out = json.loads((e.dir / "outputs.json").read_text())
        except Exception:  # noqa: BLE001
            pass
        if not isinstance(out, dict):
            out = {}
        try:
            lines.append(_env_line(e.id, cfg, out))
        except Exception:  # noqa: BLE001 - a hand-edited config with values of an unexpected shape
            lines.append(f"- {e.id}: (config.json has unexpected values: {e.dir / 'config.json'})")
    lines += ["", "## Tooling"]
    for key in ("aws", "gcp", "azure", "vmware"):
        rows = deps.status(key)
        have = [r["tool"] for r in rows if r["path"]]
        miss = [r["tool"] for r in rows if not r["path"]]
        creds = "credentials: " + ("detected" if not clouds.get(key).credential_warnings({"vars": {}}) else "NOT detected")
        lines.append(f"- {key}: have={','.join(have) or '-'} missing={','.join(miss) or '-'}; {creds}")
    lines += [
        "",
        "## Implementation questions",
        f"Use `cloudseed explain <feature>` ({' '.join(explain.FEATURES)}; also any target, command, platform item or "
        "`variable <cloud> <name>`, with `--json` for data) for exact implementation facts instead of guessing, "
        "`cloudseed inventory <cloud> --env <name>` "
        "for what exists and its history, and `cloudseed troubleshoot ... --log` for what happened in the last failure.",
        "",
        "## Rules",
        "- Never read credential files, state files, or print environment variables. Secrets are redacted anyway.",
        "- Before any destroy, restate what will be removed and use --select/--target for partial teardown.",
        "- Prefer `cloudseed status`/`output` over re-running setup to learn about an environment.",
        "",
        "## Task",
        task.strip(),
    ]
    return secrets.redact("\n".join(lines))


def plain(task: str, skills_in_prompt: bool = False) -> str:
    """The prompt without the brief. An agent that cannot load skills (Grok) gets them in the prompt (agents.run puts
    them above this text), so it is told to follow them rather than to use a skill it does not have."""
    how = ("Follow the cloudseed skill included above and use the `cloudseed` CLI (on PATH)" if skills_in_prompt else
           "Use the `cloudseed` skill and the `cloudseed` CLI (on PATH)")
    return secrets.redact(how + " to do the following. Never read credential or state files.\n\nTask: " + task.strip())
