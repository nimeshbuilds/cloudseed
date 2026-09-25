"""Credential minimization for explicitly targeted operation subprocesses.

This is an inheritance boundary, not a sandbox against code running as the user.
Cloud SDKs may still use the user's own login caches and configured identities.
"""
import json

MARKER = "CLOUDSEED_CREDENTIAL_SCOPE"
PREFIXES = {"aws": ("AWS_",), "gcp": ("GOOGLE_", "GCLOUD_", "CLOUDSDK_"), "azure": ("ARM_", "AZURE_")}
AGENTS = ("ANTHROPIC_", "OPENAI_", "GEMINI_", "GROK_", "XAI_")
SERVICES = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "UBUNTU_PRO_TOKEN", "TS_AUTHKEY", "GITLAB_RUNNER_TOKEN", "DATABRICKS_TOKEN", "SNOWFLAKE_PASSWORD"}


def for_argv(argv):
    # Use the CLI's parser, not a scan for words which could be option values.
    from . import cli
    try:
        ns = cli.build_parser().parse_args(argv)
    except (SystemExit, ValueError):
        return None
    cloud = getattr(ns, "cloud", None)
    if cloud not in ("aws", "gcp", "azure", "vmware"):
        return None
    services = []
    if ns.cmd in ("setup", "provision"):
        services = ["UBUNTU_PRO_TOKEN", "TS_AUTHKEY"]
    elif ns.cmd == "vpn":
        services = ["TS_AUTHKEY"]
    elif ns.cmd == "platform":
        services = ["GITLAB_RUNNER_TOKEN"]
        # The kagent chart uses these keys to create the user's model-provider
        # Secret. They are not granted to unrelated platform operations.
        selected = set(getattr(ns, "items", []) or [])
        if getattr(ns, "platform_cmd", "") in ("install", "plan") and selected.intersection({"kagent", "agentic", "all"}):
            services += ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    return {"cloud": cloud, "services": services}


def permitted(key, scope, secret=False):
    for cloud, prefixes in PREFIXES.items():
        if key.startswith(prefixes):
            return cloud == scope["cloud"]
    if key.startswith(AGENTS):
        return key in scope.get("services", []) and key in SERVICES
    if key in SERVICES:
        return key in scope.get("services", [])
    return not secret


def parse(raw):
    if not raw:
        return None
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("cloud") not in (*PREFIXES, "vmware"):
        raise ValueError("Invalid operation credential scope")
    if not isinstance(data.get("services", []), list) or not all(isinstance(s, str) for s in data.get("services", [])) or set(data.get("services", [])) - SERVICES:
        raise ValueError("Invalid operation credential service scope")
    return data
