"""Cloud adapter interface: prompts, provider/backend config, and Terraform root rendering."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import netutil, ui

_TRUE = ("true", "yes", "y", "on", "1")
_FALSE = ("false", "no", "n", "off", "0")


def as_bool(value: Any, key: str = "") -> bool:
    """Strict boolean: True/False, 1/0 and true/false, yes/no, on/off (any case). Anything else raises ValueError,
    because bool("False") or bool("no") is True in Python and would silently switch features on."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in _TRUE:
        return True
    if isinstance(value, str) and value.strip().lower() in _FALSE:
        return False
    raise ValueError(f"{key + ': ' if key else ''}expected true or false (yes/no, on/off, 1/0), got {value!r}")


def as_int(value: Any, key: str = "", minimum: int = 0) -> int:
    """Strict whole number >= minimum: an int (not a bool), an integral float, or a string of digits."""
    n = None
    if isinstance(value, bool):
        n = None
    elif isinstance(value, int):
        n = value
    elif isinstance(value, float) and value.is_integer():
        n = int(value)
    elif isinstance(value, str) and re.fullmatch(r"\s*-?\d+\s*", value):
        n = int(value)
    if n is None:
        raise ValueError(f"{key + ': ' if key else ''}expected a whole number, got {value!r}")
    if n < minimum:
        raise ValueError(f"{key + ': ' if key else ''}must be >= {minimum}, got {n}")
    return n


@dataclass
class Question:
    key: str
    prompt: str
    default: Any = ""                # literal, or callable(cfg) -> value
    kind: str = "str"                # str | bool | int
    required: bool = False
    env: tuple[str, ...] = field(default_factory=tuple)   # env vars consulted for a default
    advanced: bool = False           # only asked with --advanced
    validate: Callable[[str], str | None] | None = None
    # the only accepted answers of an enumerated setting (e.g. vpn_type: openvpn, tailscale), checked before
    # `validate`; the web console renders a select for them (webui.clouds_catalog sends them)
    choices: tuple[str, ...] = ()
    # the range of an int setting (e.g. az_count 1-5), checked before `validate`; None = no bound (the lower bound is
    # then 0: no setting counts below zero). One source for the CLI, the prompt and the web console's number field.
    minimum: int | None = None
    maximum: int | None = None
    # the question whose answer is this one's default (e.g. enable_regional_baseline follows enable_account_baseline):
    # a form that shows the default, such as the web console, follows that answer until this one is set
    follows: str = ""
    # the yes/no question this setting belongs to (e.g. enable_security_hub: enable_regional_baseline). While that
    # answer is no, this one is not asked and has no effect; it keeps its saved or built-in value.
    depends_on: str = ""

    # the sub-settings of a feature that predate depends_on: vpn_type needs a VPN, kubernetes_* a cluster
    _IMPLIED_PARENT = (("vpn_type", "enable_vpn"), ("kubernetes_", "enable_kubernetes"))

    def parent(self) -> str:
        """The yes/no question this setting depends on (depends_on, or the implied one); "" when none."""
        if self.depends_on:
            return self.depends_on if self.depends_on != self.key else ""
        return next((p for prefix, p in self._IMPLIED_PARENT if self.key.startswith(prefix) and self.key != p), "")

    def unused(self, answers: dict, parent_default: Any = False) -> bool:
        """True when this setting belongs to a feature that is off in `answers` (its parent() answered no): it is not
        asked and has no effect. A missing or blank parent answer counts as `parent_default` (Cloud.unused passes the
        parent question's own default: enable_regional_baseline, missing from configurations saved before it
        existed, follows enable_account_baseline). Saved answers may still be strings ('false', 'no')."""
        parent = self.parent()
        if not parent:
            return False
        value = answers.get(parent)
        if value is None or (isinstance(value, str) and not value.strip()):
            value = parent_default
        try:
            return not as_bool(value)
        except ValueError:
            return True               # not a yes/no: the feature is not on

    @property
    def flag(self) -> str:
        return "--" + self.key.replace("_", "-")

    # argparse flags that exist for some questions; every other question is set with --var KEY=VALUE
    FLAG_KEYS = ("project_id", "subscription_id", "zone", "ssh_username", "admin_username", "profile")

    @property
    def fix_flag(self) -> str:
        return f"{self.flag} VALUE" if self.key in self.FLAG_KEYS else f"--var {self.key}=VALUE"

    def stock_default(self, cfg: dict) -> Any:
        return self.default(cfg) if callable(self.default) else self.default

    def coerce(self, value: Any) -> Any:
        """The answer as its kind (bool/int/str); ValueError when it is not one, or the validator refuses it."""
        if self.kind == "bool":
            return as_bool(value)
        if self.kind == "int":
            number = as_int(value, minimum=0 if self.minimum is None else self.minimum)
            if self.maximum is not None and number > self.maximum:
                raise ValueError(f"must be <= {self.maximum}, got {number}")
            problem = self.validate(str(number)) if self.validate else None   # e.g. the AWS az_count range
            if problem:
                raise ValueError(problem)
            return number
        text = "" if value is None else str(value).strip()
        if text and self.choices:
            match = next((c for c in self.choices if c == text), None) or \
                next((c for c in self.choices if c.lower() == text.lower()), None)   # --var vpn_type=Tailscale
            if match is None:
                raise ValueError(f"{text!r} is not one of: {', '.join(self.choices)}")
            text = match
        if text and self.validate:
            problem = self.validate(text)
            if problem:
                raise ValueError(problem)
        return text

    def problem(self, value: Any) -> str | None:
        try:
            self.coerce(value)
        except ValueError as e:
            return str(e)
        return None


def coerce_answer(q: Question, value: Any, source: str = "") -> Any:
    """Question.coerce, raising ui.Abort that names where the value came from (e.g. '--var workload_count')."""
    try:
        return q.coerce(value)
    except ValueError as e:
        shown = "" if repr(value) in str(e) else f"={value!r}"
        raise ui.Abort(f"{source or q.fix_flag.replace('=VALUE', '').replace(' VALUE', '')}{shown} is invalid: {e}") from None


def escape_literals(obj: Any) -> Any:
    """Make sure user strings are never interpreted as Terraform templates: in JSON configuration Terraform evaluates
    `${...}` / `%{...}` in object keys as well as in values."""
    if isinstance(obj, str):
        return obj.replace("${", "$${").replace("%{", "%%{")
    if isinstance(obj, list):
        return [escape_literals(x) for x in obj]
    if isinstance(obj, dict):
        return {(escape_literals(k) if isinstance(k, str) else k): escape_literals(v) for k, v in obj.items()}
    return obj


# Stack variables cloudseed computes itself, and the flag that sets each one. `--var` must not override them: the
# summary, update-ip, the CIDR overlap check and the remote-state bootstrap all read cloudseed's own value.
MANAGED_VAR_FLAGS = {
    "name": "--name",
    "environment": "--env",
    "region": "--region",
    "location": "--region",
    "network_cidr": "--cidr",
    "vpc_cidr": "--cidr",
    "private_cidr": "--cidr",
    "allowed_ssh_cidrs": "--allow-ip (or `cloudseed update-ip`)",
    "ssh_public_key": "--ssh-public-key",
    "tags": "--tag KEY=VALUE",
    "labels": "--tag KEY=VALUE",
    "platform_prereqs": "`cloudseed platform install <item>` (it applies an item's cloud prerequisites)",
    "base_disk": "--var guest_os=...",
    "guest_os_id": "--var guest_os=...",
}

# A tag/label key or value may not be empty or contain a template sequence (they end up in Terraform configuration).
_TAG_TEMPLATE = re.compile(r"[$%]\{")

# (variable, value) pairs already reported by _ignored_env: the question loop can run twice and _default recurses
_ENV_WARNED: set = set()


def _ignored_env(name: str, value: str, format_problem: str | None, problem: str) -> None:
    """Say once why an environment variable (or a value from the vault) is not used as a default: an invalid one
    otherwise ends in a bare "project ID is required ... pass --project-id" although the user exported it. A value
    that is fine in itself but does not fit this configuration (CLOUDSDK_COMPUTE_ZONE of another region) is only
    mentioned. The values are settings such as a project ID, profile or zone, never secrets."""
    if (name, value) in _ENV_WARNED:
        return
    _ENV_WARNED.add((name, value))
    from .. import creds
    where = f" (saved with `cloudseed creds set`; change it there or: cloudseed creds unset {name})" \
        if creds.APPLIED.get(name) == value else ""
    if format_problem:
        ui.warn(f"Ignoring {name}={value!r}{where}: {format_problem}")
    else:
        ui.info(f"Ignoring {name}={value!r} here{where}: {problem}")


class Cloud:
    key = ""
    display = ""
    local = False                # True for on-machine virtualization (no region, no remote state, no public IP)
    region_prompt = "Region"
    default_region = ""
    region_env: tuple[str, ...] = ()
    cli_tool = ""
    questions: list[Question] = []
    outputs: list[str] = []
    login_hint = ""

    # login-name settings: root and system accounts are refused on every target (PermitRootLogin no)
    LOGIN_KEYS = ("ssh_username", "admin_username")

    # ---- validation hooks ----
    def value_problem(self, q: Question, value: Any, cfg: dict) -> str | None:
        """Rules for one answer that depend on the rest of the configuration (Question.validate only sees the value),
        e.g. a GCP zone must lie in the chosen region. Adapters override (and call super()); None means fine."""
        if q.key in self.LOGIN_KEYS and value not in (None, ""):
            return netutil.validate_login_username(value)
        return None

    def network_problems(self, cfg: dict) -> list[str]:
        """Target-specific limits on the network CIDR / SSH allow-list. Adapters override."""
        return []

    def answer_problem(self, q: Question, value: Any, cfg: dict) -> str | None:
        return q.problem(value) or self.value_problem(q, value, cfg)

    def invalid_answers(self, cfg: dict) -> dict[str, str]:
        """Saved answers that are not valid (question key -> problem), e.g. written by an older version that did not
        check --var values. A null or empty answer is not set (its default applies): nothing to report. So is a
        whitespace-only yes/no or number (Cloud.var_bool / var_int read it as the default); a whitespace-only text
        answer is still checked, because it is rendered as it is (a GCP zone or login name of '  ')."""
        answers = cfg.get("vars") or {}
        out = {}
        for q in self.questions:
            value = answers.get(q.key)
            if value is not None and value != "" and \
                    not (q.kind in ("bool", "int") and isinstance(value, str) and not value.strip()):
                problem = self.answer_problem(q, answers[q.key], cfg)
                if problem:
                    out[q.key] = problem
        return out

    def question(self, key: str) -> Question | None:
        return next((q for q in self.questions if q.key == key), None)

    def unused(self, q: Question, cfg: dict) -> bool:
        """`q` is a sub-setting of a feature that is off in cfg["vars"] (Question.unused: vpn_type without a VPN, the
        cluster sizing without a cluster, a declared depends_on), a missing parent answer counting as the parent
        question's default. Use it rather than Question.unused on saved answers, which may predate the parent."""
        key = q.parent()
        if not key:
            return False
        answers = cfg.get("vars") or {}
        given = answers.get(key)
        parent, default = self.question(key), False
        if parent is not None and (given is None or (isinstance(given, str) and not given.strip())):
            try:
                default = parent.stock_default(cfg)
            except Exception:  # noqa: BLE001 - a default that cannot be computed from this cfg: treat as off
                default = False
        return q.unused(answers, default)

    def check_config(self, cfg: dict) -> list[str]:
        """Everything wrong with a complete configuration, whatever path its values came from (prompt, flag, --var,
        saved config, web console, MCP). Run before it is saved."""
        problems = []
        answers = cfg.get("vars") or {}
        for key, problem in self.invalid_answers(cfg).items():
            problems.append(f"{key}={answers[key]!r}: {problem} (fix: {self.question(key).fix_flag})")
        for k, v in (cfg.get("tags") or {}).items():
            if v in (None, ""):
                continue                  # an emptied tag (--tag KEY=) is not rendered (see tags()): nothing to check
            problem = self.tag_problem(str(k), str(v))
            if problem:
                problems.append(f"--tag {k}={v}: {problem} (to drop a saved tag: --tag {k}=)")
        problems += self.tags_problems(cfg)
        problems += self.network_problems(cfg)
        return problems

    def tags_problems(self, cfg: dict) -> list[str]:
        """Rules for the tags as a whole (tag_problem sees one at a time). Two --tag keys that differ only in case
        (team / Team) are refused: AWS IAM and Azure treat tag keys case-insensitively and reject such a pair (or keep
        one at random), and GCP lower-cases label keys, so only one of the two values could ever apply. A tag that
        spells Project/Environment/Owner in another case is not a conflict: it sets that tag (see tags())."""
        skip = {"project", "environment", "owner"} | {t.lower() for t in self.IDENTITY_TAGS}
        seen: dict[str, str] = {}
        problems = []
        for k, v in (cfg.get("tags") or {}).items():
            low = str(k).strip().lower()
            if v in (None, "") or low in skip:
                continue
            if low in seen:
                problems.append(f"--tag {seen[low]} and --tag {k} differ only in case, and tag keys are case-insensitive "
                                f"in the cloud: keep one of them (drop a saved one with --tag {seen[low]}=)")
            else:
                seen[low] = str(k)
        return problems

    def tag_problem(self, key: str, value: str) -> str | None:
        """Generic tag rules; adapters may add the cloud's own (length, charset)."""
        if not key.strip():
            return "the tag key is empty"
        if key.strip().lower() in {k.lower() for k in self.IDENTITY_TAGS}:
            return f"{key} is set by cloudseed (it marks what this environment created) and cannot be changed"
        if _TAG_TEMPLATE.search(key) or _TAG_TEMPLATE.search(value):
            return "tags may not contain '${' or '%{'"
        return None

    def managed_vars(self, cfg: dict | None = None) -> dict[str, str]:
        """Stack variables cloudseed sets itself (not overridable with --var) -> the flag to use instead. Derived from
        stack_vars, minus the prompted settings (those are meant to be set with --var)."""
        qkeys = {q.key for q in self.questions}
        probe = {"name": "x", "env": "x", "region": self.default_region or "x", "network_cidr": "10.0.0.0/16",
                 "allowed_ssh_cidrs": [], "ssh_public_key": "", "owner": "", "tags": {}, "workdir": "",
                 "platform_prereqs": [], "state": {}, **(cfg or {})}
        probe["vars"] = {**{q.key: q.stock_default(probe) if not callable(q.default) else "" for q in self.questions},
                         **((cfg or {}).get("vars") or {})}
        try:
            keys = set(self.stack_vars(probe))
        except Exception:  # noqa: BLE001 - a half-built config: fall back to the known list
            keys = set(MANAGED_VAR_FLAGS)
        return {k: MANAGED_VAR_FLAGS.get(k, "the matching setup flag") for k in sorted(keys - qkeys)}

    # ---- prompts ----
    def collect_vars(self, args, existing: dict, cfg: dict, advanced: bool, overrides: dict | None = None) -> dict:
        """Answer every question. Precedence: a CLI flag (--zone ...), then `overrides` (--var KEY=VALUE for a
        prompted setting), then the prompt (default: the saved answer, a valid env var, or the built-in default).
        Flag and --var values are checked like typed answers and never prompted for again; a saved answer that is no
        longer valid is reported with the way to fix it instead of blocking every later run."""
        overrides = dict(overrides or {})
        existing = dict(existing or {})
        out: dict = {}
        for q in self.questions:
            given, source = getattr(args, q.key, None), q.flag
            if given is None and q.key in overrides:
                given, source = overrides[q.key], f"--var {q.key}"
            if q.kind == "str" and isinstance(given, str) and not given.strip():
                if q.required:
                    raise ui.Abort(f"{source} cannot be empty.")
                if callable(q.default) or q.default not in (None, ""):
                    given = None              # an empty value means "the default" (e.g. an emptied web form field)
            if given is not None:
                value = coerce_answer(q, given, source)
                problem = self.value_problem(q, value, {**cfg, "vars": out})
                if problem:
                    raise ui.Abort(f"{source}={given!r} is invalid: {problem}")
                out[q.key] = value
                if ui.interactive():
                    shown = ("yes" if value else "no") if q.kind == "bool" else str(value)
                    print(f"  {ui.style('✔', 'leaf')} {ui.style(q.prompt, 'muted')}  {ui.style('·', 'dim')}  "
                          f"{ui.style(shown, 'text', 'bold')} {ui.dim('(' + source + ')')}")
                continue
            view = {**cfg, "vars": out}
            default = self._default(q, view, existing)
            # a sub-setting of a feature that is off (vpn_type without a VPN, the cluster sizing without a cluster,
            # Security Hub without the regional baseline) is not asked
            asked = not ((q.advanced and not advanced) or self.unused(q, view))
            if not asked:
                if default in (None, ""):
                    default = q.stock_default(view)
                out[q.key] = self._usable(q, default, view, asked=False)
                continue
            default = self._usable(q, default, view, asked=True)
            if q.kind == "bool":
                out[q.key] = ui.ask_bool(q.prompt, bool(default))
            elif q.kind == "int":
                # a whole number first, then Question.problem (as_int plus the question's own range check, e.g. az_count 1-5)
                raw = ui.ask(q.prompt, str(default), flag=q.fix_flag,
                             validate=lambda s, q=q: "Enter a number." if not s.strip().isdigit() else q.problem(s))
                out[q.key] = as_int(raw)
            else:
                out[q.key] = ui.ask(q.prompt, "" if default is None else str(default), required=q.required,
                                    flag=q.fix_flag,
                                    validate=lambda s, q=q, view=view: self.answer_problem(q, s, view))
        return out

    def _default(self, q: Question, cfg: dict, existing: dict) -> Any:
        """Saved answer, else an env var that is valid here, else the built-in default. A saved answer that only
        conflicts with the rest of the configuration (a zone after the region changed) is re-derived."""
        saved = existing.get(q.key)
        if saved == "" and not callable(q.default) and q.default in (None, ""):
            return ""                         # an optional setting deliberately left blank (e.g. the AWS profile)
        if saved not in (None, ""):
            if q.problem(saved) is None and self.value_problem(q, saved, cfg):
                fresh = self._default(q, cfg, {})
                ui.info(f"{q.key}: the saved {saved!r} does not fit the new settings; using {fresh!r}.")
                return fresh
            return saved
        for name in q.env:
            value = os.environ.get(name)
            if not value:
                continue
            problem = self.answer_problem(q, value, cfg)
            if problem is None:
                return value
            _ignored_env(name, value, q.problem(value), problem)
        return q.stock_default(cfg)

    def _usable(self, q: Question, default: Any, cfg: dict, asked: bool) -> Any:
        """The default as its kind. An invalid saved value is replaced by the built-in default when the question is
        not asked (with a warning), re-prompted for interactively, and refused with the fix in -y mode."""
        if default in (None, "") and q.kind == "str":
            return default
        problem = self.answer_problem(q, default, cfg)
        if problem is None:
            return q.coerce(default)
        stock = q.stock_default(cfg)
        if not asked or ui.interactive():
            ui.warn(f"The saved {q.key} {default!r} is invalid ({problem}); using {stock!r}"
                    + ("." if not asked else " as the default."))
            return q.coerce(stock) if self.answer_problem(q, stock, cfg) is None else stock
        raise ui.Abort(f"The saved {q.key} {default!r} is invalid: {problem}. Fix it with: {q.fix_flag}")

    # ---- typed access to saved answers (for stack_vars) ----
    # A missing, null or blank saved value means the default (a hand-edited or older config.json): never a silent
    # False (a blank enable_account_baseline must not switch the baseline off) and never an abort that would lock
    # status/destroy out. Anything else is parsed strictly (bool("no") is True in Python) and aborts with the fix.
    def var_bool(self, cfg: dict, key: str, default: bool) -> bool:
        return self._typed(cfg, key, default, as_bool)

    def var_int(self, cfg: dict, key: str, default: int, minimum: int = 0) -> int:
        return self._typed(cfg, key, default, lambda v: as_int(v, minimum=minimum))

    def _typed(self, cfg: dict, key: str, default: Any, conv: Callable[[Any], Any]) -> Any:
        v = (cfg.get("vars") or {}).get(key)
        if v is None or (isinstance(v, str) and not v.strip()):
            return default
        try:
            return conv(v)
        except ValueError as e:
            env = f"{self.key}-{cfg.get('env', '<env>')}"
            raise ui.Abort(f"The saved setting {key}={v!r} of {env} is invalid ({e}). Fix it with: "
                           f"cloudseed setup {self.key} --env {cfg.get('env', '<env>')} --var {key}=VALUE") from None

    # ---- naming / tags ----
    # Tags that identify what cloudseed created and for which environment: reconcile.ownership decides from them
    # whether an existing object may be adopted, so a --tag of the same name (any case) never replaces them.
    IDENTITY_TAGS = ("ManagedBy", "CloudseedEnv", "CloudseedEnvId")

    def tags(self, cfg: dict) -> dict:
        """Tags/labels on every resource: Project, Environment and Owner (a --tag may change these), the user's --tag
        values, and the identity tags ManagedBy=cloudseed, CloudseedEnv=<cloud>-<env> and, for environments created
        by this version, CloudseedEnvId=<the environment's unique id> (paths.Env.save). Empty values are left out."""
        identity = {
            "ManagedBy": "cloudseed",
            "CloudseedEnv": f"{self.key}-{cfg['env']}",
            "CloudseedEnvId": str(cfg.get("uid") or ""),
        }
        reserved = {k.lower() for k in identity}
        base = {
            "Project": cfg["name"],
            "Environment": cfg["env"],
            "Owner": cfg.get("owner", ""),
        }
        # Tag keys are case-insensitive on AWS (IAM) and Azure, and GCP lower-cases label keys: a key spelled in
        # another case replaces the one before it (--tag owner=alice sets Owner) instead of rendering a duplicate the
        # cloud refuses at apply time. The built-in keys keep their spelling. An emptied tag (--tag KEY=) removes the
        # user's value in any case (a built-in one then shows its default again).
        canonical = {k.lower(): k for k in base}
        user: dict = {}
        for k, v in (cfg.get("tags") or {}).items():
            low = str(k).strip().lower()
            if low in reserved:
                continue
            user.pop(low, None)
            if v not in (None, ""):
                user[low] = (canonical.get(low, k), v)
        base.update(dict(user.values()))
        base.update(identity)
        return {k: v for k, v in base.items() if v}

    def ssh_user(self, cfg: dict) -> str:
        raise NotImplementedError

    # ---- terraform root pieces ----
    def required_providers(self) -> dict:
        raise NotImplementedError

    def provider_block(self, cfg: dict) -> dict:
        raise NotImplementedError

    def stack_vars(self, cfg: dict) -> dict:
        raise NotImplementedError

    def bootstrap_vars(self, cfg: dict) -> dict:
        raise NotImplementedError

    bootstrap_outputs: list[str] = []

    def backend_from_outputs(self, cfg: dict, outputs: dict) -> dict:
        raise NotImplementedError

    def credential_warnings(self, cfg: dict) -> list[str]:
        return []

    def check_vars(self, cfg: dict) -> None:
        """Hook run by setup once every answer (flags, prompts, --var) is final and before anything is saved:
        normalize cfg["vars"] and raise ui.Abort for values the cloud would only reject at apply time."""

    def keep_on_destroy(self, cfg: dict, resources: list[str]) -> list[tuple[str, str]]:
        """Hook run by a full destroy: (state address, notice) for each object in `resources` (terraform state list)
        that is a setting of the whole account or subscription rather than of this environment. destroy removes these
        from the state (`terraform state rm`, the object stays) instead of deleting them, and shows each distinct
        non-empty notice once."""
        return []

    def prepare(self, cfg: dict, dry_run: bool = False) -> None:
        """Hook run before Terraform (local adapters build the provider, fetch images, start services)."""

    # ---- rendering ----
    # Managed variables whose saved --var override (accepted by older versions) is ignored when rendering: cloudseed's
    # own value must win (the 0.0.0.0/0 guard and update-ip; the ManagedBy/CloudseedEnv tags) and the change is an
    # in-place update. Other saved overrides (name, CIDR, region, key) stay in effect: dropping them would replace
    # resources; setup refuses new ones and migrates the CIDR.
    ENFORCED_VARS = ("allowed_ssh_cidrs", "tags", "labels")

    def module_vars(self, cfg: dict) -> dict:
        """stack_vars plus the user's --var overrides (minus ENFORCED_VARS)."""
        extra = {k: v for k, v in (cfg.get("extra_vars") or {}).items() if k not in self.ENFORCED_VARS}
        return {**self.stack_vars(cfg), **extra}

    def render_stack(self, cfg: dict, tf_root) -> dict:
        tf_block: dict = {"required_version": ">= 1.10", "required_providers": self.required_providers()}
        backend = (cfg.get("state") or {}).get("backend")
        if backend:
            tf_block["backend"] = backend
        return {
            "terraform": tf_block,
            "provider": escape_literals(self.provider_block(cfg)),
            "module": {"stack": {"source": str(tf_root / self.key), **escape_literals(self.module_vars(cfg))}},
            "output": {n: {"value": f"${{module.stack.{n}}}"} for n in self.outputs},
        }

    def render_bootstrap(self, cfg: dict, tf_root) -> dict:
        return {
            "terraform": {"required_version": ">= 1.10", "required_providers": self.required_providers()},
            "provider": escape_literals(self.provider_block(cfg)),
            "module": {"state": {"source": str(tf_root / f"{self.key}-bootstrap"),
                                 **escape_literals(self.bootstrap_vars(cfg))}},
            "output": {n: {"value": f"${{module.state.{n}}}"} for n in self.bootstrap_outputs},
        }

