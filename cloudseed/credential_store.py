"""Optional native OS-keychain storage; never silently falls back to plaintext."""
from __future__ import annotations
import hashlib
import json
import platform
from pathlib import Path
from . import paths


def metadata(store: Path):
    file = store.with_name("credential-backend.json")
    if not file.exists():
        return {"backend": "file"}
    data = json.loads(file.read_text())
    if not isinstance(data, dict) or data.get("backend") not in ("file", "os-keychain"):
        raise ValueError("Invalid credential-backend.json; refusing to choose another credential store")
    return data


def _identity(store):
    digest = hashlib.sha256(str(store.resolve()).encode()).hexdigest()[:24]
    return "cloudseed." + digest, "credentials"


def _native():
    try:
        if platform.system() == "Darwin":
            from keyring.backends.macOS import Keyring
            backend = Keyring()
        elif platform.system() == "Linux":
            from keyring.backends.SecretService import Keyring
            backend = Keyring()
        elif platform.system() == "Windows":
            from keyring.backends.Windows import WinVaultKeyring
            backend = WinVaultKeyring()
        else:
            raise ValueError("No supported native keychain backend on this operating system")
        # Accessing priority checks the platform's native service. Do not select a
        # third-party plaintext fallback or auto-install anything while unlocking.
        if backend.priority <= 0:
            raise ValueError("Native keychain is unavailable")
        return backend
    except ImportError as exc:
        raise ValueError("OS keychain support needs the optional keyring package in the Cloudseed Python runtime; install keyring and retry") from exc


def read(store):
    service, account = _identity(store)
    raw = _native().get_password(service, account)
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("The keychain credential entry is not an object")
    return data


def write(store, data):
    service, account = _identity(store)
    _native().set_password(service, account, json.dumps(data))
    from . import secrets
    secrets._LIT_CACHE["stamp"] = None


def clear(store):
    service, account = _identity(store)
    backend = _native()
    if backend.get_password(service, account) is not None:
        backend.delete_password(service, account)
    from . import secrets
    secrets._LIT_CACHE["stamp"] = None


def execute(action, cloud, env, cfg, params):
    from . import creds
    current = metadata(creds.STORE)["backend"]
    target = params.get("backend", current)
    if target not in ("file", "os-keychain"):
        raise ValueError("backend must be file or os-keychain")
    report = {"schema_version": 1, "operation": action, "verdict": "PASS", "backend": current,
              "requested_backend": target, "changed": False,
              "limits": ["Native keychain protects storage at rest; it does not isolate code running as the same authorized user.",
                         "SDK key-file materialization and existing undo entries can contain credential copies; use explicit forget when clearing old copies."]}
    if target == current:
        return report
    if not params.get("approve"):
        report.update(verdict="PLAN", message="Review the storage migration, then repeat with --approve.")
        return report
    with creds._LOCK:
        # Existing file vaults may intentionally live behind symlinks. Removing
        # that link would leave the original plaintext secret file behind.
        if creds.STORE.is_symlink():
            raise ValueError("Credential migration requires a regular credentials.json file; resolve its symlink before migrating so no plaintext target is left behind")
        data = creds.load()
        if target == "os-keychain":
            write(creds.STORE, data)
            if read(creds.STORE) != data:
                raise ValueError("Keychain verification failed; original file was preserved")
        else:
            creds._write_private(creds.STORE, json.dumps(data, indent=2) + "\n")
        paths.atomic_write(creds.STORE.with_name("credential-backend.json"),
                           json.dumps({"backend": target}) + "\n", 0o600)
        # The verified destination is selected before retiring the previous copy.
        if target == "os-keychain":
            creds.STORE.unlink(missing_ok=True)
        else:
            clear(creds.STORE)
    report.update(backend=target, changed=True)
    return report
