#!/usr/bin/env bash
# Build a single self-contained cloudseed binary for this OS/arch.
# Embeds: the Python CLI, every Terraform module, the web console, platform templates, skills, the Ansible playbooks,
# the VMware provider sources and a verified Terraform release. Result: dist/cloudseed-<os>-<arch>
#
# Data directories are staged into build/stage first, without anything a working checkout accumulates
# (.terraform provider caches from `make validate` / `terraform init`, lock files, state, plans, secrets, caches):
# a onefile binary unpacks everything it carries on every start.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
STAGE="$BUILD/stage"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac
NAME="cloudseed-${OS}-${ARCH}"
BIN="$ROOT/dist/$NAME"

TF_VERSION="${TF_VERSION:-$(curl -fsSL https://checkpoint-api.hashicorp.com/v1/check/terraform | python3 -c 'import json,sys; print(json.load(sys.stdin)["current_version"])')}"
echo "▸ Terraform ${TF_VERSION} for ${OS}/${ARCH}"

mkdir -p "$BUILD/tfbin"
ZIP="terraform_${TF_VERSION}_${OS}_${ARCH}.zip"
BASE="https://releases.hashicorp.com/terraform/${TF_VERSION}"
curl -fsSL "$BASE/$ZIP" -o "$BUILD/$ZIP"
curl -fsSL "$BASE/terraform_${TF_VERSION}_SHA256SUMS" -o "$BUILD/SHA256SUMS"
EXPECTED="$(grep " ${ZIP}\$" "$BUILD/SHA256SUMS" | awk '{print $1}')"
ACTUAL="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$BUILD/$ZIP")"
if [[ -z "$EXPECTED" || "$EXPECTED" != "$ACTUAL" ]]; then echo "checksum mismatch for $ZIP" >&2; exit 1; fi
unzip -qo "$BUILD/$ZIP" terraform -d "$BUILD/tfbin"
chmod +x "$BUILD/tfbin/terraform"

echo "▸ Staging data"
rm -rf "$STAGE"
python3 - "$ROOT" "$STAGE" <<'PY'
import shutil
import sys
from pathlib import Path

root, stage = Path(sys.argv[1]), Path(sys.argv[2])
junk = shutil.ignore_patterns(
    ".terraform", ".terraform.lock.hcl", "*.tfstate", "*.tfstate.*", "tfplan", "*.tfvars", "crash.log",
    ".env", ".env.*", ".envrc", "__pycache__", "*.pyc", ".DS_Store", "*.test", "go.sum.bak", "terraform-provider-*")
# every directory the code reads from REPO_ROOT (paths.REPO_ROOT is the unpack dir in a bundle)
for d in ("terraform", "skills", "ansible", "providers", "templates", "assets", "cloudseed/web"):
    shutil.copytree(root / d, stage / d, ignore=junk)
PY

echo "▸ Preparing PyInstaller"
python3 -m venv "$BUILD/venv"
"$BUILD/venv/bin/pip" install --quiet --upgrade pip pyinstaller

echo "▸ Building"
"$BUILD/venv/bin/pyinstaller" --onefile --clean --noconfirm \
  --name "$NAME" \
  --distpath "$ROOT/dist" --workpath "$BUILD/pyi" --specpath "$BUILD" \
  --paths "$ROOT" \
  --add-data "$STAGE/terraform:terraform" \
  --add-data "$STAGE/skills:skills" \
  --add-data "$STAGE/ansible:ansible" \
  --add-data "$STAGE/providers:providers" \
  --add-data "$STAGE/templates:templates" \
  --add-data "$STAGE/assets:assets" \
  --add-data "$STAGE/cloudseed/web:cloudseed/web" \
  --add-data "$BUILD/tfbin/terraform:tfbin" \
  "$ROOT/bin/cloudseed"

echo "▸ Smoke test"
SMOKE="$(mktemp -d)"
trap 'rm -rf "$SMOKE"' EXIT
export CLOUDSEED_HOME="$SMOKE/home"
"$BIN" --version
(cd "$SMOKE" && "$BIN" -y platform template gitlab-ci >/dev/null) && test -f "$SMOKE/.gitlab-ci.yml" \
  || { echo "smoke test failed: platform template (templates/ not bundled?)" >&2; exit 1; }
LISTING="$("$BUILD/venv/bin/pyi-archive_viewer" -l "$BIN" 2>/dev/null || true)"
if [[ -n "$LISTING" ]]; then
  for f in cloudseed/web/index.html cloudseed/web/app.js assets/icon.svg templates/gitlab-ci/.gitlab-ci.yml tfbin/terraform; do
    grep -q "$f" <<<"$LISTING" || { echo "smoke test failed: $f is missing from the bundle" >&2; exit 1; }
  done
  if grep -q "/\.terraform/" <<<"$LISTING"; then echo "smoke test failed: .terraform caches were bundled" >&2; exit 1; fi
else
  echo "  (pyi-archive_viewer unavailable; skipped the content listing check)"
fi
unset CLOUDSEED_HOME

echo "✔ Built: $BIN"
echo "  Copy it anywhere on your PATH, e.g.: install -m 755 dist/$NAME /usr/local/bin/cloudseed"
echo "  Short alias:                          ln -s /usr/local/bin/cloudseed /usr/local/bin/cs   (skip it if another cs exists)"
