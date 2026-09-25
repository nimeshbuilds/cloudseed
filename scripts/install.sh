#!/usr/bin/env bash
# Put `cloudseed` (and the short alias `cs`) on your PATH as symlinks to this checkout.
#
#   scripts/install.sh [TARGET_DIR] [--alias NAME | --no-alias] [--force] [--uninstall]
#
# TARGET_DIR defaults to /usr/local/bin when writable, else ~/.local/bin. An existing file that is not a link to this
# checkout is never replaced silently: `cloudseed` stops with an explanation, the alias is skipped (use --alias NAME
# for another name, or --force to move the existing file aside as <name>.bak.<time> first).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/bin/cloudseed"
MIN_PY="3.9"

TARGET=""
ALIAS="cs"
FORCE=0
UNINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --alias) [[ $# -ge 2 && -n "$2" ]] || { echo "--alias needs a name" >&2; exit 2; }; ALIAS="$2"; shift 2 ;;
    --alias=*) ALIAS="${1#--alias=}"; shift ;;
    --no-alias) ALIAS=""; shift ;;
    --force) FORCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    *) [[ -z "$TARGET" ]] || { echo "only one target directory, got '$TARGET' and '$1'" >&2; exit 2; }; TARGET="$1"; shift ;;
  esac
done
if [[ -z "$TARGET" ]]; then
  if [[ -w /usr/local/bin ]]; then TARGET=/usr/local/bin; else TARGET="$HOME/.local/bin"; fi
fi
if [[ "$ALIAS" == */* || "$ALIAS" == "cloudseed" ]]; then echo "invalid alias name: $ALIAS" >&2; exit 2; fi

# absolute, symlink-free path of whatever a link points to (portable: no readlink -f on older macOS)
resolve() {
  python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1" 2>/dev/null || echo "$1"
}
REAL_SRC="$(resolve "$SRC")"
ours() { [[ -L "$1" || -e "$1" ]] && [[ "$(resolve "$1")" == "$REAL_SRC" ]]; }

if [[ "$UNINSTALL" == 1 ]]; then
  # every link in TARGET that points at this checkout's launcher (cloudseed, cs, or any --alias used before)
  removed=0
  for p in "$TARGET"/*; do
    [[ -L "$p" ]] || continue
    [[ "$(readlink "$p")" == *cloudseed* ]] || continue
    if ours "$p"; then rm -f "$p"; echo "✔ removed $p"; removed=1; fi
  done
  [[ "$removed" == 1 ]] || echo "nothing of this checkout is linked in $TARGET"
  exit 0
fi

# Python: the launcher runs `/usr/bin/env python3`
if ! command -v python3 >/dev/null 2>&1; then
  echo "✖ python3 was not found on PATH; cloudseed needs Python >= $MIN_PY (macOS: brew install python; Linux: your package manager)." >&2
  exit 1
fi
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= tuple(int(x) for x in '$MIN_PY'.split('.')) else 1)"; then
  echo "✖ $(command -v python3) is Python $(python3 -c 'import platform; print(platform.python_version())'); cloudseed needs >= $MIN_PY." >&2
  echo "  macOS: brew install python   ·   Linux: install python3.9 or newer with your package manager" >&2
  exit 1
fi

mkdir -p "$TARGET"

# link NAME REQUIRED: 0 = linked, 1 = skipped (only when not required)
link() {
  local name="$1" required="$2" p="$TARGET/$1"
  if [[ -L "$p" || -e "$p" ]] && ! ours "$p"; then
    local what
    if [[ -L "$p" ]]; then what="a link to $(resolve "$p")"; else what="$(file -b "$p" 2>/dev/null | cut -c1-60 || echo "a file")"; fi
    if [[ "$FORCE" == 1 ]]; then
      local bak; bak="$p.bak.$(date +%s)"
      mv "$p" "$bak"
      echo "! moved the existing $p ($what) to $bak"
    elif [[ "$required" == 1 ]]; then
      echo "✖ $p already exists ($what) and is not this checkout's cloudseed; not replacing it." >&2
      echo "  Use another directory (scripts/install.sh DIR), or --force to move it aside." >&2
      exit 1
    else
      echo "! $p already exists ($what); not replacing it. Use \`cloudseed\`, or re-run with --alias NAME (or --force)."
      return 1
    fi
  fi
  ln -sfn "$SRC" "$p"
  return 0
}

link cloudseed 1
echo "✔ linked $TARGET/cloudseed -> $SRC"
SHORT="cloudseed"
if [[ -n "$ALIAS" ]] && link "$ALIAS" 0; then
  echo "✔ linked $TARGET/$ALIAS -> $SRC   (short alias)"
  SHORT="$ALIAS"
fi

# the command must be the one we just linked, not another one earlier on PATH
case ":$PATH:" in
  *":$TARGET:"*)
    for name in $(printf '%s\n' cloudseed "$SHORT" | sort -u); do
      found="$(command -v "$name" 2>/dev/null || true)"
      if [[ -n "$found" && "$(resolve "$found")" != "$REAL_SRC" ]]; then
        echo "! \`$name\` currently runs $found (earlier on PATH than $TARGET)."
      fi
    done
    ;;
esac
echo "  try: cloudseed help   ·   $SHORT setup aws   ·   $SHORT agentic \"list my environments\""
case ":$PATH:" in
  *":$TARGET:"*) ;;
  *)
    echo "! $TARGET is not on your PATH. Add it with:"
    case "$(basename "${SHELL:-sh}")" in
      zsh)  echo "    echo 'export PATH=\"$TARGET:\$PATH\"' >> ~/.zshrc && source ~/.zshrc" ;;
      bash) echo "    echo 'export PATH=\"$TARGET:\$PATH\"' >> ~/.bash_profile && source ~/.bash_profile" ;;
      fish) echo "    fish_add_path $TARGET" ;;
      *)    echo "    export PATH=\"$TARGET:\$PATH\"   (in your shell's startup file)" ;;
    esac
    ;;
esac
