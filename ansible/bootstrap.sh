#!/usr/bin/env bash
# Runs ON the host (invoked by `cloudseed provision` over SSH).
# Installs Ansible into a private venv and applies ansible/$CLOUDSEED_PLAYBOOK (bastion.yml by default) locally.
set -euo pipefail

# ssh forwards the workstation's LANG/LC_* (SendEnv on macOS/Linux clients, AcceptEnv in Debian/Ubuntu/AL2023 sshd).
# ansible-core aborts ("could not initialize the preferred locale") when that locale is not generated on this host,
# so pin a UTF-8 locale every image has.
pick_locale() {
  local l
  for l in C.UTF-8 C.utf8 en_US.UTF-8 en_US.utf8; do
    if locale -a 2>/dev/null | grep -qix "$l"; then echo "$l"; return; fi
  done
  echo C.UTF-8
}
LOC="$(LC_ALL=C pick_locale)"
export LANG="$LOC" LC_ALL="$LOC"
unset LANGUAGE

REPO="${CLOUDSEED_REPO:-$HOME/cloudseed}"
VARS="${CLOUDSEED_VARS:-$HOME/cloudseed-vars.json}"
VENV="$HOME/.cloudseed-ansible"
PLAYBOOK="${CLOUDSEED_PLAYBOOK:-bastion.yml}"
MIN_PY="3.10"          # ansible-core >= 2.16 needs Python >= 3.10

echo "▸ bootstrap on $(uname -n) ($(. /etc/os-release && echo "$PRETTY_NAME"))"
# A fresh cloud image is still running cloud-init (package update/upgrade) when SSH first answers: wait for it.
if command -v cloud-init >/dev/null; then
  echo "▸ waiting for cloud-init to finish"
  timeout 900 cloud-init status --wait >/dev/null 2>&1 || true
fi

APT_TIMERS="apt-daily.timer apt-daily-upgrade.timer"
restore_apt_timers() {
  # the periodic apt timers (they drive unattended-upgrades) were stopped for the run: start the enabled ones again,
  # whatever the outcome, so a failed or --no-harden run never leaves automatic updates off until the next reboot
  local t
  for t in $APT_TIMERS; do
    if systemctl is-enabled --quiet "$t" 2>/dev/null; then sudo systemctl start "$t" 2>/dev/null || true; fi
  done
}
wait_for_apt() {
  # first boot on Ubuntu/Debian may still be running apt-daily / unattended-upgrades: stop them, then wait for the lock
  trap restore_apt_timers EXIT
  sudo systemctl stop $APT_TIMERS apt-daily.service apt-daily-upgrade.service unattended-upgrades 2>/dev/null || true
  local i=0
  while sudo fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/lib/dpkg/lock >/dev/null 2>&1 \
        || pgrep -x apt-get >/dev/null || pgrep -x dpkg >/dev/null || pgrep -x unattended-upgr >/dev/null; do
    i=$((i+1)); [ $i -eq 1 ] && echo "▸ waiting for the package manager lock"
    [ $i -gt 120 ] && { echo "package manager still busy after 10 minutes" >&2; return 1; }
    sleep 5
  done
}

py_ok() {   # $1 can build a venv (venv + ensurepip) and is new enough for ansible-core
  "$1" -c "import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (${MIN_PY/./, }) else 1)" >/dev/null 2>&1
}

APT="sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600"
if command -v apt-get >/dev/null; then
  wait_for_apt
  $APT update -qq
  $APT install -y -qq python3 python3-venv python3-pip tar >/dev/null
elif command -v dnf >/dev/null; then
  sudo dnf install -y -q python3 tar >/dev/null
  if ! py_ok python3; then
    # Amazon Linux 2023 (and RHEL 9) ship python3 = 3.9: install a newer interpreter next to it
    for v in 3.12 3.11; do sudo dnf install -y -q "python$v" >/dev/null 2>&1 && break; done
  fi
fi

PY=""
for c in python3 python3.13 python3.12 python3.11 python3.10; do
  if command -v "$c" >/dev/null && py_ok "$c"; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  echo "✖ ansible-core needs Python >= $MIN_PY with venv, and this host has none ($(python3 -V 2>&1 || echo 'no python3'))." >&2
  exit 1
fi

venv_ok() {
  [ -x "$VENV/bin/ansible-playbook" ] && \
    "$VENV/bin/python" -c "import sys, ansible; sys.exit(0 if sys.version_info >= (${MIN_PY/./, }) else 1)" >/dev/null 2>&1
}
if ! venv_ok; then
  echo "▸ installing ansible-core into $VENV ($("$PY" -V 2>&1))"
  # --clear: an earlier failed run (e.g. with a too-old python3) may have left a venv without Ansible
  "$PY" -m venv --clear "$VENV"
  log="$VENV/pip.log"
  if ! { "$VENV/bin/pip" install -q --disable-pip-version-check --upgrade pip &&
         "$VENV/bin/pip" install -q --disable-pip-version-check "ansible-core>=2.16"; } >"$log" 2>&1; then
    grep -v 'Ignored the following versions' "$log" | tail -20 >&2 || true
    echo "✖ could not install ansible-core with $("$PY" -V 2>&1) (full log: $log)" >&2
    exit 1
  fi
fi

# The address this SSH session comes from, as the host sees it (the workstation, a VMware host adapter, a NAT gateway):
# fail2ban never bans it, also when it is not in the SSH allow-list. The play runs under become, and sudo drops
# SSH_CLIENT, so it is handed over here.
CLIENT="${SSH_CLIENT:-}"
CLIENT="${CLIENT%% *}"
CLIENT_VARS=()
if [[ "$CLIENT" =~ ^[0-9A-Fa-f:.]+$ ]]; then CLIENT_VARS=(-e "cloudseed_ssh_client=$CLIENT"); fi

cd "$REPO/ansible"
echo "▸ running ansible/$PLAYBOOK"
rc=0
"$VENV/bin/ansible-playbook" -i localhost, -c local "$PLAYBOOK" -e "@$VARS" ${CLIENT_VARS[@]+"${CLIENT_VARS[@]}"} "$@" || rc=$?
exit "$rc"
