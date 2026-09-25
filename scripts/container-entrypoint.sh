#!/bin/sh
# Entry point of the cloudseed container image: runs cloudseed, then gives the host user back what it created.
#
# Everything in the container runs as root. With rootful Docker on Linux, root inside is root on the host, so files
# written into the bind-mounted host directories (CLOUDSEED_HOME, workdirs, ~/.aws & co) would end up owned by root.
# cloudseed/container.py then passes CLOUDSEED_HOST_UID / CLOUDSEED_HOST_GID and the mounted paths
# (CLOUDSEED_CHOWN_PATHS, ':'-separated); after the command, every root-owned file this run created or changed there
# is handed to that uid:gid. Without those variables (macOS, podman keep-id, rootless Docker) it only runs cloudseed.
set -u
CLOUDSEED="$(dirname "$0")/../bin/cloudseed"           # /workspace/bin/cloudseed

uid="${CLOUDSEED_HOST_UID:-}"
gid="${CLOUDSEED_HOST_GID:-$uid}"
case "$uid:$gid" in
  *[!0-9:]*|:*|*:) exec "$CLOUDSEED" "$@" ;;          # not set, or not numeric: nothing to hand back
esac
if [ "$uid" = 0 ] || [ "$(id -u)" != 0 ]; then
  exec "$CLOUDSEED" "$@"
fi

# ctime marks what this run created or changed (unlike mtime, extraction and copies cannot backdate it)
marker="$(mktemp 2>/dev/null)" || exec "$CLOUDSEED" "$@"
"$CLOUDSEED" "$@"
rc=$?

set -f                                                  # the list is split on ':' only, never globbed
old_ifs="$IFS"
IFS=:
for p in ${CLOUDSEED_CHOWN_PATHS:-${CLOUDSEED_HOME:-}}; do
  IFS="$old_ifs"
  [ -n "$p" ] && [ -e "$p" ] || continue
  find "$p" -user 0 -cnewer "$marker" -exec chown -h "$uid:$gid" {} + 2>/dev/null || true
done
IFS="$old_ifs"
rm -f "$marker"
exit "$rc"
