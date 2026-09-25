package vmware

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Shell-script stand-ins for vmrun and vmware-vdiskmanager. They only use shell builtins (PATH is narrowed in the tests
// so no ISO tool or real VMware binary is ever found), log every call to $FAKE_LOG and keep the "running" VM list in
// $FAKE_DIR/running, one .vmx path per line.
const fakeVmrun = `#!/bin/sh
echo "vmrun $*" >> "$FAKE_LOG"
shift 2
case "$1" in
list)
  n=0; lines=""
  if [ -f "$FAKE_DIR/running" ]; then
    while IFS= read -r l; do [ -n "$l" ] && { n=$((n+1)); lines="$lines$l
"; }; done < "$FAKE_DIR/running"
  fi
  echo "Total running VMs: $n"; printf '%s' "$lines" ;;
start) printf '%s\n' "$2" >> "$FAKE_DIR/running" ;;
stop)
  new=""
  if [ -f "$FAKE_DIR/running" ]; then
    while IFS= read -r l; do [ "$l" = "$2" ] || new="$new$l
"; done < "$FAKE_DIR/running"
  fi
  printf '%s' "$new" > "$FAKE_DIR/running" ;;
getGuestIPAddress) echo "10.0.0.9" ;;
bad) echo "Error: The file specified is not a virtual machine"; exit 255 ;;
esac
exit 0
`

const fakeVdisk = `#!/bin/sh
echo "vdisk $*" >> "$FAKE_LOG"
case "$1" in
-r) : > "$5" ;;
-x) if [ -n "$FAKE_VDISK_FAIL" ]; then echo "Failed to expand the disk: the virtual disk has snapshots"; exit 1; fi ;;
esac
exit 0
`

// fakeTools puts fake vmrun / vmware-vdiskmanager into a fresh VMWARE_HOME, points PATH at it only (plus /bin for sh),
// and returns the directory; fakeLog reads what they were asked to do.
func fakeTools(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fakes")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"vmrun": fakeVmrun, "vmware-vdiskmanager": fakeVdisk} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VMWARE_HOME", dir)
	t.Setenv("FAKE_DIR", dir)
	t.Setenv("FAKE_LOG", filepath.Join(dir, "calls.log"))
	t.Setenv("FAKE_VDISK_FAIL", "")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/bin")
	return dir
}

func fakeLog(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "calls.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
