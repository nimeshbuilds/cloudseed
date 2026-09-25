"""Exercise files owned by a frozen process after its launching process exits."""
import json
import os
import shlex
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path


@unittest.skipUnless(os.environ.get("CLOUDSEED_TEST_BINARY"), "requires a built cloudseed binary")
class BundleLifecycleTests(unittest.TestCase):
    def test_console_job_keeps_bundled_resources_after_console_stops(self):
        binary = str(Path(os.environ["CLOUDSEED_TEST_BINARY"]).resolve())
        with tempfile.TemporaryDirectory(prefix="cs-bundle-life-") as temporary:
            home = Path(temporary)
            cs = home / "cs"
            (cs / "bin").mkdir(parents=True)
            (cs / "ui").mkdir()
            (cs / "ui" / "server.json").write_text('{"service":"background"}')
            env_dir = cs / "envs" / "aws-dev"
            env_dir.mkdir(parents=True)
            (env_dir / "config.json").write_text(json.dumps({
                "cloud": "aws", "env": "dev", "name": "cs", "region": "us-west-2",
                "vars": {}, "state": {"type": "local"},
            }))
            (env_dir / "outputs.json").write_text('{"bastion_public_ip":"192.0.2.1"}')
            release = home / "release"
            fake_ssh = cs / "bin" / "ssh"
            fake_ssh.write_text(
                "#!/bin/sh\necho bundle-job-ready\nn=0\n"
                f"while [ ! -f {shlex.quote(str(release))} ]; do "
                "n=$((n + 1)); [ $n -lt 1200 ] || exit 124; sleep 0.05; done\n"
                f"exec {shlex.quote(binary)} skill show cloudseed\n"
            )
            fake_ssh.chmod(0o755)
            env = dict(os.environ, CLOUDSEED_HOME=str(cs), HOME=str(home), NO_COLOR="1")
            for key in ("CLOUDSEED_SESSION", "CLOUDSEED_REDACT", "CLOUDSEED_UI_MANAGED", "CLOUDSEED_MCP_MANAGED"):
                env.pop(key, None)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            url = f"http://127.0.0.1:{port}"

            def run(*args):
                result = subprocess.run([binary, *args], env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout

            def api(method, path, body=None):
                request = urllib.request.Request(
                    url + path, method=method,
                    data=json.dumps(body).encode() if body is not None else None,
                    headers={"X-CS-Token": (cs / "ui" / "token").read_text().strip(),
                             "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    return json.load(response)

            def wait_for(check):
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if check():
                        return
                    time.sleep(0.1)
                self.fail("bundled console job did not reach the expected state")

            try:
                run("enable", "ui", "--no-open", "--port", str(port))
                # The launching CLI has exited; the detached console still needs its HTML.
                with urllib.request.urlopen(url + "/", timeout=10) as response:
                    self.assertIn(b"<html", response.read().lower())
                job = api("POST", "/api/run", {"action": "cloudseed_ssh", "args": {
                    "cloud": "aws", "env": "dev", "command": "uptime", "confirm": True,
                }})["job"]
                wait_for(lambda: "bundle-job-ready" in api("GET", f"/api/jobs/{job}")["lines"])
                run("ui", "stop")
                # The detached job must launch a bundled command after the console's assets are removed.
                release.touch()
                result = cs / "ui" / "jobs" / f"{job}.rc"
                wait_for(result.exists)
                log = (result.with_suffix(".log")).read_text()
                self.assertEqual(result.read_text().strip(), "0", log)
                self.assertIn("name: cloudseed", log)
                run("ui", "start", "--no-open")
                wait_for(lambda: not api("GET", f"/api/jobs/{job}")["running"])
                self.assertEqual(api("GET", f"/api/jobs/{job}")["rc"], 0)
            finally:
                release.touch()
                subprocess.run([binary, "ui", "stop"], env=env, capture_output=True, timeout=60)


if __name__ == "__main__":
    unittest.main()
