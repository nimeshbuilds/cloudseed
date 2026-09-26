"""Bundled HTTPS trust is shared by downloads and release discovery, without live network calls."""

import contextlib
import hashlib
import io
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest import mock

from cloudseed import deps, dr, localvm, netutil, scan


class Response(io.BytesIO):
    def __init__(self, body=b"release data", url="https://github.com/example/project/releases/tag/v1.2.3"):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}
        self.url = url

    def geturl(self):
        return self.url


class HTTPSDownloadTrustTests(unittest.TestCase):
    def setUp(self):
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.contexts.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.folder = Path(self.contexts.enter_context(tempfile.TemporaryDirectory(prefix="cloudseed-https-test-")))
        self.tls = netutil.https_context()

    def assert_verified(self, open_url, count=1):
        self.assertEqual(open_url.call_count, count)
        for call in open_url.call_args_list:
            context = call.kwargs["context"]
            self.assertIs(context, self.tls)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            request = call.args[0]
            url = request.full_url if hasattr(request, "full_url") else request
            self.assertTrue(url.startswith("https://"), url)

    def test_dependency_scanner_and_recovery_downloads_use_shared_verified_context(self):
        for fetch in (deps._download, scan._fetch, dr._get):
            with self.subTest(fetch=fetch.__module__), \
                    mock.patch.object(netutil, "https_context", return_value=self.tls) as trust, \
                    mock.patch("urllib.request.urlopen", return_value=Response()) as open_url:
                self.assertEqual(fetch("https://example.com/release", 17), b"release data")
                trust.assert_called_once_with()
                self.assert_verified(open_url)
                self.assertEqual(open_url.call_args.kwargs["timeout"], 17)

    def test_dependency_release_discovery_uses_shared_verified_context(self):
        with mock.patch.object(netutil, "https_context", return_value=self.tls) as trust, \
                mock.patch("urllib.request.urlopen", return_value=Response()) as open_url:
            self.assertEqual(deps._latest_github_tag("example/project", "v0.9.0"), "v1.2.3")
        trust.assert_called_once_with()
        self.assert_verified(open_url)
        self.assertEqual(open_url.call_args.args[0].get_method(), "HEAD")

    def test_scanner_release_api_and_redirect_fallback_use_verified_context(self):
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", return_value=Response(b'{"tag_name":"v2.0.0"}')) as open_url:
            self.assertEqual(scan._latest_tag("example/project"), "v2.0.0")
        self.assert_verified(open_url)
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", side_effect=[urllib.error.URLError("API unavailable"), Response()]) as open_url:
            self.assertEqual(scan._latest_tag("example/project"), "v1.2.3")
        self.assert_verified(open_url, count=2)

    def test_scanner_security_content_discovery_uses_verified_context(self):
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", return_value=Response(b'{"tag_name":"v1.2.3"}')) as open_url:
            self.assertEqual(scan._ssg_version(), "1.2.3")
        self.assert_verified(open_url)

    def test_vm_image_and_checksum_downloads_use_verified_context(self):
        destination = self.folder / "image.img"
        expected = hashlib.sha256(b"release data").hexdigest()
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", return_value=Response()) as open_url:
            localvm._download("https://example.com/image.img", destination, expected=("sha256", expected))
        self.assert_verified(open_url)
        self.assertEqual(destination.read_bytes(), b"release data")
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", return_value=Response(f"{expected} *image.img\n".encode())) as open_url:
            self.assertEqual(localvm._expected_sum("https://example.com/SHA256SUMS", "image.img"), ("sha256", expected))
        self.assert_verified(open_url)

    def test_certificate_failures_abort_downloads_without_insecure_retry(self):
        problem = urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate"))
        for fetch, error in ((deps._download, deps.DownloadError),
                             (scan._fetch, urllib.error.URLError), (dr._get, urllib.error.URLError)):
            with self.subTest(fetch=fetch.__module__), \
                    mock.patch.object(netutil, "https_context", return_value=self.tls), \
                    mock.patch("urllib.request.urlopen", side_effect=problem) as open_url:
                with self.assertRaises(error):
                    fetch("https://example.com/release", 1)
                self.assert_verified(open_url)

    def test_vm_image_certificate_failure_preserves_existing_file_and_discards_partials(self):
        destination = self.folder / "image.img"
        destination.write_bytes(b"previous verified image")
        problem = urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate"))
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", side_effect=problem) as open_url:
            with self.assertRaises(localvm._FetchError):
                localvm._download("https://example.com/image.img", destination)
        self.assert_verified(open_url)
        self.assertEqual(destination.read_bytes(), b"previous verified image")
        self.assertEqual(list(self.folder.iterdir()), [destination])

    def test_release_discovery_keeps_safe_fallback_on_certificate_failure(self):
        problem = urllib.error.URLError(ssl.SSLCertVerificationError("untrusted certificate"))
        with mock.patch.object(netutil, "https_context", return_value=self.tls), \
                mock.patch("urllib.request.urlopen", side_effect=problem) as open_url:
            self.assertEqual(deps._latest_github_tag("example/project", "v0.9.0"), "v0.9.0")
            self.assertEqual(scan._ssg_version(), scan.SSG_FALLBACK)
            with self.assertRaises(urllib.error.URLError):
                scan._latest_tag("example/project")
        self.assert_verified(open_url, count=4)

    def test_context_load_failure_does_not_attempt_an_unverified_download(self):
        with mock.patch.object(netutil, "https_context", side_effect=ssl.SSLError("invalid CA file")), \
                mock.patch("urllib.request.urlopen") as open_url:
            with self.assertRaises(deps.DownloadError):
                deps._download("https://example.com/release")
        open_url.assert_not_called()


if __name__ == "__main__":
    unittest.main()
