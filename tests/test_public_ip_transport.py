"""Public-IP HTTPS behavior, including portable bundle trust and safe errors."""
import io
import os
from pathlib import Path
import ssl
import sys
import types
import unittest
import urllib.error
from unittest import mock

from cloudseed import netutil


class PublicIPTransportTests(unittest.TestCase):
    def test_verified_https_returns_ipv4_without_diagnostics(self):
        diagnostics = ["old failure"]
        with mock.patch.object(netutil.urllib.request, "urlopen", return_value=io.BytesIO(b"8.8.8.8\n")) as open_url:
            self.assertEqual(netutil.detect_public_ip(timeout=2, diagnostics=diagnostics), "8.8.8.8")
        request = open_url.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://"))
        context = open_url.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(open_url.call_args.kwargs["timeout"], 2)
        self.assertEqual(diagnostics, [])

    def test_temporary_failure_and_ipv6_do_not_prevent_later_ipv4_success(self):
        answers = [TimeoutError(), io.BytesIO(b"2001:db8::1"), io.BytesIO(b"8.8.4.4\n")]
        diagnostics = []
        with mock.patch.object(netutil.urllib.request, "urlopen", side_effect=answers) as open_url:
            self.assertEqual(netutil.detect_public_ip(diagnostics=diagnostics), "8.8.4.4")
        self.assertEqual(open_url.call_count, 3)
        self.assertEqual(diagnostics, [])

    def test_certificate_failure_explains_trust_without_leaking_exception_details(self):
        problem = urllib.error.URLError(ssl.SSLCertVerificationError("proxy password secret-value"))
        diagnostics = []
        with mock.patch.object(netutil.urllib.request, "urlopen", side_effect=problem) as open_url:
            self.assertIsNone(netutil.detect_public_ip(diagnostics=diagnostics))
        self.assertEqual(open_url.call_count, len(netutil.IP_SOURCES))
        self.assertIn("certificate verification failed", diagnostics[0])
        self.assertIn("SSL_CERT_FILE", diagnostics[0])
        self.assertNotIn("secret-value", str(diagnostics))

    def test_timeout_network_and_invalid_responses_have_distinct_safe_hints(self):
        for error, expected in [(TimeoutError("secret"), "timed out"),
                                (urllib.error.URLError("secret"), "Could not reach"),
                                (ssl.SSLError("secret"), "verified HTTPS")]:
            with self.subTest(kind=type(error).__name__):
                diagnostics = []
                with mock.patch.object(netutil.urllib.request, "urlopen", side_effect=error):
                    self.assertIsNone(netutil.detect_public_ip(diagnostics=diagnostics))
                self.assertIn(expected, diagnostics[0])
                self.assertNotIn("secret", str(diagnostics))
        for body in [b"<html>proxy login</html>", b"2001:db8::1", b"\xff"]:
            diagnostics = []
            with mock.patch.object(netutil.urllib.request, "urlopen", side_effect=lambda *a, **kw: io.BytesIO(body)):
                self.assertIsNone(netutil.detect_public_ip(diagnostics=diagnostics))
            self.assertIn("no valid IPv4", diagnostics[0])

    def test_legacy_call_still_returns_none_on_failure(self):
        with mock.patch.object(netutil.urllib.request, "urlopen", side_effect=TimeoutError()):
            self.assertIsNone(netutil.detect_public_ip())


class PublicIPBundleTrustTests(unittest.TestCase):
    def test_frozen_runtime_adds_bundled_roots_to_default_context(self):
        context = mock.Mock(spec=ssl.SSLContext)
        certifi = types.SimpleNamespace(where=lambda: "/bundle/certifi/cacert.pem")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.dict(sys.modules, {"certifi": certifi}), \
                mock.patch.object(netutil.ssl, "create_default_context", return_value=context) as create:
            self.assertIs(netutil.https_context(), context)
        create.assert_called_once_with()
        context.load_verify_locations.assert_called_once_with(cafile="/bundle/certifi/cacert.pem")

    def test_explicit_trust_overrides_are_not_replaced_or_augmented(self):
        for key in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            with self.subTest(key=key):
                context = mock.Mock(spec=ssl.SSLContext)
                with mock.patch.dict(os.environ, {key: "/configured/trust"}, clear=True), \
                        mock.patch.object(sys, "frozen", True, create=True), \
                        mock.patch.dict(sys.modules, {"certifi": None}), \
                        mock.patch.object(netutil.ssl, "create_default_context", return_value=context):
                    self.assertIs(netutil.https_context(), context)
                    self.assertEqual(os.environ[key], "/configured/trust")
                context.load_verify_locations.assert_not_called()

    def test_source_runtime_does_not_require_certifi(self):
        with mock.patch.object(sys, "frozen", False, create=True), \
                mock.patch.dict(sys.modules, {"certifi": None}):
            context = netutil.https_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_missing_bundle_trust_fails_closed_with_actionable_message(self):
        diagnostics = []
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.dict(sys.modules, {"certifi": None}), \
                mock.patch.object(netutil.urllib.request, "urlopen") as open_url:
            self.assertIsNone(netutil.detect_public_ip(diagnostics=diagnostics))
        open_url.assert_not_called()
        self.assertIn("trusted HTTPS certificates", diagnostics[0])

    def test_release_build_ships_the_certificate_inventory(self):
        script = (Path(__file__).resolve().parents[1] / "scripts/build-bundle.sh").read_text()
        self.assertIn('"certifi==2026.7.22"', script)
        self.assertIn("--collect-data certifi", script)
        self.assertIn("--copy-metadata certifi", script)
        self.assertIn("tfbin/terraform certifi/cacert.pem", script)


if __name__ == "__main__":
    unittest.main()
