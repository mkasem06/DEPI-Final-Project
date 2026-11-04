"""
Tests for the two things added/fixed in this audit pass:

  1. The canary-isolation bug fix: check_reflection()/_classify_reflection()
     must check for the canary actually embedded in the `payload` argument,
     never the module-level CANARY constant.
  2. The new stored-XSS workflow (run_stored_xss_checks / the test_stored_xss
     option on run()).

Run with:  AUTHORIZED_TARGET=https://example.com python -m unittest \
             tests.test_xss_stored_and_canary -v
All HTTP is mocked - no traffic is sent anywhere.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["AUTHORIZED_TARGET"] = "https://example.com"

import importlib
import xss.xss as xss
importlib.reload(xss)


def _resp(text, status_code=200, headers=None):
    m = MagicMock()
    m.text = text
    m.status_code = status_code
    m.headers = headers or {}
    return m


class TestCanaryIsolation(unittest.TestCase):
    """Regression tests for the bug: classification used to check the
    module-level CANARY constant regardless of which canary the payload
    argument actually contained."""

    def test_payload_with_different_canary_than_module_CANARY_is_still_classified(self):
        other_canary = "xss" + "deadbeef"
        self.assertNotEqual(other_canary, xss.CANARY)  # sanity: genuinely different
        payload = f"<script>alert('{other_canary}')</script>"
        body = f"<html><body><div>{payload}</div></body></html>"

        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "confirmed")
        self.assertEqual(result["classification"], "script_context")

    def test_two_different_canaries_do_not_cross_contaminate(self):
        canary_a = "xss" + "aaaaaaaa"
        canary_b = "xss" + "bbbbbbbb"
        payload_a = f"<script>alert('{canary_a}')</script>"
        payload_b = f"<script>alert('{canary_b}')</script>"

        # A response that reflects canary_a, checked against payload_b
        # (canary_b) must NOT be reported as reflected - they must not
        # cross-match just because both are "xss"-prefixed canaries.
        body_with_a_only = f"<html><body>{payload_a}</body></html>"
        result = xss.check_reflection(body_with_a_only, payload_b)
        self.assertFalse(result["reflected"])
        self.assertEqual(result["classification"], "not_reflected")

    def test_get_payload_list_with_custom_canary_is_correctly_classified(self):
        custom_canary = "xss" + "c0ffee00"
        payloads = xss.get_payload_list(canary=custom_canary)
        script_payload = next(p for p in payloads if p["context"] == "html_text")["payload"]
        self.assertIn(custom_canary, script_payload)

        body = f"<html><body>{script_payload}</body></html>"
        result = xss.check_reflection(body, script_payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "confirmed")

    def test_extract_canary_falls_back_with_warning_for_canary_less_payload(self):
        # A payload with no embedded canary at all (unusual, but must not
        # crash) - falls back to the module CANARY and logs a warning.
        with self.assertLogs("xss.xss", level="WARNING") as log_ctx:
            extracted = xss._extract_canary("<script>alert(1)</script>")
        self.assertEqual(extracted, xss.CANARY)
        self.assertTrue(any("could not find an embedded canary" in msg for msg in log_ctx.output))

    def test_generate_unique_canary_differs_each_call(self):
        c1 = xss._generate_unique_canary()
        c2 = xss._generate_unique_canary()
        self.assertNotEqual(c1, c2)
        self.assertRegex(c1, r"^xss[0-9a-f]{8}$")


class TestStoredXssEnablement(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    def test_disabled_by_default_env_unset(self):
        env = dict(os.environ)
        env.pop("XSS_TEST_STORED_XSS", None)
        with patch.dict(os.environ, env, clear=True):
            os.environ["AUTHORIZED_TARGET"] = "https://example.com"
            self.assertFalse(xss._stored_xss_enabled(None))

    def test_env_var_true_enables(self):
        with patch.dict(os.environ, {"XSS_TEST_STORED_XSS": "true"}):
            self.assertTrue(xss._stored_xss_enabled(None))

    def test_env_var_various_truthy_strings(self):
        for val in ("1", "true", "True", "YES", "on"):
            with patch.dict(os.environ, {"XSS_TEST_STORED_XSS": val}):
                self.assertTrue(xss._stored_xss_enabled(None), f"expected {val!r} to enable")

    def test_explicit_true_overrides_env_false(self):
        with patch.dict(os.environ, {"XSS_TEST_STORED_XSS": "false"}):
            self.assertTrue(xss._stored_xss_enabled(True))

    def test_explicit_false_overrides_env_true(self):
        with patch.dict(os.environ, {"XSS_TEST_STORED_XSS": "true"}):
            self.assertFalse(xss._stored_xss_enabled(False))

    @patch("xss.xss._run_stored_phase")
    @patch("xss.xss._run_reflected_phase")
    def test_run_does_not_invoke_stored_phase_when_disabled(self, mock_reflected, mock_stored):
        mock_reflected.return_value = []
        xss.run({"params": []})  # test_stored_xss not passed -> defaults off
        mock_stored.assert_not_called()

    @patch("xss.xss._run_stored_phase")
    @patch("xss.xss._run_reflected_phase")
    def test_run_invokes_stored_phase_when_explicitly_enabled(self, mock_reflected, mock_stored):
        mock_reflected.return_value = []
        mock_stored.return_value = []
        xss.run({"params": []}, test_stored_xss=True)
        mock_stored.assert_called_once()


class TestStoredXssWorkflow(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_get_endpoints_are_never_storage_candidates(self, mock_post, mock_get):
        recon_output = {"params": [
            {"url": "https://example.com/search", "method": "GET", "params": ["q"]},
        ]}
        findings = xss.run_stored_xss_checks(recon_output)
        self.assertEqual(findings, [])
        mock_post.assert_not_called()

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_persisted_unescaped_value_is_confirmed_stored_finding(self, mock_post, mock_get):
        # The POST submission's own response is irrelevant to the stored
        # detection - only the SEPARATE later GET matters. Make the POST
        # response bland (e.g. "thanks"), and have the GET reflect the
        # payload back unescaped, as if the comment was saved and re-rendered.
        mock_post.return_value = _resp("Thanks for your comment!", 200)

        captured = {}

        def fake_get(url, headers=None, timeout=None, **kwargs):
            # requests.get is used both by inject_payload's GET path (not
            # relevant here, this endpoint is POST) and by _fetch_plain.
            payload = captured.get("payload", "")
            return _resp(f"<html><body><div class='comments'>{payload}</div></body></html>")

        mock_get.side_effect = fake_get

        # Capture the payload actually sent via POST so the fake GET can echo it.
        orig_post = mock_post.return_value

        def fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None, **kwargs):
            captured["payload"] = data.get("comment", "")
            return orig_post

        mock_post.side_effect = fake_post

        recon_output = {"params": [
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        findings = xss.run_stored_xss_checks(recon_output)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(set(f.keys()),
                          {"module", "target", "finding", "severity", "evidence", "confidence", "timestamp"})
        self.assertEqual(f["module"], "xss")
        self.assertIn("stored xss", f["finding"].lower())
        self.assertEqual(f["confidence"], "confirmed")
        # Same severity table as reflected script_context findings - NOT
        # automatically bumped to "critical" just because this came from
        # the stored-XSS phase. See _run_stored_phase's finding-
        # construction comment for why: this module cannot independently
        # confirm persistence, so it doesn't use "stored" as grounds to
        # auto-upgrade severity.
        self.assertEqual(f["severity"], "high")
        self.assertIn("No cleanup mechanism", f["evidence"])
        # Evidence must not overclaim database persistence specifically -
        # only that this is consistent with it.
        self.assertIn("not independent proof of database persistence", f["evidence"])
        mock_post.assert_called_once()
        # One POST (submit) + one GET (re-fetch) = 2 requests for this one param.
        self.assertEqual(mock_get.call_count, 1)

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_no_persistence_produces_no_finding(self, mock_post, mock_get):
        # The value is never rendered back anywhere on re-fetch - the
        # heuristic correctly produces nothing rather than guessing.
        mock_post.return_value = _resp("Thanks!", 200)
        mock_get.return_value = _resp("<html><body>Guestbook is empty.</body></html>", 200)

        recon_output = {"params": [
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        findings = xss.run_stored_xss_checks(recon_output)
        self.assertEqual(findings, [])

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_submission_failure_skips_param_without_crashing(self, mock_post, mock_get):
        mock_post.side_effect = xss.requests.exceptions.ConnectionError("boom")
        recon_output = {"params": [
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        findings = xss.run_stored_xss_checks(recon_output)  # must not raise
        self.assertEqual(findings, [])
        mock_get.assert_not_called()  # never got to the re-fetch step

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_each_param_gets_a_unique_canary(self, mock_post, mock_get):
        sent_payloads = []

        def fake_post(url, data=None, headers=None, timeout=None, allow_redirects=None, **kwargs):
            sent_payloads.append(data.get(list(data.keys())[0], ""))
            return _resp("ok", 200)

        mock_post.side_effect = fake_post
        mock_get.return_value = _resp("nothing here", 200)

        recon_output = {"params": [
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
            {"url": "https://example.com/profile", "method": "POST", "params": ["bio"]},
        ]}
        xss.run_stored_xss_checks(recon_output)

        self.assertEqual(len(sent_payloads), 2)
        canary_1 = xss._extract_canary(sent_payloads[0])
        canary_2 = xss._extract_canary(sent_payloads[1])
        self.assertNotEqual(canary_1, canary_2)

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_out_of_scope_endpoint_is_skipped(self, mock_post, mock_get):
        recon_output = {"params": [
            {"url": "https://attacker.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        findings = xss.run_stored_xss_checks(recon_output)
        self.assertEqual(findings, [])
        mock_post.assert_not_called()
        mock_get.assert_not_called()

    def test_raises_without_authorized_target(self):
        env = dict(os.environ)
        env.pop("AUTHORIZED_TARGET", None)
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                xss.run_stored_xss_checks({"params": []})

    def test_invalid_recon_output_returns_empty_list(self):
        self.assertEqual(xss.run_stored_xss_checks(12345), [])

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_respects_shared_budget_with_reflected_phase(self, mock_post, mock_get):
        # With a tiny shared budget, the reflected phase alone can exhaust
        # it, leaving nothing for the stored phase - proving the two phases
        # share ONE budget rather than each getting the full allowance.
        mock_get.return_value = _resp("nothing reflected here", 200)
        mock_post.return_value = _resp("ok", 200)

        recon_output = {"params": [
            {"url": "https://example.com/search", "method": "GET", "params": ["q"]},
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        with patch.object(xss, "MAX_REQUESTS_PER_RUN", 2):
            xss.run(recon_output, test_stored_xss=True)

        # 2 total requests allowed; reflected phase alone has 14 payloads
        # for the GET param, so it consumes the whole budget before the
        # stored phase (POST endpoint) ever gets a turn.
        mock_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
