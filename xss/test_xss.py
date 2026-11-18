"""
Unit tests for xss/xss.py.

Run with:  python -m unittest tests.test_xss -v        (from repo root)
        or: pytest tests/test_xss.py -v                 (if pytest is installed)

All HTTP is mocked (unittest.mock) - no traffic is sent anywhere, per the
project's testing rules.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["AUTHORIZED_TARGET"] = "https://example.com"

import importlib
import xss.xss as xss
importlib.reload(xss)  # pick up AUTHORIZED_TARGET set above, and get a fresh CANARY


def _resp(text, status_code=200, headers=None):
    m = MagicMock()
    m.text = text
    m.status_code = status_code
    m.headers = headers or {}
    return m


class TestGetPayloadList(unittest.TestCase):
    def test_returns_reasonable_count(self):
        payloads = xss.get_payload_list()
        self.assertGreaterEqual(len(payloads), 10)
        self.assertLessEqual(len(payloads), 15)

    def test_every_entry_has_required_keys_and_unique_canary(self):
        payloads = xss.get_payload_list()
        for entry in payloads:
            self.assertIn("payload", entry)
            self.assertIn("context", entry)
            self.assertIn("description", entry)
            self.assertIn(xss.CANARY, entry["payload"])

    def test_contexts_are_from_known_set(self):
        known = {"html_text", "html_attribute", "uri_scheme", "filter_bypass"}
        for entry in xss.get_payload_list():
            self.assertIn(entry["context"], known)

    def test_payloads_are_not_destructive(self):
        # Sanity check: nothing resembling a destructive action (file deletion,
        # OS command execution) should be in the payload set.
        forbidden_markers = ["rm -rf", "DROP TABLE", "os.system", "subprocess"]
        for entry in xss.get_payload_list():
            for marker in forbidden_markers:
                self.assertNotIn(marker, entry["payload"])


class TestScope(unittest.TestCase):
    def test_exact_match_in_scope(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertTrue(xss._in_scope("https://example.com/login"))

    def test_different_host_out_of_scope(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertFalse(xss._in_scope("https://attacker.com/login"))

    def test_different_scheme_out_of_scope(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertFalse(xss._in_scope("http://example.com/login"))

    def test_default_port_equivalence(self):
        # https://example.com (implicit :443) must match an explicit :443,
        # and must NOT match a non-standard port.
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertTrue(xss._in_scope("https://example.com:443/login"))
            self.assertFalse(xss._in_scope("https://example.com:8443/login"))

    def test_embedded_credentials_rejected(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertFalse(xss._in_scope("https://user:pass@example.com/login"))

    def test_malformed_authorized_target_fails_closed(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "not-a-url"}):
            self.assertFalse(xss._in_scope("https://example.com/login"))

    def test_missing_authorized_target_fails_closed(self):
        env = dict(os.environ)
        env.pop("AUTHORIZED_TARGET", None)
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(xss._in_scope("https://example.com/login"))

    def test_unsupported_scheme_out_of_scope(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertFalse(xss._in_scope("ftp://example.com/login"))


class TestInjectPayload(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    def test_malformed_endpoint_not_dict(self):
        self.assertIsNone(xss.inject_payload(["not", "a", "dict"], "q", "x"))

    def test_endpoint_missing_url(self):
        self.assertIsNone(xss.inject_payload({"method": "GET", "params": ["q"]}, "q", "x"))

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_unsupported_method_sends_no_request(self, mock_post, mock_get):
        endpoint = {"url": "https://example.com/x", "method": "PUT", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "payload")
        self.assertIsNone(result)
        mock_get.assert_not_called()
        mock_post.assert_not_called()

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_out_of_scope_sends_no_request(self, mock_post, mock_get):
        endpoint = {"url": "https://attacker.com/x", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "payload")
        self.assertIsNone(result)
        mock_get.assert_not_called()
        mock_post.assert_not_called()

    @patch("xss.xss.requests.get")
    def test_get_request_fills_other_params_with_default(self, mock_get):
        mock_get.return_value = _resp("ok", 200)
        endpoint = {"url": "https://example.com/search", "method": "GET", "params": ["q", "lang"]}
        xss.inject_payload(endpoint, "q", "PAYLOAD")
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"]["q"], "PAYLOAD")
        self.assertEqual(kwargs["params"]["lang"], xss.DEFAULT_VALUE)
        self.assertNotIn("verify", kwargs)  # never explicitly disabled

    @patch("xss.xss.requests.post")
    def test_post_request_uses_data(self, mock_post):
        mock_post.return_value = _resp("ok", 200)
        endpoint = {"url": "https://example.com/comment", "method": "POST", "params": ["body"]}
        xss.inject_payload(endpoint, "body", "PAYLOAD")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["data"]["body"], "PAYLOAD")

    @patch("xss.xss.requests.get")
    def test_network_exception_returns_none(self, mock_get):
        mock_get.side_effect = xss.requests.exceptions.ConnectionError("boom")
        endpoint = {"url": "https://example.com/x", "method": "GET", "params": ["q"]}
        self.assertIsNone(xss.inject_payload(endpoint, "q", "x"))

    @patch("xss.xss.requests.get")
    def test_in_scope_redirect_is_followed(self, mock_get):
        redirect = _resp("", 302, {"Location": "/final"})
        final = _resp("landed", 200)
        mock_get.side_effect = [redirect, final]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNotNone(result)
        self.assertEqual(result.text, "landed")
        self.assertEqual(mock_get.call_count, 2)

    @patch("xss.xss.requests.get")
    def test_out_of_scope_redirect_is_blocked(self, mock_get):
        redirect = _resp("", 302, {"Location": "https://attacker.com/evil"})
        mock_get.return_value = redirect
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 1)  # never followed the bad redirect

    @patch("xss.xss.requests.get")
    def test_too_many_redirects_gives_up(self, mock_get):
        mock_get.return_value = _resp("", 302, {"Location": "/loop"})
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, xss.MAX_REDIRECTS + 1)


class TestCheckReflection(unittest.TestCase):
    def setUp(self):
        self.canary = xss.CANARY

    def test_not_reflected(self):
        result = xss.check_reflection("nothing here", "<script>alert(1)</script>")
        self.assertFalse(result["reflected"])
        self.assertFalse(result["vulnerable"])
        self.assertIsNone(result["confidence"])

    def test_fully_escaped_script_is_not_a_finding(self):
        import html as html_mod
        payload = f"<script>alert('{self.canary}')</script>"
        body = f"<div>results for: {html_mod.escape(payload)}</div>"
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["reflected"])
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["classification"], "escaped_text")

    def test_raw_script_tag_is_confirmed(self):
        payload = f"<script>alert('{self.canary}')</script>"
        body = f"<html><body><div>results for: {payload}</div></body></html>"
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "confirmed")
        self.assertEqual(result["classification"], "script_context")

    def test_event_handler_breakout_is_confirmed(self):
        payload = f"\" onmouseover=alert('{self.canary}') x=\""
        body = f'<input type="text" value="{payload}">'
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "confirmed")
        self.assertEqual(result["classification"], "event_handler_attribute")

    def test_uri_scheme_breakout_is_confirmed(self):
        payload = f"javascript:alert('{self.canary}')"
        body = f'<a href="{payload}">link</a>'
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "confirmed")
        self.assertEqual(result["classification"], "uri_scheme_attribute")

    def test_attribute_value_no_breakout_is_not_a_finding(self):
        # The quote char never breaks out (app escaped the double quote);
        # bs4 sees one ordinary attribute value, not a new attribute.
        payload = "\" onmouseover=alert('x')"
        body = f'<input type="text" value="&quot; onmouseover=alert(&#x27;{self.canary}&#x27;)">'
        result = xss.check_reflection(body, f"\" onmouseover=alert('{self.canary}')")
        self.assertFalse(result["vulnerable"])
        self.assertIn(result["classification"], ("attribute_value_context", "escaped_text"))

    def test_raw_angle_bracket_in_text_is_suspected_not_confirmed(self):
        payload = f"<3 {self.canary}"
        body = f"<p>rating: {payload}</p>"
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["confidence"], "suspected")
        self.assertEqual(result["classification"], "unescaped_angle_bracket_in_text")

    def test_comment_reflection_is_suspected_not_confirmed(self):
        payload = f"{self.canary}"
        body = f"<p>hello <!-- {payload} --></p>"
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["reflected"])
        self.assertNotEqual(result["confidence"], "confirmed")

    def test_json_reflection_is_not_a_finding(self):
        # A plain JSON API response reflecting the canary with no HTML at
        # all must never be flagged - there is nothing here a browser would
        # execute as markup.
        payload = f"{self.canary}"
        body = '{"error": "' + payload + ' not found"}'
        result = xss.check_reflection(body, payload)
        self.assertFalse(result["vulnerable"])

    def test_parse_failure_is_suspected_inconclusive(self):
        payload = f"<script>alert('{self.canary}')</script>"
        body = f"whatever {self.canary} whatever"
        with patch("xss.xss.BeautifulSoup", side_effect=Exception("boom")):
            result = xss.check_reflection(body, payload)
        self.assertTrue(result["reflected"])
        self.assertEqual(result["confidence"], "suspected")
        self.assertEqual(result["classification"], "inconclusive")

    def test_exact_string_match_alone_is_not_treated_as_proof(self):
        # Regression test for the original bug: a verbatim substring match
        # used to be sufficient. Now, a payload reflected but fully
        # neutralized (e.g. defanged by surrounding escaped text so bs4
        # still parses it as escaped) must not be "confirmed" just because
        # str.find() would have matched it.
        import html as html_mod
        payload = f"<script>alert('{self.canary}')</script>"
        # The exact payload string is technically a substring of the escaped
        # body text's *decoded* form, but the raw source is fully encoded.
        body = html_mod.escape(payload)
        result = xss.check_reflection(body, payload)
        self.assertFalse(result["vulnerable"])


class TestRun(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    def test_raises_without_authorized_target(self):
        env = dict(os.environ)
        env.pop("AUTHORIZED_TARGET", None)
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                xss.run({"params": []})

    def test_invalid_recon_output_type_returns_empty_list(self):
        self.assertEqual(xss.run(12345), [])
        self.assertEqual(xss.run("not valid"), [])

    def test_empty_params_returns_empty_list(self):
        self.assertEqual(xss.run({"params": []}), [])

    def test_malformed_endpoint_entries_are_skipped(self):
        recon_output = {"params": [
            "not a dict",
            {"method": "GET", "params": ["q"]},  # missing url
            {"url": "https://example.com/x", "method": "GET", "params": "not-a-list"},
        ]}
        self.assertEqual(xss.run(recon_output), [])  # nothing crashes, nothing scanned

    @patch("xss.xss.inject_payload")
    def test_out_of_scope_endpoint_is_never_injected(self, mock_inject):
        recon_output = {"params": [
            {"url": "https://attacker.com/x", "method": "GET", "params": ["q"]},
        ]}
        xss.run(recon_output)
        mock_inject.assert_not_called()

    @patch("xss.xss.inject_payload")
    def test_duplicate_param_entries_are_tested_once(self, mock_inject):
        mock_inject.return_value = _resp("nothing reflected")
        recon_output = {"params": [
            {"url": "https://example.com/x", "method": "GET", "params": ["q"]},
            {"url": "https://example.com/x", "method": "GET", "params": ["q"]},  # duplicate
        ]}
        xss.run(recon_output)
        payload_count = len(xss.get_payload_list())
        self.assertEqual(mock_inject.call_count, payload_count)  # not 2x

    @patch("xss.xss.inject_payload")
    def test_request_failure_does_not_crash_scan(self, mock_inject):
        mock_inject.side_effect = Exception("network exploded")
        recon_output = {"params": [
            {"url": "https://example.com/x", "method": "GET", "params": ["q"]},
        ]}
        result = xss.run(recon_output)  # must not raise
        self.assertEqual(result, [])

    @patch("xss.xss.inject_payload")
    def test_finding_matches_exact_shared_schema(self, mock_inject):
        payload = f"<script>alert('{xss.CANARY}')</script>"
        mock_inject.return_value = _resp(f"<div>{payload}</div>")
        recon_output = {"params": [
            {"url": "https://example.com/search", "method": "GET", "params": ["q"]},
        ]}
        findings = xss.run(recon_output)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding.keys()),
                          {"module", "target", "finding", "severity", "evidence", "confidence", "timestamp"})
        self.assertEqual(finding["module"], "xss")
        self.assertIn(finding["severity"], ("low", "medium", "high", "critical"))
        self.assertIn(finding["confidence"], ("confirmed", "suspected"))
        self.assertEqual(finding["confidence"], "confirmed")

    @patch("xss.xss.inject_payload")
    def test_stops_at_first_confirmed_payload_per_param(self, mock_inject):
        payload_entries = xss.get_payload_list()
        # First payload in the list reflects unescaped; the rest should
        # never even be sent for this param.
        first_payload = payload_entries[0]["payload"]
        mock_inject.return_value = _resp(f"<div>{first_payload}</div>")
        recon_output = {"params": [
            {"url": "https://example.com/search", "method": "GET", "params": ["q"]},
        ]}
        xss.run(recon_output)
        self.assertEqual(mock_inject.call_count, 1)

    @patch("xss.xss.requests.get")
    def test_respects_max_requests_per_run(self, mock_get):
        # Mocks at the actual HTTP layer (requests.get), not inject_payload
        # itself: budget accounting lives inside
        # _send_with_scope_safe_redirects now (one unit per real HTTP
        # attempt, including redirect hops - see that function's docstring
        # for why), so a test of the budget has to go through that real
        # code path rather than mocking it out at a higher level.
        mock_get.return_value = _resp("nothing reflected")
        recon_output = {"params": [
            {"url": "https://example.com/x", "method": "GET", "params": ["a", "b", "c", "d", "e"]},
        ]}
        with patch.object(xss, "MAX_REQUESTS_PER_RUN", 3):
            xss.run(recon_output)
        self.assertEqual(mock_get.call_count, 3)


if __name__ == "__main__":
    unittest.main()
