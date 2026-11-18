"""
Regression tests for the three defects found and fixed in the final
delivery audit pass:

  1. _classify_reflection() returned as soon as it found the FIRST
     attribute containing the canary, even if it was harmless - hiding a
     genuinely dangerous occurrence in a LATER attribute/tag.
  2. _send_with_scope_safe_redirects() converted a POST to GET on a
     301/302/303 redirect (correct) but kept sending the original POST
     body as GET query parameters on the follow-up request (incorrect -
     a real browser discards the body in this case).
  3. _in_scope()/_effective_port() crashed with an unhandled ValueError
     (instead of failing closed) on a malformed explicit port - either on
     the requested URL or on AUTHORIZED_TARGET itself.

Run with:  AUTHORIZED_TARGET=https://example.com python -m unittest \
             tests.test_xss_delivery_audit_fixes -v
All HTTP is mocked.
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


def _attr_breakout_payload(canary):
    """A double-quote breakout payload creating a new onmouseover attribute."""
    return f"\" onmouseover=alert('{canary}') x=\""


class TestAttributeOccurrencePriority(unittest.TestCase):
    """A harmless attribute occurrence must never hide a dangerous one
    found elsewhere in the same response, in either document order."""

    def test_harmless_occurrence_first_does_not_hide_dangerous_second(self):
        canary = "xss" + "d00dfeed"
        payload = _attr_breakout_payload(canary)
        body = (
            f'<div data-log="user comment preview: {canary} truncated at 50 chars total length here"></div>'
            f'<input type="text" value="{payload}">'
        )
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "event_handler_attribute")
        self.assertEqual(result["confidence"], "confirmed")
        self.assertTrue(result["vulnerable"])

    def test_dangerous_occurrence_first_harmless_second_still_confirmed(self):
        canary = "xss" + "feedd00d"
        payload = _attr_breakout_payload(canary)
        body = (
            f'<input type="text" value="{payload}">'
            f'<div data-log="user comment preview: {canary} truncated at 50 chars total length here"></div>'
        )
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "event_handler_attribute")
        self.assertEqual(result["confidence"], "confirmed")

    def test_only_harmless_occurrences_anywhere_is_not_a_finding(self):
        # No text-node occurrence at all, and the only attribute occurrence
        # is harmless - must correctly report attribute_value_context, not
        # fall through to the generic "inconclusive" catch-all.
        canary = "xss" + "cafed00d"
        payload = _attr_breakout_payload(canary)
        body = f'<div data-log="user comment preview: {canary} truncated at 50 chars total length here"></div>'
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "attribute_value_context")
        self.assertFalse(result["vulnerable"])

    def test_two_harmless_occurrences_in_same_tag_different_attributes(self):
        canary = "xss" + "0a0b0c0d"
        payload = _attr_breakout_payload(canary)
        body = f'<div data-a="{canary} padded out to a longer harmless value here" data-b="also {canary} harmless and long">x</div>'
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "attribute_value_context")
        self.assertFalse(result["vulnerable"])


class TestRedirectBodyNotLeakedToQueryParams(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_303_redirect_does_not_resend_post_body_as_get_params(self, mock_post, mock_get):
        mock_post.return_value = _resp("", 303, {"Location": "/thanks"})
        mock_get.return_value = _resp("Thanks!", 200)

        endpoint = {"url": "https://example.com/submit", "method": "POST", "params": ["comment"]}
        result = xss.inject_payload(endpoint, "comment", "sensitive-payload-value")

        self.assertIsNotNone(result)
        _, get_kwargs = mock_get.call_args
        self.assertEqual(get_kwargs["params"], {})  # body discarded, not resurrected as query params

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_302_redirect_also_discards_post_body(self, mock_post, mock_get):
        mock_post.return_value = _resp("", 302, {"Location": "/thanks"})
        mock_get.return_value = _resp("Thanks!", 200)

        endpoint = {"url": "https://example.com/submit", "method": "POST", "params": ["comment"]}
        xss.inject_payload(endpoint, "comment", "sensitive-payload-value")

        _, get_kwargs = mock_get.call_args
        self.assertEqual(get_kwargs["params"], {})

    @patch("xss.xss.requests.post")
    def test_307_redirect_preserves_post_body(self, mock_post):
        # 307 (and 308) must behave differently from 301/302/303: same
        # method AND same body on the follow-up request.
        mock_post.side_effect = [
            _resp("", 307, {"Location": "/retry-same-method"}),
            _resp("ok", 200),
        ]
        endpoint = {"url": "https://example.com/submit", "method": "POST", "params": ["comment"]}
        result = xss.inject_payload(endpoint, "comment", "payload-value")

        self.assertIsNotNone(result)
        self.assertEqual(mock_post.call_count, 2)
        second_call_kwargs = mock_post.call_args_list[1].kwargs
        self.assertEqual(second_call_kwargs["data"], {"comment": "payload-value"})

    @patch("xss.xss.requests.post")
    def test_308_redirect_preserves_post_body(self, mock_post):
        mock_post.side_effect = [
            _resp("", 308, {"Location": "/retry-same-method"}),
            _resp("ok", 200),
        ]
        endpoint = {"url": "https://example.com/submit", "method": "POST", "params": ["comment"]}
        xss.inject_payload(endpoint, "comment", "payload-value")

        second_call_kwargs = mock_post.call_args_list[1].kwargs
        self.assertEqual(second_call_kwargs["data"], {"comment": "payload-value"})
        self.assertEqual(mock_post.call_count, 2)  # method stayed POST, not switched to GET

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_301_redirect_switches_to_get_and_discards_body(self, mock_post, mock_get):
        mock_post.return_value = _resp("", 301, {"Location": "/moved"})
        mock_get.return_value = _resp("moved content", 200)

        endpoint = {"url": "https://example.com/submit", "method": "POST", "params": ["comment"]}
        xss.inject_payload(endpoint, "comment", "payload-value")

        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args.kwargs["params"], {})


class TestMalformedPortFailsClosed(unittest.TestCase):
    def test_out_of_range_explicit_port_on_requested_url_fails_closed(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            result = xss._in_scope("https://example.com:999999/path")
        self.assertFalse(result)

    def test_non_numeric_explicit_port_on_requested_url_fails_closed(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            result = xss._in_scope("https://example.com:abc/path")
        self.assertFalse(result)

    def test_malformed_authorized_target_port_fails_closed(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com:999999"}):
            result = xss._in_scope("https://example.com/path")
        self.assertFalse(result)

    def test_both_sides_malformed_in_the_same_way_still_fails_closed(self):
        # Must NOT accidentally evaluate True just because both ports
        # independently come back as None (the "can't determine" sentinel).
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com:999999"}):
            result = xss._in_scope("https://example.com:999999/path")
        self.assertFalse(result)

    def test_valid_port_still_works_correctly_after_the_fix(self):
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            self.assertTrue(xss._in_scope("https://example.com:443/path"))
            self.assertFalse(xss._in_scope("https://example.com:8443/path"))

    def test_effective_port_returns_none_for_malformed_port(self):
        from urllib.parse import urlsplit
        parsed = urlsplit("https://example.com:999999/path")
        self.assertIsNone(xss._effective_port(parsed))

    @patch("xss.xss.requests.get")
    def test_malformed_redirect_location_port_does_not_crash_the_scan(self, mock_get):
        # Simulates a target sending back a redirect to a URL with a
        # malformed port in its Location header - this must be blocked,
        # not crash inject_payload().
        with patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"}):
            mock_get.return_value = _resp("", 302, {"Location": "https://example.com:999999/evil"})
            endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
            result = xss.inject_payload(endpoint, "q", "x")  # must not raise
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
