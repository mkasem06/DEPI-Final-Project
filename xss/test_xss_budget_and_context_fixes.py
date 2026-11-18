"""
Tests for this audit pass's fixes:
  1. Request budget now counts actual HTTP attempts (including every
     redirect hop and every failed attempt), not logical calls to
     inject_payload()/_fetch_plain().
  2. _fetch_plain() now goes through the same scope-safe, no-auto-redirect
     machinery as inject_payload(), instead of a bare requests.get() that
     defaulted to following redirects with zero scope revalidation.
  3. _classify_reflection() no longer misclassifies one occurrence of a
     canary based on a DIFFERENT occurrence's position in the response.
  4. An on*/javascript: attribute whose value is much longer than our
     payload (i.e. the canary is a small fragment of something that
     already existed) is no longer confirmed as a newly-created
     event-handler/URI attribute.

Run with:  AUTHORIZED_TARGET=https://example.com python -m unittest \
             tests.test_xss_budget_and_context_fixes -v
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


class TestBudgetCountsRealHttpAttempts(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    def test_each_redirect_hop_consumes_one_budget_unit(self, mock_get):
        # 2 redirects then a final 200 = 3 real HTTP attempts for ONE
        # inject_payload() call. The budget must reflect 3, not 1.
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/hop2"}),
            _resp("", 302, {"Location": "/hop3"}),
            _resp("landed", 200),
        ]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        budget = xss._ScanBudget()
        result = xss.inject_payload(endpoint, "q", "x", budget=budget)

        self.assertIsNotNone(result)
        self.assertEqual(result.text, "landed")
        self.assertEqual(budget.request_count, 3)
        self.assertEqual(mock_get.call_count, 3)

    @patch("xss.xss.requests.get")
    def test_failed_attempt_still_consumes_budget(self, mock_get):
        mock_get.side_effect = xss.requests.exceptions.ConnectionError("boom")
        endpoint = {"url": "https://example.com/x", "method": "GET", "params": ["q"]}
        budget = xss._ScanBudget()
        result = xss.inject_payload(endpoint, "q", "x", budget=budget)

        self.assertIsNone(result)
        self.assertEqual(budget.request_count, 1)

    @patch("xss.xss.requests.get")
    def test_no_further_requests_after_budget_exhausted_mid_redirect_chain(self, mock_get):
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/hop2"}),
            _resp("", 302, {"Location": "/hop3"}),
            _resp("would land here", 200),
        ]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        budget = xss._ScanBudget()
        budget.request_count = 1  # pretend 1 unit was already used elsewhere this scan

        with patch.object(xss, "MAX_REQUESTS_PER_RUN", 2):
            result = xss.inject_payload(endpoint, "q", "x", budget=budget)

        # Only 1 more attempt was allowed (budget: 1 used + 1 allowed = 2
        # total) before the chain had to stop mid-way.
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(budget.request_count, 2)

    @patch("xss.xss.requests.get")
    def test_standalone_call_with_no_budget_argument_still_works(self, mock_get):
        # inject_payload(endpoint, param, payload) - exactly 3 positional
        # args, no budget - must still work (preserves the existing public
        # signature); internally it gets its own throwaway budget.
        mock_get.return_value = _resp("ok", 200)
        endpoint = {"url": "https://example.com/x", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNotNone(result)

    @patch("xss.xss.requests.get")
    @patch("xss.xss.requests.post")
    def test_reflected_and_stored_phases_draw_from_one_shared_budget_across_redirects(self, mock_post, mock_get):
        # The reflected phase's single GET param redirects twice (3 real
        # requests); with a budget of 3, nothing should be left for the
        # stored phase's POST endpoint.
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/hop2"}),
            _resp("", 302, {"Location": "/hop3"}),
            _resp("nothing reflected", 200),
        ]
        recon_output = {"params": [
            {"url": "https://example.com/search", "method": "GET", "params": ["q"]},
            {"url": "https://example.com/guestbook", "method": "POST", "params": ["comment"]},
        ]}
        with patch.object(xss, "MAX_REQUESTS_PER_RUN", 3):
            xss.run(recon_output, test_stored_xss=True)

        mock_post.assert_not_called()


class TestFetchPlainScopeSafety(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    def test_fetch_plain_does_not_auto_follow_redirects_via_requests_default(self, mock_get):
        # If _fetch_plain used a bare requests.get(), the mock would only
        # ever be called once (requests itself would silently follow the
        # redirect internally, invisibly to us). Going through the manual
        # scope-safe redirect loop means WE see and validate each hop
        # ourselves - proven here by observing 2 separate calls for 2 hops.
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/final"}),
            _resp("final content", 200),
        ]
        result = xss._fetch_plain("https://example.com/display")
        self.assertIsNotNone(result)
        self.assertEqual(result.text, "final content")
        self.assertEqual(mock_get.call_count, 2)
        # allow_redirects=False must have been passed - otherwise requests
        # itself would resolve the redirect before we ever see it.
        _, kwargs = mock_get.call_args_list[0]
        self.assertEqual(kwargs.get("allow_redirects"), False)

    @patch("xss.xss.requests.get")
    def test_fetch_plain_blocks_out_of_scope_redirect(self, mock_get):
        mock_get.return_value = _resp("", 302, {"Location": "https://attacker.com/steal"})
        result = xss._fetch_plain("https://example.com/display")
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 1)  # never followed the bad redirect

    @patch("xss.xss.requests.get")
    def test_fetch_plain_rejects_out_of_scope_url_outright(self, mock_get):
        result = xss._fetch_plain("https://attacker.com/display")
        self.assertIsNone(result)
        mock_get.assert_not_called()

    @patch("xss.xss.requests.get")
    def test_fetch_plain_sends_no_injected_parameters(self, mock_get):
        mock_get.return_value = _resp("ok", 200)
        xss._fetch_plain("https://example.com/display")
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs.get("params"), {})

    @patch("xss.xss.requests.get")
    def test_fetch_plain_never_disables_tls_verification(self, mock_get):
        mock_get.return_value = _resp("ok", 200)
        xss._fetch_plain("https://example.com/display")
        _, kwargs = mock_get.call_args
        self.assertNotIn("verify", kwargs)

class TestMultiHopRedirects(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    def test_multiple_in_scope_hops_all_followed(self, mock_get):
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/hop2"}),
            _resp("", 302, {"Location": "/hop3"}),
            _resp("", 302, {"Location": "/hop4"}),
            _resp("finally", 200),
        ]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNotNone(result)
        self.assertEqual(result.text, "finally")
        self.assertEqual(mock_get.call_count, 4)

    @patch("xss.xss.requests.get")
    def test_chain_that_eventually_leaves_scope_is_blocked(self, mock_get):
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/hop2"}),          # in scope
            _resp("", 302, {"Location": "https://attacker.com/evil"}),  # leaves scope
            _resp("should never be reached", 200),
        ]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 2)  # stopped before the 3rd (bad) hop

    @patch("xss.xss.requests.get")
    def test_relative_location_header_resolved_against_current_hop(self, mock_get):
        # A relative Location on hop 2 must resolve against hop 2's own
        # URL, not the original request URL.
        mock_get.side_effect = [
            _resp("", 302, {"Location": "/sub/hop2"}, ),
            _resp("", 302, {"Location": "hop3"}),  # relative to /sub/hop2 -> /sub/hop3
            _resp("done", 200),
        ]
        endpoint = {"url": "https://example.com/start", "method": "GET", "params": ["q"]}
        result = xss.inject_payload(endpoint, "q", "x")
        self.assertIsNotNone(result)
        third_call_url = mock_get.call_args_list[2][0][0]
        self.assertEqual(third_call_url, "https://example.com/sub/hop3")


class TestCrossOccurrenceClassification(unittest.TestCase):
    """Regression tests for the bug where classification of one occurrence
    of the canary could be based on a DIFFERENT occurrence's position."""

    def test_unsafe_occurrence_found_even_when_a_safe_occurrence_comes_first(self):
        canary = "xss" + "cafebabe"
        payload = f"<3 {canary}"
        body = (
            f"<p>Log: user searched for &lt;3 {canary} (escaped, harmless)&gt;</p>"
            f"<p>Comment: {payload}</p>"  # genuinely unescaped '<' here
        )
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["classification"], "unescaped_angle_bracket_in_text")

    def test_unsafe_occurrence_found_even_when_a_safe_occurrence_comes_after(self):
        canary = "xss" + "babecafe"
        payload = f"<3 {canary}"
        body = (
            f"<p>Comment: {payload}</p>"  # genuinely unescaped '<' here, FIRST
            f"<p>Log: user searched for &lt;3 {canary} (escaped, harmless)&gt;</p>"
        )
        result = xss.check_reflection(body, payload)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["classification"], "unescaped_angle_bracket_in_text")

    def test_all_occurrences_safely_escaped_is_not_a_finding(self):
        canary = "xss" + "0ff1ce00"
        payload = f"<3 {canary}"
        body = (
            f"<p>&lt;3 {canary} first&gt;</p>"
            f"<p>&lt;3 {canary} second&gt;</p>"
        )
        result = xss.check_reflection(body, payload)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["classification"], "escaped_text")

    def test_script_context_takes_priority_regardless_of_other_safe_occurrences(self):
        canary = "xss" + "1a2b3c4d"
        payload = f"<script>alert('{canary}')</script>"
        body = (
            f"<p>&lt;script&gt;alert('{canary}') harmless mention&gt;</p>"
            f"<script>alert('{canary}')</script>"
        )
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "script_context")
        self.assertEqual(result["confidence"], "confirmed")


class TestAttributeBreakoutPrecision(unittest.TestCase):
    """Regression tests for the fix distinguishing a newly-created on*/
    javascript: attribute from the canary being a small fragment inside a
    much longer, likely pre-existing attribute value."""

    def test_short_value_matching_payload_is_confirmed(self):
        canary = "xss" + "deadbeef"
        payload = f"\" onmouseover=alert('{canary}') x=\""
        body = f'<input type="text" value="{payload}">'
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "event_handler_attribute")
        self.assertEqual(result["confidence"], "confirmed")

    def test_canary_fragment_in_long_preexisting_onclick_is_not_confirmed(self):
        canary = "xss" + "feedface"
        payload = f"' onmouseover=alert('{canary}') x='"
        # The app's OWN onclick attribute, unrelated to our breakout
        # attempt, with our (harmless, inert) data interpolated into one
        # of its arguments - the quote breakout did NOT succeed.
        body = (
            '<button onclick="logEvent(\'comment_posted\', \'author:anon, text:'
            + payload + ', length:48\')">Post</button>'
        )
        result = xss.check_reflection(body, payload)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["classification"], "attribute_value_context")

    def test_canary_fragment_in_long_preexisting_js_uri_is_not_confirmed(self):
        canary = "xss" + "0a0b0c0d"
        payload = f"javascript:alert('{canary}')"
        body = (
            '<a href="javascript:trackAndNavigate(\'referrer=search&query='
            + payload + '&campaign=none\')">link</a>'
        )
        result = xss.check_reflection(body, payload)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["classification"], "attribute_value_context")

    def test_short_js_uri_matching_payload_is_confirmed(self):
        canary = "xss" + "11223344"
        payload = f"javascript:alert('{canary}')"
        body = f'<a href="{payload}">link</a>'
        result = xss.check_reflection(body, payload)
        self.assertEqual(result["classification"], "uri_scheme_attribute")
        self.assertEqual(result["confidence"], "confirmed")


class TestParamDeclarationValidation(unittest.TestCase):
    """Section 6: parameter names should be validated against the
    endpoint's declared params 'when applicable' - logged, not blocked
    (testing an undeclared/hidden param is a legitimate deliberate use)."""

    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    @patch("xss.xss.requests.get")
    def test_undeclared_param_is_still_sent_but_logged(self, mock_get):
        mock_get.return_value = _resp("ok", 200)
        endpoint = {"url": "https://example.com/x", "method": "GET", "params": ["q", "lang"]}
        with self.assertLogs("xss.xss", level="WARNING") as log_ctx:
            result = xss.inject_payload(endpoint, "hidden_field", "payload")
        self.assertIsNotNone(result)  # not blocked
        self.assertTrue(any("not in endpoint" in msg and "declared params" in msg for msg in log_ctx.output))
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"]["hidden_field"], "payload")

    @patch("xss.xss.requests.get")
    def test_declared_param_produces_no_warning(self, mock_get):
        mock_get.return_value = _resp("ok", 200)
        endpoint = {"url": "https://example.com/x", "method": "GET", "params": ["q", "lang"]}
        # No assertLogs here - just confirm it runs cleanly and sends correctly.
        result = xss.inject_payload(endpoint, "q", "payload")
        self.assertIsNotNone(result)
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"]["q"], "payload")
        self.assertEqual(kwargs["params"]["lang"], xss.DEFAULT_VALUE)


if __name__ == "__main__":
    unittest.main()
