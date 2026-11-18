import os
import sys
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from bs4 import BeautifulSoup
from requests.adapters import BaseAdapter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["AUTHORIZED_TARGET"] = "https://example.com"

import recon.recon as recon
import xss.xss as xss


class FormSessionAdapter(BaseAdapter):
    def __init__(self):
        self.submitted_request = None
        self.sent_requests = []

    def send(self, request, **kwargs):
        self.sent_requests.append(request)
        response = requests.Response()
        response.url = request.url
        response.request = request

        if request.method == "GET" and request.path_url.startswith("/form"):
            response.status_code = 200
            response.headers["Set-Cookie"] = "sessionid=form-session; Path=/"
            cookie_headers = Message()
            cookie_headers.add_header("Set-Cookie", "sessionid=form-session; Path=/")
            response.raw = SimpleNamespace(
                _original_response=SimpleNamespace(msg=cookie_headers),
                close=lambda: None,
            )
            response._content = (
                b'<form method="POST" action="/submit">'
                b'<input type="hidden" name="__RequestVerificationToken" value="fresh-token">'
                b'<input name="search" value="remembered">'
                b'<textarea name="body">starter text</textarea>'
                b'<input type="checkbox" name="include" value="yes" checked>'
                b'<input type="checkbox" name="skip" value="no">'
                b'</form>'
            )
        elif request.method == "POST" and request.path_url == "/submit":
            self.submitted_request = request
            response.status_code = 200
            response._content = b"ok"
        else:
            response.status_code = 404
            response._content = b""

        return response

    def close(self):
        pass


class TestFormSubmission(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": "https://example.com"})
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()

    def test_recon_records_form_source_and_position(self):
        soup = BeautifulSoup(
            '<form><input name="first"></form>'
            '<form method="post" action="/submit"><input name="body"></form>',
            "html.parser",
        )

        endpoints = recon.extract_params(soup, "https://example.com/form")

        self.assertEqual(endpoints[1]["page_url"], "https://example.com/form")
        self.assertEqual(endpoints[1]["form_index"], 1)

    def test_recon_dedup_contract_keeps_full_forms_for_xss(self):
        forms = [
            {
                "url": "https://example.com/submit",
                "method": "POST",
                "params": ["body"],
                "page_url": page_url,
                "form_index": 0,
            }
            for page_url in (
                "https://example.com/first",
                "https://example.com/second",
            )
        ]
        query = {
            "url": "https://example.com/search",
            "method": "GET",
            "params": ["q"],
        }

        recon_params = recon._remove_duplicate_params([query, *forms])

        self.assertEqual(len(recon_params), 2)
        self.assertEqual(xss._parse_endpoints({
            "params": recon_params,
            "forms": forms,
        }), [query, *forms])

    def test_form_defaults_csrf_token_and_session_cookie_are_preserved(self):
        adapter = FormSessionAdapter()
        session = requests.Session()
        session.mount("https://example.com/", adapter)
        endpoint = {
            "url": "https://example.com/submit",
            "method": "POST",
            "params": ["__RequestVerificationToken", "search", "body", "include", "skip"],
            "page_url": "https://example.com/form",
            "form_index": 0,
        }
        budget = xss._ScanBudget()

        try:
            response = xss.inject_payload(endpoint, "body", "test-payload", budget=budget, session=session)
        finally:
            session.close()

        self.assertIsNotNone(response)
        self.assertEqual(len(adapter.sent_requests), 2)
        self.assertEqual(budget.request_count, 2)
        self.assertIsNotNone(adapter.submitted_request)
        body = adapter.submitted_request.body
        if isinstance(body, bytes):
            body = body.decode("ascii")
        self.assertIn("__RequestVerificationToken=fresh-token", body)
        self.assertIn("search=remembered", body)
        self.assertIn("body=test-payload", body)
        self.assertIn("include=yes", body)
        self.assertNotIn("skip=no", body)
        self.assertIn("sessionid=form-session", adapter.submitted_request.headers["Cookie"])

    def test_csrf_fields_are_not_selected_as_xss_payload_parameters(self):
        endpoint = {
            "url": "https://example.com/submit",
            "method": "POST",
            "params": ["search", "__RequestVerificationToken"],
            "page_url": "https://example.com/form",
            "form_index": 0,
        }
        payload = {"payload": "probe", "context": "html_text", "description": "test"}

        with patch.object(xss, "get_payload_list", return_value=[payload]), patch.object(
            xss, "inject_payload", return_value=None
        ) as inject:
            xss._run_reflected_phase([endpoint], xss._ScanBudget())

        inject.assert_called_once()
        self.assertEqual(inject.call_args.args[1], "search")

    def test_changed_form_action_is_not_submitted(self):
        session = MagicMock()
        page = MagicMock()
        page.status_code = 200
        page.url = "https://example.com/form"
        page.text = '<form method="POST" action="https://other.example/submit"><input name="body"></form>'
        session.get.return_value = page
        endpoint = {
            "url": "https://example.com/submit",
            "method": "POST",
            "params": ["body"],
            "page_url": "https://example.com/form",
            "form_index": 0,
        }

        result = xss.inject_payload(endpoint, "body", "payload", session=session)

        self.assertIsNone(result)
        session.post.assert_not_called()

    def test_same_action_and_parameter_on_distinct_forms_are_both_tested(self):
        endpoints = [
            {
                "url": "https://example.com/submit",
                "method": "POST",
                "params": ["search"],
                "page_url": "https://example.com/page",
                "form_index": form_index,
            }
            for form_index in (0, 1)
        ]
        response = MagicMock()
        response.status_code = 200
        response.text = "<html></html>"

        with patch.object(
            xss,
            "get_payload_list",
            return_value=[{
                "payload": "<script>xssdeadbeef</script>",
                "context": "html_text",
                "description": "test",
            }],
        ), patch.object(xss, "inject_payload", return_value=response) as inject:
            xss._run_reflected_phase(endpoints, xss._ScanBudget())

        self.assertEqual(inject.call_count, 2)


if __name__ == "__main__":
    unittest.main()
