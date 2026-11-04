import os
import re
import sys
import threading
import unittest
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from unittest.mock import patch

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import main
from recon import recon
from xss import xss


class ControlledXssHandler(BaseHTTPRequestHandler):
    escape_all = False
    fail_payload_requests = False
    fail_baseline_requests = False
    validate_contact_fields = False
    single_form = False
    submissions = []
    csrf_failures = 0
    request_observations = []
    http_requests = []
    csrf_token = "fresh-antiforgery-token"
    csrf_cookie = "antiforgery-cookie-secret"

    def log_message(self, _format, *_args):
        pass

    def _respond(self, body, status=200, headers=None):
        content = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        self.__class__.http_requests.append(("GET", self.path))
        body = (
            '<form method="post" action="/reflect">'
            f'<input type="hidden" name="__RequestVerificationToken" value="{self.csrf_token}">'
            '<input name="Name" value="">'
            '<input type="email" name="Email" value="">'
            '<textarea name="Message"></textarea>'
            '</form>'
        )
        if not self.__class__.single_form:
            body += (
                '<form method="post" action="/escaped">'
                f'<input type="hidden" name="__RequestVerificationToken" value="{self.csrf_token}">'
                '<input name="subject" value="">'
                '<textarea name="comment"></textarea>'
                '</form>'
            )
        self._respond(
            body,
            headers={"Set-Cookie": f".AspNetCore.Antiforgery.test={self.csrf_cookie}; Path=/; HttpOnly"},
        )

    def do_POST(self):
        self.__class__.http_requests.append(("POST", self.path))
        size = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
        self.__class__.submissions.append((self.path, fields))

        content_type = self.headers.get("Content-Type", "")
        cookie = self.headers.get("Cookie", "")
        token_valid = fields.get("__RequestVerificationToken") == [self.csrf_token]
        cookie_valid = f".AspNetCore.Antiforgery.test={self.csrf_cookie}" in cookie
        self.__class__.request_observations.append({
            "content_type": content_type,
            "token_valid": token_valid,
            "cookie_valid": cookie_valid,
            "fields": fields,
        })

        if not content_type.startswith("application/x-www-form-urlencoded"):
            self._respond("Unsupported form encoding", status=415)
            return

        if not token_valid or not cookie_valid:
            self.__class__.csrf_failures += 1
            self._respond("Antiforgery validation failed", status=400)
            return

        all_values = [value for values in fields.values() for value in values]
        has_payload_canary = any(
            re.search(r"xss[0-9a-f]{8}", value, re.IGNORECASE)
            for value in all_values
        )
        if self.__class__.fail_baseline_requests and not has_payload_canary:
            self._respond(
                f"Baseline handler error; token={self.csrf_token}; "
                f"cookie={self.csrf_cookie}; email={fields.get('Email', [''])[0]}",
                status=500,
            )
            return

        if self.__class__.validate_contact_fields:
            email = fields.get("Email", [""])[0]
            contact_fields_valid = (
                bool(fields.get("Name", [""])[0].strip())
                and bool(fields.get("Message", [""])[0].strip())
                and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None
            )
            if not contact_fields_valid:
                self._respond(
                    f"Contact model validation failed; token={self.csrf_token}; "
                    f"cookie={self.csrf_cookie}; email={email}",
                    status=500,
                )
                return

        if self.__class__.fail_payload_requests and any(
            re.search(r"xss[0-9a-f]{8}", value, re.IGNORECASE) for value in all_values
        ):
            error_body = (
                "<html><body>Server failed handling the submitted email "
                f"{fields.get('Email', [''])[0]}; "
                f"__RequestVerificationToken={self.csrf_token}; "
                f"Cookie={self.csrf_cookie}; application error</body></html>"
            )
            self._respond(error_body, status=500)
            return

        should_escape = self.__class__.escape_all or self.path == "/escaped"
        reflected_values = [
            value
            for name, values in fields.items()
            if name != "__RequestVerificationToken"
            for value in values
        ]
        if should_escape:
            body = "".join(escape(value) for value in reflected_values)
        else:
            body = "".join(reflected_values)
        self._respond(f"<html><body>{body}</body></html>")


class TestXssIntegration(unittest.TestCase):
    def setUp(self):
        ControlledXssHandler.submissions = []
        ControlledXssHandler.csrf_failures = 0
        ControlledXssHandler.request_observations = []
        ControlledXssHandler.http_requests = []
        ControlledXssHandler.fail_payload_requests = False
        ControlledXssHandler.fail_baseline_requests = False
        ControlledXssHandler.validate_contact_fields = False
        ControlledXssHandler.single_form = False
        self.server = HTTPServer(("127.0.0.1", 0), ControlledXssHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.target_url = f"http://127.0.0.1:{self.server.server_port}/"

        self.auth_patch = patch.dict(os.environ, {"AUTHORIZED_TARGET": self.target_url})
        self.auth_patch.start()
        self.delay_patch = patch.object(recon, "DELAY_SECONDS", 0)
        self.delay_patch.start()

    def tearDown(self):
        self.delay_patch.stop()
        self.auth_patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    def _scan(self, escape_all):
        ControlledXssHandler.escape_all = escape_all
        original_recon = main.run_recon

        def run_recon_then_reset_request_counter(target_url):
            results = original_recon(target_url)
            ControlledXssHandler.http_requests.clear()
            return results

        with patch.object(main, "validate_target"), patch.object(main, "save_scan") as save_scan, patch.object(
            main, "run_recon", side_effect=run_recon_then_reset_request_counter
        ):
            response = main.start_xss_scan(main.ReconRequest(target_url=self.target_url))
        return response, save_scan

    def test_api_scans_csrf_post_forms_actions_and_multiple_fields(self):
        response, save_scan = self._scan(escape_all=False)

        self.assertEqual(response["status"], "completed")
        self.assertGreater(response["findings_count"], 0)
        diagnostics = response["diagnostics"]
        self.assertEqual(diagnostics["form_count"], 2)
        self.assertEqual(diagnostics["forms_tested"], 2)
        self.assertEqual(diagnostics["forms_skipped"], 0)
        self.assertEqual(
            {item["url"] for item in diagnostics["endpoints"]},
            {
                f"http://127.0.0.1:{self.server.server_port}/reflect",
                f"http://127.0.0.1:{self.server.server_port}/escaped",
            },
        )
        self.assertTrue(
            all(item["status"] == "tested" for item in diagnostics["endpoints"])
        )
        self.assertEqual(ControlledXssHandler.csrf_failures, 0)
        self.assertTrue(
            all(fields.get("__RequestVerificationToken") == [ControlledXssHandler.csrf_token]
                for _path, fields in ControlledXssHandler.submissions)
        )
        submitted_fields = {
            name
            for _path, fields in ControlledXssHandler.submissions
            for name in fields
        }
        self.assertTrue({"Name", "Email", "Message", "subject", "comment"} <= submitted_fields)
        save_scan.assert_called_once()
        self.assertEqual(save_scan.call_args.kwargs["status"], "completed")

    def test_properly_escaped_application_completes_with_zero_findings(self):
        response, save_scan = self._scan(escape_all=True)

        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["findings_count"], 0)
        self.assertEqual(response["findings"], [])
        self.assertEqual(response["diagnostics"]["forms_tested"], 2)
        self.assertEqual(response["diagnostics"]["forms_skipped"], 0)
        self.assertEqual(ControlledXssHandler.csrf_failures, 0)
        save_scan.assert_called_once()
        self.assertEqual(save_scan.call_args.kwargs["status"], "completed")

    def test_fourteen_escaped_payloads_are_fourteen_successful_http_posts(self):
        ControlledXssHandler.single_form = True
        response, _save_scan = self._scan(escape_all=True)

        diagnostics = response["diagnostics"]
        endpoint = diagnostics["endpoints"][0]
        self.assertEqual(len(xss.get_payload_list()), 14)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["findings"], [])
        self.assertEqual(endpoint["baseline"]["requests_attempted"], 2)

        parameters = {item["name"]: item for item in endpoint["parameters"]}
        self.assertEqual(set(parameters), {"Name", "Email", "Message", "__RequestVerificationToken"})
        for name in ("Name", "Email", "Message"):
            self.assertEqual(parameters[name]["payload_attempts"], 14)
            self.assertEqual(parameters[name]["responses"], 14)
            self.assertEqual(parameters[name]["successful_responses"], 14)
            self.assertEqual(parameters[name]["http_status_counts"], {"200": 14})

        payload_post_counts = {name: 0 for name in ("Name", "Email", "Message")}
        for method, path in ControlledXssHandler.http_requests:
            self.assertIn(method, {"GET", "POST"})
            self.assertEqual(path, "/" if method == "GET" else "/reflect")
        for path, fields in ControlledXssHandler.submissions:
            if path != "/reflect":
                continue
            for name in payload_post_counts:
                if any(
                    re.search(r"xss[0-9a-f]{8}", value, re.IGNORECASE)
                    for value in fields.get(name, [])
                ):
                    payload_post_counts[name] += 1

        self.assertEqual(payload_post_counts, {"Name": 14, "Email": 14, "Message": 14})
        self.assertEqual(len(ControlledXssHandler.http_requests), 86)
        self.assertEqual(diagnostics["requests_attempted"], len(ControlledXssHandler.http_requests))
        self.assertEqual(sum(method == "GET" for method, _ in ControlledXssHandler.http_requests), 43)
        self.assertEqual(sum(method == "POST" for method, _ in ControlledXssHandler.http_requests), 43)
        self.assertTrue(
            all(item["content_type"].startswith("application/x-www-form-urlencoded")
                for item in ControlledXssHandler.request_observations)
        )
        self.assertTrue(
            all(item["token_valid"] and item["cookie_valid"]
                for item in ControlledXssHandler.request_observations)
        )

    def test_out_of_scope_form_is_reported_as_skipped_and_scan_incomplete(self):
        diagnostics = {}
        endpoint = {
            "url": "http://outside.invalid/submit",
            "method": "POST",
            "params": ["message"],
            "page_url": "http://outside.invalid/form",
            "form_index": 0,
        }

        with patch.dict(os.environ, {"AUTHORIZED_TARGET": self.target_url}):
            findings = xss.run({"params": [endpoint]}, diagnostics=diagnostics)

        self.assertEqual(findings, [])
        self.assertEqual(diagnostics["status"], "incomplete")
        self.assertEqual(diagnostics["forms_skipped"], 1)
        self.assertEqual(diagnostics["endpoints"][0]["status"], "skipped")
        self.assertIn("outside the authorized scope", diagnostics["endpoints"][0]["reason"])

    def test_failed_requests_are_reported_as_incomplete(self):
        diagnostics = {}
        endpoint = {
            "url": self.target_url,
            "method": "GET",
            "params": ["search"],
        }

        with patch.object(xss, "inject_payload", return_value=None):
            findings = xss.run({"params": [endpoint]}, diagnostics=diagnostics)

        self.assertEqual(findings, [])
        self.assertEqual(diagnostics["status"], "incomplete")
        self.assertEqual(diagnostics["endpoints"][0]["status"], "failed")
        self.assertTrue(any(issue["kind"] == "request" for issue in diagnostics["issues"]))

    def test_response_parsing_errors_are_reported(self):
        diagnostics = {}
        endpoint = {
            "url": self.target_url,
            "method": "GET",
            "params": ["search"],
        }
        def reflected_response(_endpoint, _param, payload, **_kwargs):
            return type("Response", (), {"status_code": 200, "text": payload})()

        with patch.object(xss, "inject_payload", side_effect=reflected_response), patch.object(
            xss, "BeautifulSoup", side_effect=ValueError("controlled parser failure")
        ):
            findings = xss.run({"params": [endpoint]}, diagnostics=diagnostics)

        self.assertTrue(findings)
        self.assertEqual(diagnostics["status"], "incomplete")
        self.assertTrue(any(issue["kind"] == "parsing" for issue in diagnostics["issues"]))

    def test_antiforgery_baseline_passes_but_payload_http_500s_are_not_findings(self):
        ControlledXssHandler.single_form = True
        ControlledXssHandler.fail_payload_requests = True

        response, _save_scan = self._scan(escape_all=False)

        self.assertEqual(response["status"], "incomplete")
        self.assertEqual(response["findings"], [])
        self.assertEqual(response["findings_count"], 0)
        diagnostics = response["diagnostics"]
        self.assertEqual(diagnostics["forms_failed"], 1)
        self.assertEqual(diagnostics["forms_tested"], 0)

        endpoint = diagnostics["endpoints"][0]
        self.assertEqual(endpoint["baseline"]["status"], "passed")
        self.assertEqual(endpoint["baseline"]["status_code"], 200)
        self.assertEqual(
            endpoint["baseline"]["request_content_type"],
            "application/x-www-form-urlencoded",
        )
        self.assertTrue(endpoint["baseline"]["csrf_field_present"])
        self.assertEqual(endpoint["baseline"]["session_cookie_count"], 1)
        self.assertEqual(endpoint["status"], "failed")

        parameters = {item["name"]: item for item in endpoint["parameters"]}
        self.assertEqual(
            set(parameters),
            {"Name", "Email", "Message", "__RequestVerificationToken"},
        )
        self.assertEqual(parameters["__RequestVerificationToken"]["status"], "skipped")
        for name in ("Name", "Email", "Message"):
            parameter = parameters[name]
            self.assertEqual(parameter["status"], "failed")
            self.assertEqual(parameter["payload_attempts"], 14)
            self.assertEqual(parameter["responses"], 14)
            self.assertEqual(parameter["successful_responses"], 0)
            self.assertEqual(parameter["http_status_counts"], {"500": 14})

        baseline = next(
            fields for path, fields in ControlledXssHandler.submissions
            if path == "/reflect" and fields["Name"] == ["XSS scanner"]
        )
        self.assertEqual(baseline["Email"], ["xss-scanner@example.invalid"])
        self.assertEqual(baseline["Message"], ["XSS scanner baseline message"])
        self.assertEqual(ControlledXssHandler.csrf_failures, 0)
        self.assertTrue(
            all(item["token_valid"] and item["cookie_valid"]
                for item in ControlledXssHandler.request_observations)
        )
        self.assertTrue(
            all(item["content_type"].startswith("application/x-www-form-urlencoded")
                for item in ControlledXssHandler.request_observations)
        )

        http_issues = [
            issue for issue in diagnostics["issues"]
            if issue["kind"] == "http" and "HTTP 500" in issue["message"]
        ]
        self.assertTrue(http_issues)
        for issue in http_issues:
            self.assertNotIn(ControlledXssHandler.csrf_token, issue["message"])
            self.assertNotIn(ControlledXssHandler.csrf_cookie, issue["message"])
            self.assertNotIn("xss-scanner@example.invalid", issue["message"])

    def test_baseline_http_500_stops_payload_testing(self):
        ControlledXssHandler.single_form = True
        ControlledXssHandler.fail_baseline_requests = True

        response, _save_scan = self._scan(escape_all=False)

        self.assertEqual(response["status"], "incomplete")
        self.assertEqual(response["findings"], [])
        self.assertEqual(ControlledXssHandler.csrf_failures, 0)
        self.assertEqual(len(ControlledXssHandler.submissions), 1)
        endpoint = response["diagnostics"]["endpoints"][0]
        self.assertEqual(endpoint["baseline"]["status"], "failed")
        self.assertEqual(endpoint["baseline"]["status_code"], 500)
        self.assertEqual(endpoint["status"], "failed")
        self.assertEqual(endpoint["parameters"], [])
        excerpt = endpoint["baseline"]["response_excerpt"]
        self.assertIn("Baseline handler error", excerpt)
        self.assertNotIn(ControlledXssHandler.csrf_token, excerpt)
        self.assertNotIn(ControlledXssHandler.csrf_cookie, excerpt)
        self.assertNotIn("xss-scanner@example.invalid", excerpt)

    def test_blank_sibling_fields_are_filled_to_avoid_model_validation_500s(self):
        ControlledXssHandler.single_form = True
        ControlledXssHandler.validate_contact_fields = True

        with requests.Session() as session:
            page = session.get(self.target_url, timeout=5)
            token = BeautifulSoup(page.text, "html.parser").find(
                "input", attrs={"name": "__RequestVerificationToken"},
            )["value"]
            original_request = session.post(
                f"http://127.0.0.1:{self.server.server_port}/reflect",
                data={
                    "__RequestVerificationToken": token,
                    "Name": "",
                    "Email": "",
                    "Message": "",
                },
                timeout=5,
            )
        self.assertEqual(original_request.status_code, 500)

        response, _save_scan = self._scan(escape_all=False)

        self.assertEqual(response["status"], "incomplete")
        endpoint = response["diagnostics"]["endpoints"][0]
        self.assertEqual(endpoint["baseline"]["status"], "passed")
        parameters = {item["name"]: item for item in endpoint["parameters"]}
        self.assertEqual(parameters["Name"]["status"], "tested")
        self.assertEqual(parameters["Message"]["status"], "tested")
        self.assertEqual(parameters["Email"]["status"], "failed")
        self.assertEqual(parameters["Email"]["http_status_counts"], {"500": 14})
        self.assertGreater(response["findings_count"], 0)

        payload_submissions = [
            fields for path, fields in ControlledXssHandler.submissions
            if path == "/reflect" and any(
                re.search(r"xss[0-9a-f]{8}", value, re.IGNORECASE)
                for values in fields.values()
                for value in values
            )
        ]
        self.assertTrue(payload_submissions)
        for fields in payload_submissions:
            self.assertTrue(fields["Name"][0])
            self.assertTrue(fields["Message"][0])
            if re.search(r"xss[0-9a-f]{8}", fields["Email"][0], re.IGNORECASE):
                self.assertEqual(fields["Email"][0], next(
                    value for value in fields["Email"]
                    if re.search(r"xss[0-9a-f]{8}", value, re.IGNORECASE)
                ))
            else:
                self.assertEqual(fields["Email"], ["xss-scanner@example.invalid"])


if __name__ == "__main__":
    unittest.main()
