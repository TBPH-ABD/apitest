"""Tests for apitest's API security checks."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest

import apitest
from apitest import (Response, check_authentication, check_cors,
                     check_error_disclosure, check_headers, check_methods,
                     check_rate_limit, check_sensitive_fields,
                     check_transport, run)
from tests.support.fakes import capture_cli, http_fake

SECURE = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}


def args(**overrides) -> argparse.Namespace:
    values = {"timeout": 5.0, "insecure": False, "rate_limit": False,
              "burst": 4}
    values.update(overrides)
    return argparse.Namespace(**values)


def endpoint(path="users/me", method="GET", auth_required=True) -> dict:
    return {"path": path, "method": method, "auth_required": auth_required}


def checks(findings) -> set[str]:
    return {f.check for f in findings}


def response(status=200, headers=None, body="") -> Response:
    return Response(status, {k.lower(): v for k, v in (headers or {}).items()},
                    body, 1.0)


class TestTransport(unittest.TestCase):
    def test_plain_http_is_flagged_high(self):
        findings = check_transport("http://api.example.test/")
        self.assertEqual(findings[0].check, "insecure-transport")
        self.assertEqual(findings[0].severity, "high")

    def test_https_is_not_flagged(self):
        self.assertEqual(check_transport("https://api.example.test/"), [])


class TestAuthentication(unittest.TestCase):
    def test_protected_endpoint_returning_200_is_critical(self):
        with http_fake({}, default=(200, {}, "{}")) as (base, _):
            findings = check_authentication(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "broken-authentication")
        self.assertEqual(findings[0].severity, "critical")

    def test_401_is_correct_and_produces_nothing(self):
        with http_fake({}, default=(401, {}, "unauthorized")) as (base, _):
            findings = check_authentication(base + "/", endpoint(), {}, args())
        self.assertEqual(findings, [])

    def test_403_is_also_accepted(self):
        with http_fake({}, default=(403, {}, "forbidden")) as (base, _):
            findings = check_authentication(base + "/", endpoint(), {}, args())
        self.assertEqual(findings, [])

    def test_unexpected_status_is_a_low_finding(self):
        with http_fake({}, default=(500, {}, "boom")) as (base, _):
            findings = check_authentication(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "auth-response-code")
        self.assertEqual(findings[0].severity, "low")

    def test_public_endpoint_is_skipped(self):
        with http_fake({}, default=(200, {}, "{}")) as (base, _):
            findings = check_authentication(
                base + "/", endpoint(auth_required=False), {}, args())
        self.assertEqual(findings, [])

    def test_no_credentials_are_sent_on_the_probe(self):
        """The whole check depends on the request being unauthenticated."""
        with http_fake({}, default=(401, {}, "")) as (base, recorder):
            check_authentication(base + "/", endpoint(),
                                 {"Authorization": "Bearer secret"}, args())
        self.assertNotIn("authorization", recorder.requests[0]["headers"])


class TestCors(unittest.TestCase):
    def test_reflected_origin_with_credentials_is_critical(self):
        headers = {"Access-Control-Allow-Origin": "https://apitest-probe.example",
                   "Access-Control-Allow-Credentials": "true"}
        with http_fake({}, default=(200, headers, "{}")) as (base, _):
            findings = check_cors(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "cors-reflected-origin")
        self.assertEqual(findings[0].severity, "critical")

    def test_wildcard_with_credentials_is_high(self):
        headers = {"Access-Control-Allow-Origin": "*",
                   "Access-Control-Allow-Credentials": "true"}
        with http_fake({}, default=(200, headers, "{}")) as (base, _):
            findings = check_cors(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "cors-wildcard-credentials")

    def test_reflected_origin_without_credentials_is_medium(self):
        headers = {"Access-Control-Allow-Origin": "https://apitest-probe.example"}
        with http_fake({}, default=(200, headers, "{}")) as (base, _):
            findings = check_cors(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].severity, "medium")

    def test_fixed_allowlist_origin_is_not_flagged(self):
        headers = {"Access-Control-Allow-Origin": "https://app.example.com",
                   "Access-Control-Allow-Credentials": "true"}
        with http_fake({}, default=(200, headers, "{}")) as (base, _):
            self.assertEqual(check_cors(base + "/", endpoint(), {}, args()), [])

    def test_no_cors_headers_produce_nothing(self):
        with http_fake({}, default=(200, {}, "{}")) as (base, _):
            self.assertEqual(check_cors(base + "/", endpoint(), {}, args()), [])


class TestErrorDisclosure(unittest.TestCase):
    def assert_detects(self, body: str, expected: str):
        with http_fake({}, default=(500, {}, body)) as (base, _):
            findings = check_error_disclosure(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "verbose-errors")
        self.assertIn(expected, findings[0].summary)

    def test_python_traceback(self):
        self.assert_detects("Traceback (most recent call last):\n  File x",
                            "Python traceback")

    def test_php_error(self):
        self.assert_detects("Fatal error: call in /var/www/app.php on line 42",
                            "PHP error")

    def test_dotnet_exception(self):
        self.assert_detects("System.NullReferenceException: object",
                            ".NET exception")

    def test_sql_error(self):
        self.assert_detects("SQLSTATE[42000]: Syntax error", "SQL error")

    def test_oracle_error(self):
        self.assert_detects("ORA-01722: invalid number", "Oracle database error")

    def test_clean_404_produces_nothing(self):
        with http_fake({}, default=(404, {}, '{"error":"not found"}')) \
                as (base, _):
            findings = check_error_disclosure(base + "/", endpoint(), {}, args())
        self.assertEqual(findings, [])


class TestSensitiveFields(unittest.TestCase):
    def test_password_field_is_flagged(self):
        findings = check_sensitive_fields(
            endpoint(), response(body='{"id":1,"password":"x"}'))
        self.assertEqual(findings[0].check, "sensitive-data-exposure")
        self.assertEqual(findings[0].severity, "high")

    def test_api_key_field_is_flagged(self):
        findings = check_sensitive_fields(
            endpoint(), response(body='{"api_key":"abc"}'))
        self.assertEqual(len(findings), 1)

    def test_access_token_field_is_flagged(self):
        findings = check_sensitive_fields(
            endpoint(), response(body='{"access_token":"abc"}'))
        self.assertEqual(len(findings), 1)

    def test_ordinary_body_is_not_flagged(self):
        findings = check_sensitive_fields(
            endpoint(), response(body='{"id":1,"name":"Salah"}'))
        self.assertEqual(findings, [])

    def test_a_field_merely_named_username_is_not_flagged(self):
        findings = check_sensitive_fields(
            endpoint(), response(body='{"username":"salah"}'))
        self.assertEqual(findings, [])


class TestHeaders(unittest.TestCase):
    def test_missing_headers_are_reported(self):
        findings = check_headers(endpoint(), response(), is_https=True)
        self.assertIn("missing-header", checks(findings))

    def test_all_headers_present_over_http_produces_nothing(self):
        headers = dict(SECURE)
        findings = check_headers(endpoint(), response(headers=headers),
                                 is_https=False)
        self.assertEqual(findings, [])

    def test_hsts_is_only_required_over_https(self):
        findings = check_headers(endpoint(), response(headers=SECURE),
                                 is_https=True)
        summaries = " ".join(f.summary for f in findings)
        self.assertIn("strict-transport-security", summaries)

    def test_json_body_with_wrong_content_type_is_flagged(self):
        resp = response(headers={**SECURE, "Content-Type": "text/plain"},
                        body='{"a":1}')
        findings = check_headers(endpoint(), resp, is_https=False)
        self.assertIn("content-type-mismatch", checks(findings))

    def test_correct_content_type_is_not_flagged(self):
        resp = response(headers={**SECURE, "Content-Type": "application/json"},
                        body='{"a":1}')
        findings = check_headers(endpoint(), resp, is_https=False)
        self.assertNotIn("content-type-mismatch", checks(findings))


class TestMethods(unittest.TestCase):
    def test_trace_is_flagged_medium(self):
        headers = {"Allow": "GET, POST, TRACE"}
        with http_fake({}, default=(200, headers, "")) as (base, _):
            findings = check_methods(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "dangerous-method")
        self.assertEqual(findings[0].severity, "medium")

    def test_state_changing_methods_on_a_read_endpoint_are_info(self):
        headers = {"Allow": "GET, PUT, DELETE"}
        with http_fake({}, default=(200, headers, "")) as (base, _):
            findings = check_methods(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "method-surface")
        self.assertEqual(findings[0].severity, "info")

    def test_read_only_allow_header_produces_nothing(self):
        with http_fake({}, default=(200, {"Allow": "GET, HEAD"}, "")) as (base, _):
            self.assertEqual(check_methods(base + "/", endpoint(), {}, args()), [])


class TestRateLimit(unittest.TestCase):
    def test_absent_throttling_is_flagged(self):
        with http_fake({}, default=(200, {}, "{}")) as (base, _):
            findings = check_rate_limit(base + "/", endpoint(), {}, args())
        self.assertEqual(findings[0].check, "no-rate-limiting")

    def test_429_response_satisfies_the_check(self):
        with http_fake({}, default=(429, {}, "slow down")) as (base, _):
            findings = check_rate_limit(base + "/", endpoint(), {}, args())
        self.assertEqual(findings, [])

    def test_rate_limit_headers_satisfy_the_check(self):
        headers = {"X-RateLimit-Limit": "100"}
        with http_fake({}, default=(200, headers, "{}")) as (base, _):
            findings = check_rate_limit(base + "/", endpoint(), {}, args())
        self.assertEqual(findings, [])

    def test_burst_size_is_respected(self):
        with http_fake({}, default=(200, {}, "{}")) as (base, recorder):
            check_rate_limit(base + "/", endpoint(), {}, args(burst=3))
        self.assertEqual(len(recorder.requests), 3)

    def test_burst_stops_early_once_throttled(self):
        with http_fake({}, default=(429, {}, "")) as (base, recorder):
            check_rate_limit(base + "/", endpoint(), {}, args(burst=10))
        self.assertEqual(len(recorder.requests), 1)


class TestRun(unittest.TestCase):
    def setUp(self):
        # run() prints per-endpoint progress; keep it out of the test log.
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)

    def test_findings_are_sorted_most_severe_first(self):
        headers = {"Access-Control-Allow-Origin": "https://apitest-probe.example",
                   "Access-Control-Allow-Credentials": "true"}
        body = '{"password":"x"}'
        with http_fake({}, default=(200, headers, body)) as (base, _):
            findings = run({"base_url": base, "endpoints": [endpoint()]}, args())
        order = [apitest.SEVERITY_ORDER[f.severity] for f in findings]
        self.assertEqual(order, sorted(order))

    def test_endpoint_without_a_path_is_skipped(self):
        with http_fake({}, default=(401, {}, "")) as (base, _):
            findings = run({"base_url": base, "endpoints": [{}]}, args())
        # Only the transport finding from the plain-HTTP base URL.
        self.assertEqual(checks(findings), {"insecure-transport"})

    def test_rate_limit_check_is_off_unless_requested(self):
        with http_fake({}, default=(401, {}, "")) as (base, _):
            findings = run({"base_url": base, "endpoints": [endpoint()]},
                           args(rate_limit=False))
        self.assertNotIn("no-rate-limiting", checks(findings))


class TestCli(unittest.TestCase):
    def config_file(self, tmp: str, base: str) -> str:
        path = os.path.join(tmp, "config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"base_url": base, "endpoints": [endpoint()]}, fh)
        return path

    def test_refuses_without_authorization(self):
        code, out = capture_cli(apitest.main, ["nonexistent.json"])
        self.assertEqual(code, 2)
        self.assertIn("--authorized", out)

    def test_missing_config_reports_error(self):
        code, out = capture_cli(apitest.main,
                                ["/nope/config.json", "--authorized"])
        self.assertEqual(code, 2)
        self.assertIn("Could not read config", out)

    def test_config_without_base_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"endpoints": []}, fh)
            code, out = capture_cli(apitest.main, [path, "--authorized"])
        self.assertEqual(code, 2)
        self.assertIn("base_url", out)

    def test_critical_finding_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            with http_fake({}, default=(200, {}, "{}")) as (base, _):
                code, out = capture_cli(
                    apitest.main, [self.config_file(tmp, base), "--authorized"])
        self.assertEqual(code, 1)
        self.assertIn("broken-authentication", out)

    def test_json_report_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "r.json")
            with http_fake({}, default=(200, {}, "{}")) as (base, _):
                capture_cli(apitest.main,
                            [self.config_file(tmp, base), "--authorized",
                             "-o", report])
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertGreater(data["finding_count"], 0)
        self.assertIn("findings", data)


if __name__ == "__main__":
    unittest.main()
