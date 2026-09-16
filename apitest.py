#!/usr/bin/env python3
"""apitest — REST API security testing for authorized assessments.

Checks the controls that API assessments actually turn findings on: whether
authentication is really enforced, whether CORS is misconfigured, whether the
API leaks stack traces, whether rate limiting exists, whether HTTP methods are
properly restricted, and whether responses expose sensitive fields.

The tool sends ordinary, well-formed requests. It carries no exploit payloads
and never attempts to damage or persist changes to a target.

Standard library only. For AUTHORIZED testing and educational use.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

USER_AGENT = "apitest/1.0 (authorized security assessment)"

# Response fragments that indicate an unhandled server error reached the client.
STACK_TRACE_SIGNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"(?:Fatal error|Warning):.*?in .*?\.php on line \d+", re.I), "PHP error"),
    (re.compile(r"System\.\w+Exception:"), ".NET exception"),
    (re.compile(r"\bORA-\d{5}\b"), "Oracle database error"),
    (re.compile(r"SQLSTATE\[|SQL syntax.*MySQL|PostgreSQL.*ERROR", re.I), "SQL error"),
    (re.compile(r"/(?:home|var|usr|opt)/[\w./-]{8,}"), "filesystem path disclosure"),
]

# Field names that should rarely appear in an API response body.
SENSITIVE_FIELDS = re.compile(
    r'"(password|passwd|secret|api_?key|private_?key|access_?token|'
    r'refresh_token|ssn|credit_?card|cvv|authorization)"\s*:', re.I)

API_SECURITY_HEADERS = {
    "x-content-type-options": "Stops browsers MIME-sniffing an API response.",
    "cache-control": "Prevents sensitive API responses being cached.",
    "strict-transport-security": "Forces HTTPS and blocks downgrade attacks.",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    severity: str
    check: str
    endpoint: str
    summary: str
    evidence: str = ""


@dataclass
class Response:
    status: int
    headers: dict
    body: str
    elapsed_ms: float


def request(url: str, method: str = "GET", headers: dict | None = None,
            body: bytes | None = None, timeout: float = 15.0,
            verify_tls: bool = True) -> Response | None:
    """Send one request. Returns None only if the host is unreachable."""
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    all_headers.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=all_headers,
                                 method=method)
    context = None
    if not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return Response(resp.status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            resp.read(100_000).decode("utf-8", "replace"),
                            (time.perf_counter() - started) * 1000)
    except urllib.error.HTTPError as exc:
        return Response(exc.code,
                        {k.lower(): v for k, v in (exc.headers or {}).items()},
                        (exc.read(50_000) or b"").decode("utf-8", "replace"),
                        (time.perf_counter() - started) * 1000)
    except (urllib.error.URLError, OSError, ssl.SSLError):
        return None


# ===========================================================================
# Checks
# ===========================================================================
def check_authentication(base: str, endpoint: dict, auth_headers: dict,
                         args) -> list[Finding]:
    """An endpoint marked as protected must reject an unauthenticated request."""
    if not endpoint.get("auth_required", True):
        return []

    url = urllib.parse.urljoin(base, endpoint["path"])
    method = endpoint.get("method", "GET").upper()
    resp = request(url, method, timeout=args.timeout, verify_tls=not args.insecure)
    if resp is None:
        return []

    label = f"{method} {endpoint['path']}"
    if resp.status in (200, 201, 202, 204):
        return [Finding(
            "critical", "broken-authentication", label,
            "A protected endpoint returned success without any credentials — "
            "authentication is not enforced.",
            f"unauthenticated request returned HTTP {resp.status}")]
    if resp.status not in (401, 403):
        return [Finding(
            "low", "auth-response-code", label,
            f"Unauthenticated request returned HTTP {resp.status} rather than "
            f"401 or 403, which makes the auth boundary ambiguous.", "")]
    return []


def check_cors(base: str, endpoint: dict, auth_headers: dict,
               args) -> list[Finding]:
    """Reflected origin + credentials is the classic exploitable CORS bug."""
    url = urllib.parse.urljoin(base, endpoint["path"])
    probe_origin = "https://apitest-probe.example"
    headers = dict(auth_headers)
    headers["Origin"] = probe_origin
    resp = request(url, endpoint.get("method", "GET").upper(), headers,
                   timeout=args.timeout, verify_tls=not args.insecure)
    if resp is None:
        return []

    label = f"{endpoint.get('method', 'GET').upper()} {endpoint['path']}"
    allow_origin = resp.headers.get("access-control-allow-origin", "")
    allow_creds = resp.headers.get("access-control-allow-credentials",
                                   "").lower() == "true"
    findings = []

    if allow_origin == probe_origin and allow_creds:
        findings.append(Finding(
            "critical", "cors-reflected-origin", label,
            "The API reflects an arbitrary Origin and allows credentials. Any "
            "website can read authenticated responses on a victim's behalf.",
            f"Access-Control-Allow-Origin: {allow_origin} with "
            f"Allow-Credentials: true"))
    elif allow_origin == "*" and allow_creds:
        findings.append(Finding(
            "high", "cors-wildcard-credentials", label,
            "Wildcard origin combined with credentials. Browsers reject this "
            "pairing, but it signals a misconfigured CORS policy.",
            "Access-Control-Allow-Origin: * with Allow-Credentials: true"))
    elif allow_origin == probe_origin:
        findings.append(Finding(
            "medium", "cors-reflected-origin", label,
            "The API reflects an arbitrary Origin back. Without credentials the "
            "impact is limited, but the allowlist is not actually restricting.",
            f"Access-Control-Allow-Origin: {allow_origin}"))
    return findings


def check_error_disclosure(base: str, endpoint: dict, auth_headers: dict,
                           args) -> list[Finding]:
    """Ask for something that does not exist and see how the API fails."""
    path = endpoint["path"].rstrip("/") + "/apitest-nonexistent-9137"
    url = urllib.parse.urljoin(base, path)
    resp = request(url, "GET", auth_headers, timeout=args.timeout,
                   verify_tls=not args.insecure)
    if resp is None:
        return []

    label = f"GET {path}"
    findings = []
    for pattern, description in STACK_TRACE_SIGNS:
        match = pattern.search(resp.body)
        if match:
            findings.append(Finding(
                "medium", "verbose-errors", label,
                f"The API returned a {description} to the client. Internal "
                f"errors should be logged server-side and answered with a "
                f"generic message.",
                match.group(0)[:160]))
            break
    return findings


def check_sensitive_fields(endpoint: dict, resp: Response) -> list[Finding]:
    label = f"{endpoint.get('method', 'GET').upper()} {endpoint['path']}"
    match = SENSITIVE_FIELDS.search(resp.body)
    if match:
        return [Finding(
            "high", "sensitive-data-exposure", label,
            "The response body contains a field name that suggests secret "
            "material is being returned to the client.",
            match.group(0)[:80])]
    return []


def check_headers(endpoint: dict, resp: Response, is_https: bool) -> list[Finding]:
    label = f"{endpoint.get('method', 'GET').upper()} {endpoint['path']}"
    findings = []
    for header, why in API_SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not is_https:
            continue
        if header not in resp.headers:
            findings.append(Finding(
                "low", "missing-header", label,
                f"Response is missing '{header}'. {why}", ""))
    content_type = resp.headers.get("content-type", "")
    if content_type and "application/json" not in content_type \
            and resp.body.strip().startswith(("{", "[")):
        findings.append(Finding(
            "low", "content-type-mismatch", label,
            f"Body looks like JSON but Content-Type is '{content_type}'. "
            f"Mismatches invite MIME confusion.", ""))
    return findings


def check_methods(base: str, endpoint: dict, auth_headers: dict,
                  args) -> list[Finding]:
    """Unsafe methods should not be quietly accepted on a read endpoint."""
    url = urllib.parse.urljoin(base, endpoint["path"])
    findings = []

    options = request(url, "OPTIONS", auth_headers, timeout=args.timeout,
                      verify_tls=not args.insecure)
    if options and options.status < 400:
        allowed = options.headers.get("allow") or \
            options.headers.get("access-control-allow-methods", "")
        risky = [m for m in ("TRACE", "PUT", "DELETE", "PATCH")
                 if m in allowed.upper()]
        if "TRACE" in allowed.upper():
            findings.append(Finding(
                "medium", "dangerous-method", f"OPTIONS {endpoint['path']}",
                "TRACE is advertised as allowed. It can be abused to echo "
                "headers, including cookies, back to an attacker.",
                f"Allow: {allowed}"))
        elif risky and endpoint.get("method", "GET").upper() == "GET":
            findings.append(Finding(
                "info", "method-surface", f"OPTIONS {endpoint['path']}",
                f"State-changing methods advertised on a read endpoint: "
                f"{', '.join(risky)}. Confirm each is intended and authorised.",
                f"Allow: {allowed}"))
    return findings


def check_rate_limit(base: str, endpoint: dict, auth_headers: dict,
                     args) -> list[Finding]:
    """Send a modest burst and look for throttling. Never a flood."""
    url = urllib.parse.urljoin(base, endpoint["path"])
    method = endpoint.get("method", "GET").upper()
    label = f"{method} {endpoint['path']}"

    throttled = False
    saw_headers = False
    for _ in range(args.burst):
        resp = request(url, method, auth_headers, timeout=args.timeout,
                       verify_tls=not args.insecure)
        if resp is None:
            return []
        if resp.status == 429:
            throttled = True
            break
        if any(h in resp.headers for h in
               ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit",
                "retry-after")):
            saw_headers = True
    if not throttled and not saw_headers:
        return [Finding(
            "medium", "no-rate-limiting", label,
            f"{args.burst} rapid requests produced no 429 and no rate-limit "
            f"headers. Without throttling the endpoint is open to credential "
            f"stuffing and scraping.", "")]
    return []


def check_transport(base: str) -> list[Finding]:
    if urllib.parse.urlparse(base).scheme != "https":
        return [Finding(
            "high", "insecure-transport", base,
            "The API base URL is plain HTTP. Tokens and payloads travel in "
            "cleartext and can be read or modified in transit.", "")]
    return []


# ===========================================================================
# Runner
# ===========================================================================
def run(config: dict, args) -> list[Finding]:
    base = config["base_url"].rstrip("/") + "/"
    endpoints = config.get("endpoints", [])
    auth_headers = dict(config.get("auth_headers", {}))
    is_https = urllib.parse.urlparse(base).scheme == "https"

    findings: list[Finding] = check_transport(base)

    for endpoint in endpoints:
        path = endpoint.get("path")
        if not path:
            continue
        print(f"  testing {endpoint.get('method', 'GET').upper():<7} {path}")

        findings += check_authentication(base, endpoint, auth_headers, args)
        findings += check_cors(base, endpoint, auth_headers, args)
        findings += check_error_disclosure(base, endpoint, auth_headers, args)
        findings += check_methods(base, endpoint, auth_headers, args)

        url = urllib.parse.urljoin(base, path)
        resp = request(url, endpoint.get("method", "GET").upper(), auth_headers,
                       timeout=args.timeout, verify_tls=not args.insecure)
        if resp is not None:
            findings += check_headers(endpoint, resp, is_https)
            findings += check_sensitive_fields(endpoint, resp)

        if args.rate_limit:
            findings += check_rate_limit(base, endpoint, auth_headers, args)

    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


def print_findings(findings: list[Finding]) -> None:
    print(f"\n  Findings: {len(findings)}\n")
    if not findings:
        print("  No issues detected by the checks that ran.\n")
        return
    for finding in findings:
        print(f"  [{finding.severity.upper():<8}] {finding.check}")
        print(f"             {finding.endpoint}")
        print(f"             {finding.summary}")
        if finding.evidence:
            print(f"             evidence: {finding.evidence}")
        print()

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = "  ".join(f"{k}: {v}" for k, v in
                        sorted(counts.items(),
                               key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
    print(f"  Summary: {summary}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="REST API security testing for authorized assessments.")
    parser.add_argument("config", help="JSON config describing the API")
    parser.add_argument("--rate-limit", action="store_true",
                        help="include the rate-limiting check (sends a burst)")
    parser.add_argument("--burst", type=int, default=12,
                        help="requests in the rate-limit burst (default 12)")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="request timeout in seconds (default 15)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (staging with a self-signed cert)")
    parser.add_argument("-o", "--output", help="write the JSON report to this file")
    parser.add_argument("--authorized", action="store_true",
                        help="confirm you are authorized to test this API")
    args = parser.parse_args(argv)

    if not args.authorized:
        print("Refusing to run: pass --authorized to confirm you have explicit "
              "permission to test this API.", file=sys.stderr)
        return 2

    try:
        with open(args.config, "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read config: {exc}", file=sys.stderr)
        return 2

    if "base_url" not in config:
        print("Config must contain 'base_url'.", file=sys.stderr)
        return 2

    print(f"\n  Target: {config['base_url']}")
    print(f"  Endpoints: {len(config.get('endpoints', []))}\n")

    findings = run(config, args)
    print_findings(findings)

    if args.output:
        payload = {
            "target": config["base_url"],
            "tested_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "findings": [asdict(f) for f in findings],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"  Report written to {args.output}\n")

    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
