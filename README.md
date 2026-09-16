# apitest

REST API security testing for authorized assessments. Checks the controls that
API assessments actually turn findings on — and explains the impact of each one
in language that goes straight into a report.

The tool sends ordinary, well-formed requests. It carries **no exploit payloads**
and never attempts to damage or persist changes to a target.

## Checks

| Check | Severity | What it finds |
| --- | --- | --- |
| `broken-authentication` | critical | A protected endpoint returns success with **no credentials at all** |
| `cors-reflected-origin` | critical | The API reflects any `Origin` *and* allows credentials — any site can read authenticated responses |
| `cors-wildcard-credentials` | high | Wildcard origin paired with credentials — a misconfigured policy |
| `insecure-transport` | high | The API is served over plain HTTP |
| `sensitive-data-exposure` | high | Response bodies contain `password`, `api_key`, `access_token`, `ssn`, `cvv`, … |
| `verbose-errors` | medium | Python / Java / PHP / .NET stack traces, SQL errors, or filesystem paths returned to the client |
| `dangerous-method` | medium | `TRACE` advertised as allowed |
| `no-rate-limiting` | medium | A burst produced no `429` and no rate-limit headers |
| `missing-header` | low | `X-Content-Type-Options`, `Cache-Control`, `Strict-Transport-Security` |
| `content-type-mismatch` | low | A JSON body served under a non-JSON `Content-Type` |
| `method-surface` | info | State-changing methods advertised on a read endpoint |

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
python3 apitest.py config.json --authorized

# Include the rate-limiting check and save a report
python3 apitest.py config.json --rate-limit -o api-findings.json --authorized

# Staging environment with a self-signed certificate
python3 apitest.py config.json --insecure --authorized
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--rate-limit` | Include the rate-limiting check (sends a burst) | off |
| `--burst` | Requests in the rate-limit burst | `12` |
| `--timeout` | Request timeout in seconds | `15` |
| `--insecure` | Skip TLS verification | off |
| `-o`, `--output` | Write the JSON report to this file | none |
| `--authorized` | Required. Confirms you have permission to test | off |

## Configuration

```json
{
  "base_url": "https://api.example.com/v1/",
  "auth_headers": {
    "Authorization": "Bearer REPLACE_WITH_YOUR_TEST_TOKEN"
  },
  "endpoints": [
    { "path": "users/me",   "method": "GET",  "auth_required": true },
    { "path": "health",     "method": "GET",  "auth_required": false },
    { "path": "auth/login", "method": "POST", "auth_required": false }
  ]
}
```

`auth_required: true` is what drives the authentication check — the endpoint is
requested **without** credentials and is expected to answer `401` or `403`.

> **Never commit real tokens.** Keep the token out of the config in version
> control and inject it at run time, for example by generating the config from
> an environment variable in your test script.

## Example output

Run against a deliberately vulnerable endpoint:

```
  [CRITICAL] broken-authentication
             GET users/me
             A protected endpoint returned success without any credentials —
             authentication is not enforced.
             evidence: unauthenticated request returned HTTP 200

  [CRITICAL] cors-reflected-origin
             GET users/me
             The API reflects an arbitrary Origin and allows credentials. Any
             website can read authenticated responses on a victim's behalf.
             evidence: Access-Control-Allow-Origin: https://apitest-probe.example
                       with Allow-Credentials: true

  [HIGH    ] sensitive-data-exposure
             GET users/me
             The response body contains a field name that suggests secret
             material is being returned to the client.
             evidence: "password":

  Summary: critical: 2  high: 2  medium: 2  low: 3
```

## Use in CI

Exits `1` when any critical or high finding is present, so it can gate a
deployment:

```yaml
- name: API security checks
  run: python3 apitest.py staging-api.json --authorized
```

## Responsible use

Test only APIs you own or have written permission to assess. The rate-limit
check sends a small burst (12 requests by default) — it is a probe, not a load
test, and it is off unless you ask for it. The `--authorized` flag makes your
permission explicit.

## Tests

57 tests, 95% line coverage. No dependencies, and **no test contacts a
real external service** — network-facing code is exercised against local fake
servers bound to an ephemeral port.

```bash
# Run the suite
python3 -m unittest discover -s tests -v

# Fail on any leaked socket, file, or database connection
python3 -W error::ResourceWarning -m unittest discover -s tests
```

CI runs the suite on Python 3.10–3.13 on every push, plus a coverage gate and a
3.10 syntax check. See [.github/workflows/tests.yml](.github/workflows/tests.yml).

## License

MIT — see [LICENSE](LICENSE).
