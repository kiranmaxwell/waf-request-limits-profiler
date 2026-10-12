# WAF Request Limits Profiler

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)

An open-source, vendor-neutral tool that turns a browser **HAR capture** of real application traffic into recommended **HTTP request limit** thresholds and an **allowed HTTP methods** list, for any Web Application Firewall, reverse proxy or web server.

Instead of guessing limits (and either breaking the app or leaving the control too loose), the profiler measures what the application actually sends and proposes values with a safety buffer.

Works with any WAF that enforces request limits: cloud WAFs, appliance WAFs, ModSecurity / OWASP Core Rule Set, NGINX, Apache httpd, and others.

---

## Features

- Parses any standard HAR 1.2 file (Chrome, Edge, Firefox, Safari DevTools exports)
- Measures 14 request characteristics per request:

  | Limit | Unit |
  |---|---|
  | URL length (path + query string) | Bytes |
  | Request line length | Bytes |
  | Number of request headers | Count |
  | Total header length | Bytes |
  | Header name length | Bytes |
  | Header value length | Bytes |
  | Number of cookies | Count |
  | Number of ranges in `Range` header | Count |
  | Number of arguments (query + body) | Count |
  | Argument name length | Bytes |
  | Argument value length | Bytes |
  | Total URL parameter length | Bytes |
  | Total body parameter length (file content excluded) | Bytes |
  | Request body size | Bytes |

- Computes **Observed Max**, **P95** and a **Recommended Value** (`max × buffer`, rounded up to a clean step)
- Summary values are **live Excel formulas** over the raw data, so they are auditable and recalculate if you edit the data
- **WAF Mapping** sheet: where each limit lives in OWASP CRS / ModSecurity, NGINX and Apache httpd
- **HTTP Methods** sheet: standard, WebDAV and non-standard methods with allow / confirm / block recommendations
- Built-in data-quality checks (cookies stripped from the capture, too few requests with a body)
- Optional **JSON output** for automation and policy-as-code pipelines
- HTTP/2 pseudo-headers are excluded so header metrics reflect real headers

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/kiranmaxwell/waf-request-limits-profiler.git
cd waf-request-limits-profiler
pip install -r requirements.txt
```

## Usage

```bash
python waf_request_limits_profiler.py <capture.har> [options]
```

| Option | Description |
|---|---|
| `har_file` | Path to the HAR capture (required) |
| `--out PATH` | Output `.xlsx` path. Default: `<harname>_request_limits.xlsx` |
| `--site NAME` | Label shown in the report title. Default: the first request's domain |
| `--buffer N` | Safety multiplier on the observed max. Default: `1.5` |
| `--json PATH` | Also write recommended limits and observed methods to a JSON file |
| `--version` | Print the version |

Examples:

```bash
# Basic report
python waf_request_limits_profiler.py app-session.har

# Named report with a larger safety margin and JSON output
python waf_request_limits_profiler.py app-session.har --out app_limits.xlsx --site "Example App" --buffer 2 --json app_limits.json
```

A summary table is also printed to the console.

## Output workbook

| Sheet | Contents |
|---|---|
| **Recommended Limits** | One row per limit: Observed Max, P95, Recommended Value, Unit, Sample Size, Notes, plus data-quality warnings |
| **WAF Mapping** | Recommended values alongside the equivalent OWASP CRS / ModSecurity, NGINX and Apache httpd settings |
| **HTTP Methods** | Every standard and WebDAV method (plus any non-standard ones seen), observed count and recommendation |
| **Raw Data** | One row per captured request; the source for every formula |
| **About & Caveats** | Rollout guidance and known limitations |

## Applying the results to your WAF

Request limits go by different names depending on the product: *HTTP protocol constraints*, *request limits*, *HTTP protocol validation*, *size restrictions* and so on. The **WAF Mapping** sheet covers common open-source options directly:

| Limit | OWASP CRS / ModSecurity | NGINX | Apache httpd |
|---|---|---|---|
| Request line / URL length | - | `large_client_header_buffers` | `LimitRequestLine` |
| Number of headers | - | - | `LimitRequestFields` |
| Header size | - | `large_client_header_buffers` | `LimitRequestFieldSize` |
| Number of ranges | - | `max_ranges` | `MaxRanges` |
| Number of arguments | `tx.max_num_args` | - | - |
| Argument name length | `tx.arg_name_length` | - | - |
| Argument value length | `tx.arg_length` | - | - |
| Total argument length | `tx.total_arg_length` | - | - |
| Request body size | `SecRequestBodyLimit` | `client_max_body_size` | `LimitRequestBody` |

For commercial and cloud WAFs, find the equivalent fields in your product's request-limit / protocol-constraint settings and enter the values from the **Recommended Limits** sheet. Contributions adding mappings for more products are welcome (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Capturing a good HAR

1. Open the application in your browser and press **F12** → **Network** tab.
2. Tick **Preserve log** and clear the existing list.
3. Log in and use the app thoroughly: searches, filters, large forms, uploads, downloads, PDF/media viewers. The largest requests matter most.
4. Right-click the request list → **Save all as HAR (with content)** (wording varies by browser).

> Some browsers export HARs with cookies or sensitive headers removed. If the report shows the 0-cookie warning, re-export with sensitive data included or verify cookie counts in DevTools.

## Recommended rollout

1. Run the profiler and review the **Recommended Limits** sheet.
2. Apply the values in your WAF in **detect / log-only (monitor)** mode.
3. Watch the logs for false positives over a representative period.
4. Adjust any limits legitimate traffic hits, then switch to **blocking**.

The recommended values are a **starting point**. A single capture cannot cover every path, user or integration.

## Security note

HAR files contain **session cookies, auth tokens and potentially personal data**. Never commit HAR files or generated reports to a repository; the included `.gitignore` excludes `*.har` and `*.xlsx` for this reason. Store captures securely and delete them when you are done.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE). Free to use, modify and distribute, including commercially.
