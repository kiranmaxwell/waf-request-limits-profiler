# FortiAppSec Cloud Request Limits Profiler

Turn a browser **HAR capture** of real application traffic into a ready-to-review Excel workbook of recommended **FortiAppSec Cloud → Request Limits** and **HTTP Allow Methods** settings.

Instead of guessing thresholds (and either breaking the app or leaving the control too loose), the profiler measures what the application actually sends and proposes values with a safety buffer.

Reference: [FortiAppSec Cloud — Request Limits](https://docs.fortinet.com/document/fortiappsec-cloud/latest/user-guide/219840/request-limits)

---

## Features

- Parses any standard HAR 1.2 file (Chrome, Edge, Firefox DevTools exports)
- Measures, per request:
  - Total header length, longest header name, longest header value
  - Number of cookies
  - Number of `Range` headers
  - Total URL (query string) parameter length
  - Total body parameter length (form fields only, file content excluded)
- Computes **Observed Max**, **P95**, and a **Recommended Value** (`Max × 1.5`, rounded up to a clean step)
- All summary values are **live Excel formulas** over a `Raw Data` sheet, so they are auditable and recalculate if the data is edited
- Built-in data-quality checks:
  - Warns when **0 cookies** were captured (usually means the capture stripped cookies)
  - Warns when too few requests carried a body to trust the body-length figure
- **HTTP Allow Methods** sheet showing which of FortiAppSec's checkbox methods were observed, with an allow / confirm / block recommendation for each

## Output workbook

| Sheet | Contents |
|---|---|
| **Recommended Config** | One row per Request Limits field: Observed Max, P95, Recommended Value, Unit, Sample Size, Notes, plus data-quality warnings |
| **HTTP Allow Methods** | Every FortiAppSec method checkbox, whether it was seen, request count, and recommendation |
| **Raw Data** | One row per captured request — the source for every formula |
| **About & Caveats** | Notes on how to use the report |

## Requirements

- Python 3.8+
- [openpyxl](https://pypi.org/project/openpyxl/)

```bash
pip install -r requirements.txt
```

## Usage

```bash
python fortiappsec_request_limits_profiler.py <capture.har> [--out report.xlsx] [--customer "Name"]
```

| Argument | Description |
|---|---|
| `har_file` | Path to the HAR capture (required) |
| `--out` | Output `.xlsx` path. Default: `<harname>_request_limits.xlsx` |
| `--customer` | Label shown in the report title. Default: the first request's domain |

Example:

```bash
python fortiappsec_request_limits_profiler.py app-session.har --out app_request_limits.xlsx --customer "Example Corp"
```

## Capturing a good HAR

1. Open the application in Chrome/Edge, press **F12** → **Network** tab.
2. Tick **Preserve log** and clear the existing list.
3. Log in and exercise the app thoroughly: searches, filters, large forms, uploads, downloads, PDF/media viewers — the largest requests matter most.
4. Right-click in the request list → **Save all as HAR (with content)**.

> Some browsers/versions export HARs with cookies or sensitive headers removed. If the report shows the 0-cookie warning, re-export with sensitive data included or verify cookie counts manually in DevTools.

## Recommended rollout

1. Run the profiler and review the **Recommended Config** sheet.
2. Apply the values in FortiAppSec Cloud with the action set to **Alert** only.
3. Monitor attack logs for false positives over a representative period.
4. Adjust thresholds, then switch to **Alert & Deny**.

The recommended values are a **starting point**, not a guaranteed-safe production configuration — a single capture cannot cover every path or user behaviour.

## ⚠️ Security note

HAR files contain **session cookies, auth tokens, and potentially personal data**. Never commit HAR files or generated reports to a repository. The included `.gitignore` excludes `*.har` and `*.xlsx` for this reason.

## License

Released under the [MIT License](LICENSE).

## Disclaimer

This is an independent community tool and is not affiliated with or endorsed by Fortinet. FortiAppSec is a trademark of Fortinet, Inc.
