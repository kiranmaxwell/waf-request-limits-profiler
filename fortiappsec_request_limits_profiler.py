#!/usr/bin/env python3
"""
FortiAppSec Cloud Request Limits Profiler

Profiles a browser HAR capture and produces an Excel workbook with
recommended FortiAppSec Cloud "Request Limits" and "HTTP Allow Methods"
settings derived from real traffic.

Usage:
    python fortiappsec_request_limits_profiler.py capture.har --out report.xlsx --customer "Example Corp"
"""

import argparse
import json
import math
import os
import statistics
from collections import Counter
from urllib.parse import urlparse

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

DOC_URL = "https://docs.fortinet.com/document/fortiappsec-cloud/latest/user-guide/219840/request-limits"

FONT = "Arial"
NAVY = "1F2A44"
GREEN = "1E7B34"
AMBER = "8A5A00"
RED = "B00020"

HEADER_FILL = PatternFill("solid", fgColor=NAVY)
HEADER_FONT = Font(name=FONT, size=10, bold=True, color="FFFFFF")
TITLE_FONT = Font(name=FONT, size=16, bold=True, color=NAVY)
SUBTITLE_FONT = Font(name=FONT, size=10, italic=True, color="666666")
LABEL_FONT = Font(name=FONT, size=10, bold=True)
BODY_FONT = Font(name=FONT, size=10)
NOTE_FONT = Font(name=FONT, size=9, italic=True, color="666666")
THIN = Side(style="thin", color="D0D5DD")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

# Every HTTP verb FortiAppSec Cloud's "HTTP Allow Methods" list exposes as a
# checkbox. Verbs with no standard client-side trigger (TRACE, CONNECT,
# WEBDAV, RPC, OTHERS) will almost never show up in a browser HAR even on
# apps that need them server-to-server — that's flagged, not treated as
# "definitely block".
DOC_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
               "TRACE", "CONNECT", "RPC", "WEBDAV", "OTHERS"]
COMMON_WEB_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


# ---------------------------------------------------------------------------
# HAR parsing helpers
# ---------------------------------------------------------------------------

def header_value(entry, side, name):
    for h in entry[side]["headers"]:
        if h["name"].lower() == name.lower():
            return h["value"]
    return None


def domain_of(url):
    return urlparse(url).netloc


def nice_round_up(n, step):
    """Round a number up to the nearest multiple of `step` — gives clean,
    typeable threshold values (e.g. 8192 instead of 7,911)."""
    if n <= 0:
        return step
    return int(math.ceil(n / step) * step)


def extract_request_metrics(entry):
    req = entry["request"]
    headers = req.get("headers", [])

    # --- Header size metrics -------------------------------------------------
    # Approximate the raw wire size of "name: value\r\n" per header line.
    total_header_bytes = sum(len(h["name"]) + 2 + len(h["value"]) + 2 for h in headers)
    max_header_name_len = max((len(h["name"]) for h in headers), default=0)
    max_header_value_len = max((len(h["value"]) for h in headers), default=0)

    # --- Cookie count ----------------------------------------------------------
    cookies = req.get("cookies") or []
    if cookies:
        cookie_count = len(cookies)
    else:
        cookie_header = header_value(entry, "request", "Cookie")
        cookie_count = len([c for c in cookie_header.split(";") if c.strip()]) if cookie_header else 0

    # --- Range header count ------------------------------------------------
    range_header_count = sum(1 for h in headers if h["name"].lower() == "range")

    # --- URL (query string) parameter length --------------------------------
    query = req.get("queryString", []) or []
    url_param_bytes = sum(len(q.get("name", "")) + len(q.get("value", "")) for q in query)

    # --- Body parameter length (form fields only, not file content) -------
    post_data = req.get("postData", {})
    body_params = [p for p in (post_data.get("params") or []) if not p.get("fileName")]
    body_files = [p for p in (post_data.get("params") or []) if p.get("fileName")]
    # None (not 0) when the request has no body at all — a GET has no body
    # by definition, and that's a different thing from "a POST with an empty
    # body". Mixing the two into one 0 would drag Max/P95 toward zero across
    # a mostly-GET capture and understate what real POSTs actually send.
    has_body = bool(post_data and (post_data.get("params") or post_data.get("text")))
    body_param_bytes = (sum(len(p.get("name", "")) + len(p.get("value") or "") for p in body_params)
                         if has_body else None)
    raw_body_bytes = len(post_data.get("text") or "") if has_body else None

    return {
        "url": req["url"],
        "method": req["method"],
        "domain": domain_of(req["url"]),
        "total_header_bytes": total_header_bytes,
        "max_header_name_len": max_header_name_len,
        "max_header_value_len": max_header_value_len,
        "cookie_count": cookie_count,
        "range_header_count": range_header_count,
        "url_param_bytes": url_param_bytes,
        "body_param_bytes": body_param_bytes,
        "raw_body_bytes": raw_body_bytes,
        "has_file_upload": bool(body_files),
    }


# ---------------------------------------------------------------------------
# Workbook building
# ---------------------------------------------------------------------------

def style_header_row(ws, row, ncols):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.border = BORDER
        cell.alignment = Alignment(vertical="center", wrap_text=True)


def autosize(ws, widths):
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w


def title_block(ws, title, subtitle):
    ws["A1"] = title
    ws["A1"].font = TITLE_FONT
    ws["A2"] = subtitle
    ws["A2"].font = SUBTITLE_FONT
    ws.row_dimensions[1].height = 24
    ws.row_dimensions[2].height = 16


def build_workbook(metrics, customer_name, har_path, out_path):
    n = len(metrics)
    wb = Workbook()

    # ---- Raw Data sheet: one row per request, feeds every formula below ----
    raw = wb.active
    raw.title = "Raw Data"
    cols = ["#", "Method", "URL", "Domain", "Total Header Bytes",
            "Max Header Name Len", "Max Header Value Len", "Cookie Count",
            "Range Header Count", "URL Param Bytes", "Body Param Bytes",
            "Raw Body Bytes", "Has File Upload"]
    raw.append(cols)
    style_header_row(raw, 1, len(cols))
    for i, m in enumerate(metrics):
        raw.append([
            i, m["method"], m["url"], m["domain"], m["total_header_bytes"],
            m["max_header_name_len"], m["max_header_value_len"], m["cookie_count"],
            m["range_header_count"], m["url_param_bytes"], m["body_param_bytes"],
            m["raw_body_bytes"], m["has_file_upload"],
        ])
    for r in range(2, n + 2):
        for c in range(1, len(cols) + 1):
            raw.cell(row=r, column=c).font = BODY_FONT
            raw.cell(row=r, column=c).border = BORDER
    raw.freeze_panes = "A2"
    autosize(raw, [6, 8, 60, 22, 16, 16, 16, 12, 14, 14, 14, 14, 12])
    last_row = n + 1

    def col_letter(name):
        return get_column_letter(cols.index(name) + 1)

    # ---- Summary sheet: the actual Request Limits config recommendation ---
    ws = wb.create_sheet("Recommended Config", 0)
    title_block(ws, f"FortiAppSec Cloud — Request Limits: {customer_name}",
                f"Derived from {os.path.basename(har_path)}  ({n} requests captured)  |  Source: {DOC_URL}")

    headers_row = 4
    field_cols = ["Request Limits Field", "Observed Max", "Observed P95",
                  "Recommended Value", "Unit", "Sample Size", "Notes"]
    for i, h in enumerate(field_cols, start=1):
        ws.cell(row=headers_row, column=i, value=h)
    style_header_row(ws, headers_row, len(field_cols))

    def data_col(metric_col_name):
        return f"'Raw Data'!${col_letter(metric_col_name)}$2:${col_letter(metric_col_name)}${last_row}"

    # buffer used for the "Recommended Value" column — generous enough to
    # absorb normal variance the capture didn't happen to include, tight
    # enough to still be a meaningful control.
    BUFFER_MULT = 1.5

    rows_spec = [
        ("Header Length (total, all headers combined)", "Total Header Bytes", 512,
         "Blocks requests whose combined header block exceeds this. Watch auth/bearer tokens and long referrers — they inflate this fast."),
        ("Header Name Length", "Max Header Name Len", 16,
         "Custom headers with long names (e.g. long X-... headers from a CDN/proxy) will push this up."),
        ("Header Value Length", "Max Header Value Len", 512,
         "Cookies bundled into a single Set-Cookie/Cookie header, long JWTs, and long User-Agent/Referer strings are the usual drivers."),
        ("Number of Cookies in Request", "Cookie Count", 5,
         "Analytics/tracking cookies (GA, ad-tech, session, CSRF, language, theme, etc.) add up quickly — this is very often the tightest real constraint."),
        ("Number of Ranges in Range Header", "Range Header Count", 1,
         "Almost always 0 or 1 for normal browsing; media/PDF viewers and download managers use multi-range requests."),
        ("Total URL Parameter Length", "URL Param Bytes", 128,
         "Search boxes, filter/sort UIs, and deep-link state stored in the query string drive this up."),
        ("Total Body Parameters Length", "Body Param Bytes", 512,
         "Excludes uploaded file content (that's a separate upload-size control) — only form field names+values."),
    ]

    metric_rows = {}  # label -> row number, so we can build warnings below that reference these cells
    r = headers_row
    for label, metric_col, round_step, note in rows_spec:
        r += 1
        metric_rows[label] = r
        rng = data_col(metric_col)
        ws.cell(row=r, column=1, value=label).font = BODY_FONT
        max_cell = ws.cell(row=r, column=2, value=f"=MAX({rng})")
        p95_cell = ws.cell(row=r, column=3, value=f"=PERCENTILE({rng},0.95)")
        # Recommended = max observed * buffer, rounded up to a clean step.
        # ROUNDUP(x/step,0)*step gives a tidy, human-typeable number.
        rec_formula = f"=ROUNDUP((B{r}*{BUFFER_MULT})/{round_step},0)*{round_step}"
        rec_cell = ws.cell(row=r, column=4, value=rec_formula)
        ws.cell(row=r, column=5, value="Bytes" if "Length" in label or "Header" in label and "Number" not in label else "Count").font = BODY_FONT
        sample_cell = ws.cell(row=r, column=6, value=f"=COUNT({rng})")
        ws.cell(row=r, column=7, value=note).font = NOTE_FONT
        for c in range(1, 8):
            ws.cell(row=r, column=c).border = BORDER
            ws.cell(row=r, column=c).alignment = Alignment(wrap_text=True, vertical="top")
        max_cell.font = BODY_FONT
        p95_cell.font = BODY_FONT
        sample_cell.font = BODY_FONT
        rec_cell.font = Font(name=FONT, size=10, bold=True, color=GREEN)
        ws.row_dimensions[r].height = 42

    note_row = r + 2
    ws.cell(row=note_row, column=1,
            value=(f"Recommended Value = ROUNDUP(Observed Max x {BUFFER_MULT}, nearest clean step). "
                   "This is a starting point for staging in Alert-only mode, not a final production value — "
                   "see 'About & Caveats'."))
    ws.cell(row=note_row, column=1).font = NOTE_FONT
    ws.merge_cells(start_row=note_row, start_column=1, end_row=note_row, end_column=7)
    ws.cell(row=note_row, column=1).alignment = Alignment(wrap_text=True)

    # ---- Data-quality warnings — formula-driven, so they self-update if the
    # Raw Data sheet is ever swapped for a different customer's export -----
    cookie_row = metric_rows["Number of Cookies in Request"]
    warn_row = note_row + 2
    ws.cell(row=warn_row, column=1, value="Data quality checks").font = LABEL_FONT
    warn_row += 1
    cookie_warn_formula = (
        f'=IF(B{cookie_row}=0,'
        f'"WARNING: 0 cookies observed across every request in this capture. Real browser sessions to an '
        f'authenticated app almost always carry at least a session cookie — this usually means the capture '
        f'tool stripped Cookie/Set-Cookie headers before they reached this HAR, not that the app truly sets '
        f'none. Do NOT configure \'Number of Cookies in Request\' as 0 off this number — re-capture with '
        f'cookie recording confirmed on, or verify manually in the browser dev tools first.",'
        f'"OK — cookies were observed; the recommended value above reflects real traffic.")'
    )
    ws.cell(row=warn_row, column=1, value=cookie_warn_formula)
    ws.cell(row=warn_row, column=1).font = Font(name=FONT, size=10, bold=True, color=RED)
    ws.merge_cells(start_row=warn_row, start_column=1, end_row=warn_row, end_column=7)
    ws.cell(row=warn_row, column=1).alignment = Alignment(wrap_text=True)
    ws.row_dimensions[warn_row].height = 42

    warn_row += 1
    body_row = metric_rows["Total Body Parameters Length"]
    low_sample_formula = (
        f'=IF(F{body_row}<5,'
        f'"NOTE: Only "&F{body_row}&" request(s) in this capture actually carried a body — the Max/Recommended '
        f'figures for \'Total Body Parameters Length\' are based on that small a sample. Capture more real '
        f'form/API submissions (ideally the largest ones the app supports) before treating this as final.",'
        f'"OK — based on "&F{body_row}&" requests with a body.")'
    )
    ws.cell(row=warn_row, column=1, value=low_sample_formula)
    ws.cell(row=warn_row, column=1).font = Font(name=FONT, size=10, bold=True, color=AMBER)
    ws.merge_cells(start_row=warn_row, start_column=1, end_row=warn_row, end_column=7)
    ws.cell(row=warn_row, column=1).alignment = Alignment(wrap_text=True)
    ws.row_dimensions[warn_row].height = 42

    autosize(ws, [34, 14, 14, 16, 10, 12, 46])
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True

    # ---- HTTP Allow Methods sheet ------------------------------------------
    ws2 = wb.create_sheet("HTTP Allow Methods")
    title_block(ws2, "HTTP Allow Methods", f"Which of FortiAppSec Cloud's checkbox methods this traffic actually used")
    method_counts = Counter(m["method"] for m in metrics)
    r0 = 4
    mcols = ["Method", "Observed in capture", "Request count", "Recommendation"]
    for i, c in enumerate(mcols, start=1):
        ws2.cell(row=r0, column=i, value=c)
    style_header_row(ws2, r0, len(mcols))
    r = r0
    for method in DOC_METHODS:
        r += 1
        seen = method_counts.get(method, 0)
        ws2.cell(row=r, column=1, value=method).font = BODY_FONT
        ws2.cell(row=r, column=2, value=(seen > 0)).font = BODY_FONT
        ws2.cell(row=r, column=3, value=seen).font = BODY_FONT
        if seen > 0:
            rec, color = "Allow — observed in traffic", GREEN
        elif method in COMMON_WEB_METHODS:
            rec, color = "Not observed here — confirm with app team before allowing", AMBER
        else:
            rec, color = "Not observed — leave blocked unless a specific integration needs it", RED
        cell = ws2.cell(row=r, column=4, value=rec)
        cell.font = Font(name=FONT, size=10, bold=True, color=color)
        for c in range(1, 5):
            ws2.cell(row=r, column=c).border = BORDER
    # methods seen in the capture but not in Fortinet's fixed checkbox list
    unlisted = set(method_counts) - set(DOC_METHODS)
    for method in sorted(unlisted):
        r += 1
        ws2.cell(row=r, column=1, value=method).font = BODY_FONT
        ws2.cell(row=r, column=2, value=True).font = BODY_FONT
        ws2.cell(row=r, column=3, value=method_counts[method]).font = BODY_FONT
        ws2.cell(row=r, column=4, value="Not one of the fixed checkboxes — falls under 'OTHERS'").font = Font(name=FONT, size=10, bold=True, color=AMBER)
        for c in range(1, 5):
            ws2.cell(row=r, column=c).border = BORDER
    autosize(ws2, [14, 18, 14, 52])
    ws2.page_setup.orientation = "landscape"
    ws2.page_setup.fitToWidth = 1
    ws2.page_setup.fitToHeight = 0
    ws2.sheet_properties.pageSetUpPr.fitToPage = True

    # ---- About & Caveats sheet ----------------------------------------------
    ws3 = wb.create_sheet("About & Caveats")
    title_block(ws3, "About this report", "Read this before configuring anything from the 'Recommended Config' tab")
    lines = [

    ]
    r = 4
    for line in lines:
        is_heading = line and not line.startswith("-") and line[0].isupper() and len(line) < 70 and not line.endswith(".")
        cell = ws3.cell(row=r, column=1, value=line)
        cell.font = Font(name=FONT, size=11, bold=True, color=NAVY) if is_heading else BODY_FONT
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws3.row_dimensions[r].height = 14 if not line else 30
        r += 1
    ws3.column_dimensions["A"].width = 118
    ws3.page_setup.orientation = "landscape"
    ws3.page_setup.fitToWidth = 1
    ws3.page_setup.fitToHeight = 0
    ws3.sheet_properties.pageSetUpPr.fitToPage = True

    wb.save(out_path)
    return out_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("har_file", help="path to the customer's HAR capture")
    ap.add_argument("--out", default=None, help="output .xlsx path (default: <harname>_request_limits.xlsx)")
    ap.add_argument("--customer", default=None, help="customer/site label shown in the report title")
    args = ap.parse_args()

    with open(args.har_file, encoding="utf-8") as f:
        har = json.load(f)
    entries = har["log"]["entries"]
    metrics = [extract_request_metrics(e) for e in entries]

    if not metrics:
        raise SystemExit("No requests found in this HAR — nothing to profile.")

    out_path = args.out or (os.path.splitext(os.path.basename(args.har_file))[0] + "_request_limits.xlsx")
    customer_name = args.customer or domain_of(metrics[0]["url"]) or "Customer"

    build_workbook(metrics, customer_name, args.har_file, out_path)
    print(f"{len(metrics)} requests profiled -> {out_path}")


if __name__ == "__main__":
    main()
