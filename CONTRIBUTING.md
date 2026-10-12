# Contributing

Thanks for your interest in improving WAF Request Limits Profiler. Bug reports, new WAF mappings, new metrics and documentation fixes are all welcome.

## Reporting bugs

Open an issue with:

- What you ran (command and options)
- What you expected and what happened (error output or a screenshot of the report)
- Python and `openpyxl` versions, and which browser produced the HAR

**Never attach a real HAR file.** HAR captures contain session cookies, tokens and personal data. If a capture is needed to reproduce a bug, build a minimal synthetic HAR with fake values instead.

## Adding a WAF mapping

The mapping for each limit lives in the `LIMITS` list in `waf_request_limits_profiler.py`. To add a product:

1. Add a key for it to each entry's mapping dict (use `"-"` when the product has no equivalent setting).
2. Add the column to the **WAF Mapping** sheet in `build_workbook`.
3. Update the mapping table in `README.md`.
4. In the pull request, link the product documentation for each setting you mapped.

## Adding a metric

1. Compute it in `extract_request_metrics`.
2. Add an entry to `LIMITS` (key, label, unit, rounding step, body-only flag, note, mapping).

The Raw Data columns, summary formulas and JSON output all pick up new `LIMITS` entries automatically.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep changes focused; one feature or fix per pull request.
3. Run the profiler against a synthetic HAR and open the generated workbook to check it.
4. Describe what changed and why.

## Code style

- Python 3.8+ compatible, standard library plus `openpyxl` only
- Follow PEP 8 and keep functions small and commented where the intent isn't obvious

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
