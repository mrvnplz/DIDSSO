# Working with Benchmark Outputs

The published benchmark results are in
[`benchmark-results/`](../benchmark-results/). New runs write their reports to
the same directory by default. See
[Reproduce the Evaluation](EVALUATION.md) for the commands that generate them.

## Generated Files

| File | Contents |
| --- | --- |
| `protocol-<timestamp>.json` | Protocol report with run status, settings, measurements, and summaries. |
| `protocol-<timestamp>-raw.csv` | One row per measured protocol run. |
| `protocol-<timestamp>-summary.csv` | One row of summary statistics per scenario and metric. |
| `proofs-<timestamp>.json` | Separate proof benchmark report with generation and verification times, artifact sizes, and summaries. This benchmark does not generate CSVs. |

The three protocol files with the same timestamp belong to the same run of
the benchmark. Keep them together when comparing or sharing results.

## Open the CSV Files

In OpenOffice Calc, choose **File → Open** and select the CSV. In the
[Text Import dialog](https://wiki.openoffice.org/wiki/Documentation/AOO4_User_Guides/Getting_Started/Getting_Started_with_Calc/Open_and_Save_CSV_files),
use UTF-8, comma as the only separator, and a double quote (`"`) as the text
delimiter. Select English (USA) so that numbers with a decimal point are
imported correctly.

Use the raw CSV to inspect individual runs. In the summary CSV, filter
`scenario` and `metric` to find the rows you need. Save any edited spreadsheet
separately to keep the original CSVs unchanged.

## Check Completeness

Before using the results, open the matching JSON report and check that
`status` is `completed`, `errors` is empty, and each selected series contains
the expected number of measured runs (30 by default). Warm-ups are not
included in the reported measurements.
