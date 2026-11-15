# Quantitative Evaluation

The evaluation scripts implement the measurements defined in the thesis
methodology. Protocol measurements use a real Firefox instance and the Firefox
extension. Proof measurements call the RISC Zero backend directly. STWO remains
an additional implementation but is not part of the quantitative evaluation.
The default is 100 recorded runs per series plus one unmeasured warm-up run.

The step-by-step procedure for validating, importing, plotting, and
interpreting the resulting CSV data is provided in
[`BENCHMARK_ANALYSIS.md`](BENCHMARK_ANALYSIS.md).

## 1. Prerequisites

Set up the normal local runtime and the separate, pinned Selenium evaluation
runtime:

```powershell
.\setup-runtime.ps1
.\evaluation\setup-evaluation.ps1
```

Firefox must be installed. Selenium Manager obtains a compatible geckodriver
the first time the browser benchmark is started. Browser and driver startup are
completed before any measured operation.

The browser automation uses `.venv-evaluation`. Keeping this environment
separate is intentional: current Selenium releases require newer versions of
some packages than the DIDComm libraries in `.venv-didcomm` support.

The benchmark expects:

- an IdP user account;
- an accepted RP registration for RISC Zero;
- the IdP and RP DIDComm backends to both use RISC Zero;
- exactly one usable RP token grant for the Direct Login series (the evaluator
  creates one through an unmeasured preparation SSO flow if none exists);
- all services to run locally, as specified by the methodology.

## 2. Start the instrumented prototype

Use five terminals. Run the web services normally and enable the opt-in,
in-memory measurement endpoints on the three Python backends.

```powershell
# Terminal 1
cd RP
cargo run

# Terminal 2
cd RP\didcomm-backend
.\start.ps1 -Evaluation

# Terminal 3
cd IdP
cargo run

# Terminal 4
cd IdP\didcomm-backend
.\start.ps1 -Evaluation

# Terminal 5
cd firefox-extension\backend
.\start.ps1 -Evaluation
```

RISC Zero is the only proof backend used by this evaluation. It is the runtime
default. If `DIDSSO_PROOF_BACKEND` was set previously, remove it or set it to
`risc0` in both DIDComm backend terminals before starting them. The RP must have
an accepted RISC Zero registration credential.

Do not load the extension manually for the automated benchmark. Selenium starts
a clean Firefox profile and installs a temporary archive of the repository's
extension before the measurements begin.

## 3. Run the protocol measurements

Provide the existing IdP benchmark account through environment variables so the
password is not written to the command history:

```powershell
$env:DIDSSO_BENCH_EMAIL = "benchmark@example.com"
$env:DIDSSO_BENCH_PASSWORD = "replace-with-the-account-password"
.\evaluation\benchmark-protocol.ps1 -Scenario all -Runs 100 -WarmupRuns 1
```

The three protocol series are:

- `sso`: consent confirmation until the RP claims have been rendered;
- `direct-access`: DID login with a valid Access Token;
- `direct-refresh`: DID login after the evaluator has expired the RP's Access
  Token, forcing the Refresh Token path.

The Refresh Token endpoint returns both the rotated token pair and current
claims in the same response. The script validates the actual token branch for
every Direct Login run and aborts if it differs from the requested scenario.

The default headed browser mode should be used for the reported measurements.
`-Headless` is available for diagnostics, but those results must be identified
as headless-browser measurements.

The script uses one fresh Firefox profile for the complete invocation, disables
the browser caches, and preserves cookies and wallet state between its series.
Scenario order for `all` is SSO, Direct Access, then Direct Refresh. Only RISC
Zero is evaluated, so there is no proof-backend ordering. The protocol report
records the exact Firefox, geckodriver, Selenium, Python, platform, RISC Zero
backend, and scenario order; the proof report records Python, platform, and the
RISC Zero backend. No series-order randomization or cooldown is performed.

## 4. Run the proof measurements

```powershell
.\evaluation\benchmark-proofs.ps1 -Runs 100 -WarmupRuns 1
```

Compilation, credential construction, verifier startup, and warm-up runs are
recorded as excluded setup metadata. The 100 measured runs contain RISC Zero
proof generation and verification.

For every measured proof, the report records `receipt_size_bytes`, the size of
the Base64-decoded serialized RISC Zero receipt, and
`proof_envelope_size_bytes`, the UTF-8 size of the deterministically serialized
compact JSON proof envelope. The receipt size represents the proof artifact;
the envelope size additionally includes protocol metadata and Base64 overhead.
Neither value represents the size of the encrypted DIDComm message.

These are integrated RISC Zero backend measurements, not isolated
cryptographic-kernel benchmarks: they include the Python call, serialization,
file handling, WSL wrapper, and proof subprocesses. RISC Zero uses one
persistent verifier whose startup is excluded from the measured runs.

Both suites can be started sequentially with:

```powershell
.\evaluation\evaluate.ps1 -Suite all -Runs 100 -WarmupRuns 1
```

## 5. Measurement boundaries

Browser boundaries use `performance.timeOrigin + performance.now()`. Internal
durations use `time.perf_counter_ns()`. Cross-process events use Unix epoch
milliseconds because all components execute on the same experimental host.

The SSO start is captured in the IdP's Accept-button handler. The end is captured
after the RP has validated the session, loaded the account, updated the claims
DOM, and passed two animation frames. WebDriver's polling delay therefore does
not form part of the reported End-to-End duration.

The evaluator authenticates the benchmark account before the series. If the
one-hour IdP browser session expires during a long proof series, it submits the
same benchmark credentials again before the consent button is measured. This
re-authentication therefore remains outside the `t0`--`t_end` interval.

The current artifact has two competing navigation paths: the Firefox extension
polls every second, while the RP waiting page polls every 1.2 seconds. Both are
left unchanged. Every run records whether `extension` or `rp_session_poll`
actually initiated navigation. The extension-detection timestamp is retained
even when the RP page wins the race. Consequently:

- result-delivery latency ends at the actual navigation trigger;
- extension polling delay is reported separately;
- wallet-result validation latency includes delivery to the wallet backend and
  its validation/binding work; it is not interpreted as pure transport time;
- browser-processing latency runs from the actual navigation trigger until the
  claims are visibly rendered;
- the remaining time is labelled unattributed and is not interpreted as pure
  DIDComm time.

## 6. Results

Results are written after every completed run to `benchmark-results/`:

- JSON report containing metadata, raw runs, errors, and summaries;
- raw CSV with one row per run;
- summary CSV with count, mean, median, sample standard deviation, minimum, and
  maximum.

The protocol benchmark writes the JSON report and both CSV files. The RISC Zero
proof benchmark writes its raw values, setup metadata, errors, and summaries to
a JSON report. Partial results remain available if a later run fails or the
benchmark is cancelled. This applies to both the protocol and the potentially
long-running proof suite. Run order is retained because the prototype's JSON
state files grow during repeated flows and this may cause performance drift.

Only reports with `status` equal to `completed` and the requested number of
completed runs per series should be used for aggregate thesis results. The
reported standard deviation is the sample standard deviation.
