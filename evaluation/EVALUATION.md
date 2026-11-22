# Reproduce the Evaluation

Use the native Windows setup with RISC Zero in WSL 2. The protocol benchmark
measures Privacy-Enhanced SSO and Direct DID-Based Login with either a valid
access token or a token refresh. The separate proof benchmark measures RISC
Zero proof generation, verification, and artifact sizes.

- [Prepare the environment](#prepare-the-environment)
- [Start the instrumented prototype](#start-the-instrumented-prototype)
- [Run the benchmarks](#run-the-benchmarks)
- [Find the results](#find-the-results)
- [Troubleshooting](#troubleshooting)

## Prepare the Environment

Follow the [native Windows guide](../docs/NATIVE_SETUP_WINDOWS.md) to install
the prerequisites, prepare the Python environments, and build the RISC Zero
host in WSL 2. For the protocol benchmark, also install the separate Selenium
environment from the repository root:

```powershell
.\evaluation\setup-evaluation.ps1
```

Use test data. The protocol benchmark can create or update an RP account and
deliberately expires access tokens for the refresh scenario. Do not run the
native and Docker setups at the same time.

## Start the Instrumented Prototype

For the protocol benchmark, start each service in a separate PowerShell
terminal from the repository root. Use `-Evaluation` on all three Python
backends, not on the Rust web applications.

| Service | Commands |
| --- | --- |
| IdP protocol backend | `.\IdP\didcomm-backend\start.ps1 -Evaluation` |
| RP protocol backend | `.\RP\didcomm-backend\start.ps1 -Evaluation` |
| Wallet backend | `.\firefox-extension\backend\start.ps1 -Evaluation` |
| IdP web application | `Set-Location IdP`, then `cargo run --locked` |
| RP web application | `Set-Location RP`, then `cargo run --locked` |

Both protocol backends must use RISC Zero (`risc0`), the default. If you
previously set `DIDSSO_PROOF_BACKEND` to `stwo`, unset it or set it to
`risc0` in both backend terminals before starting them.

Once the services are running, create a test account at the
[IdP](https://127.0.0.1:3001) and complete the
[RP registration](../README.md#using-the-prototype). Confirm that the request
appears under Accepted requests in RP Admin. You do not need to sign in to
the RP or load the extension manually: Selenium opens a fresh Firefox profile
and loads the extension itself.

## Run the Benchmarks

From a new PowerShell terminal at the repository root, run both benchmarks
in sequence:

```powershell
.\evaluation\evaluate.ps1 -Suite all -Runs 30 -WarmupRuns 1
```

Enter the test account's email and password when prompted. The script uses
`DIDSSO_BENCH_EMAIL` and `DIDSSO_BENCH_PASSWORD` instead if they are already
set. The defaults are 30 measured runs and one unmeasured warm-up per series.
The [published runs](../benchmark-results/) took about an hour in total on the
reference machine, excluding installation and compilation.

To run the benchmarks separately:

```powershell
.\evaluation\benchmark-protocol.ps1 -Scenario all -Runs 30 -WarmupRuns 1
.\evaluation\benchmark-proofs.ps1 -Runs 30 -WarmupRuns 1
```

Leave Firefox in its default visible mode when reproducing the published
protocol measurements. The proof-only command needs the native DIDComm
Python environment and the RISC Zero host in WSL, but no browser, running
services, IdP account, or RP registration.

## Find the Results

The reports are saved in [`benchmark-results/`](../benchmark-results/) by
default. See [Working with Benchmark Outputs](BENCHMARK_ANALYSIS.md) for
the file formats, CSV import, and how to check that a report is complete.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| An evaluation endpoint is unavailable. | Check that the named Python backend is running and was started with `-Evaluation`. |
| The RP has no accepted IdP credential for RISC0. | Check approval in IdP Admin, the configured IdP HTTPS origin, and that both backends use `risc0`. |
| Direct login reports more than one usable token grant. | Use a dedicated test state. Direct-login measurements require exactly one usable grant; if there is none when starting the benchmark, the script prepares one through an unmeasured SSO. |
| The proof tool fails to start. | Run the `method-id` check in the [native WSL setup](../docs/NATIVE_SETUP_WINDOWS.md#build-the-risc-zero-proof-tool). |

For errors shown by the prototype itself, see the
[prototype troubleshooting guide](../docs/TROUBLESHOOTING.md).
