# Native Setup on Windows

Run the prototype from source without Docker. The IdP and RP web applications,
their Python protocol backends, and the Python wallet backend run on Windows.
Only the RISC Zero proof tooling runs inside WSL 2.

- [Requirements for native setup](#requirements-for-native-setup)
- [Prepare the Python environments](#prepare-the-python-environments)
- [Build the RISC Zero proof tool](#build-the-risc-zero-proof-tool)
- [Start the services](#start-the-services)
- [Set up Firefox and sign in](#set-up-firefox-and-sign-in)
- [Stop or reset the native setup](#stop-or-reset-the-native-setup)
- [Troubleshooting](#troubleshooting)

## Requirements for Native Setup

The native protocol ran on Windows 11 (x86-64) with Python 3.11.9,
Firefox 160.0, and RISC Zero. These are reference versions, not minimum
requirements. If you run into compatibility issues, try the recorded versions
first. See the [evaluation guide](../evaluation/EVALUATION.md) for benchmark
setup and execution.

| Component | What you need |
| --- | --- |
| Windows PowerShell | Run the setup and start scripts in PowerShell on Windows. |
| Git | Make `git` available on PATH. Some Python dependencies are installed from Git repositories. |
| Python | Install 64-bit Python 3.11 with the Windows launcher so `py -3.11` works. |
| Rust and Cargo on Windows | Install stable Rust via `rustup` and the MSVC C++ build tools. See [Microsoft's Rust setup guide](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup). |
| WSL 2 with a Linux distribution | Use an x86-64 distribution such as Ubuntu. Install a separate Linux Rust toolchain and RISC Zero tools as described below. |
| Firefox | Install Firefox on Windows. The extension is loaded from the local checkout. |

Open a new PowerShell terminal after installing the Windows tools and check
that `git --version`, `py -3.11 --version`, and `cargo --version` run.

## Prepare the Python Environments

In PowerShell, clone the repository if you do not already have it, then run
the setup script from its root:

```powershell
git clone https://github.com/mrvnplz/DIDSSO.git
Set-Location DIDSSO
.\setup-runtime.ps1
```

The script creates `.venv-didcomm` for the IdP and RP and a separate
`firefox-extension\.venv` for the wallet backend. The start scripts select
these interpreters automatically; no manual activation is needed. If setup
succeeds, the script reports that both runtimes are ready. Run it again after
updating dependencies.

## Build the RISC Zero Proof Tool

If WSL is not installed, follow [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
and finish the initial Linux user setup. From PowerShell, use
`wsl.exe --list --verbose` to check that the default distribution (marked
with `*`) is listed as version `2`. The prototype's wrapper uses this default
distribution, so install the tools there.

Run `wsl.exe` from the repository root to open a Linux shell in the checkout.
Install the Linux build dependencies. On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential ca-certificates clang cmake curl git \
  libssl-dev ninja-build pkg-config protobuf-compiler
```

Install Rust with [rustup for Linux](https://rust-lang.org/tools/install/)
inside WSL, then install `rzup` using the
[RISC Zero installation guide](https://dev.risczero.com/api/zkvm/install).
Use the tool versions pinned in the
[repository's RISC Zero build recipe](../docker/didcomm-risc0.Dockerfile):

```bash
rzup install rust 1.97.0
rzup install cpp 2024.1.5
rzup install cargo-risczero 3.0.6
rzup install r0vm 3.0.6
```

In the same Linux shell, change into the proof workspace and build the host
binary, which also builds the guest. Run this block in WSL Bash, not at a
`PS C:\...` prompt. If you prefer to stay in PowerShell, use the
[explicit WSL build command](../zk-risc0/README.md#rebuild-the-proof-host).

```bash
cd zk-risc0
cargo build --release --locked -p host
exit
```

Back in PowerShell at the repository root, verify that the Windows wrapper
can run the Linux binary:

```powershell
.\zk-risc0\risc0_wsl.cmd method-id
```

This should print the compiled guest's method identifier. The first build
can take several minutes. The wrapper can build a missing binary, but
will not rebuild an existing one after source changes. To refresh it, run
the WSL build command again. The rest of this guide uses the default
RISC Zero backend on both the IdP and RP.

## Start the Services

Stop the Docker setup first if it is running; the two setups use the same
host ports. Open five PowerShell terminals, each starting at the repository
root. Run each row in its own terminal and leave it running.

| Service | Commands | Default local address |
| --- | --- | --- |
| IdP protocol backend | `.\IdP\didcomm-backend\start.ps1` | `http://127.0.0.1:8770` |
| RP protocol backend | `.\RP\didcomm-backend\start.ps1` | `http://127.0.0.1:8771` |
| Wallet backend | `.\firefox-extension\backend\start.ps1` | `http://127.0.0.1:8765` |
| IdP web application | `Set-Location IdP`, then `cargo run --locked` | <https://127.0.0.1:3001> |
| RP web application | `Set-Location RP`, then `cargo run --locked` | <http://127.0.0.1:3002> |

Wait for the backends to report that they are listening and for both web
pages to open. The IdP protocol backend starts its verifier during startup.
The first Cargo build of each web application can also take a few minutes.

## Set Up Firefox and Sign In

1. In Firefox, open `about:debugging#/runtime/this-firefox`. Choose **Load
   Temporary Add-on** and select
   [`firefox-extension/manifest.json`](../firefox-extension/manifest.json) from
   your local clone.
2. Open the extension from the Firefox toolbar. **Wallet loaded.** confirms
   that the wallet backend is reachable, even if no DIDs are listed yet.
   If you see **Could not reach the DID service.**, check that the backend is
   running in its PowerShell terminal.
3. Open the IdP at <https://127.0.0.1:3001> and the RP at
   <http://127.0.0.1:3002>. Accept the self-signed certificate warning
   for the local IdP.
4. Follow [Using the Prototype](../README.md#using-the-prototype) to create an
   IdP account, register the RP, and try Privacy-Enhanced SSO followed by
   Direct DID-Based Login. The steps are the same for Docker and native setups.

Reload the temporary add-on after restarting Firefox.

## Stop or Reset the Native Setup

Press **Ctrl+C** in each of the five service terminals to stop the prototype.
An ordinary restart preserves data stored in `IdP\data`, `RP\data`, and
`firefox-extension\data`.

**Reset only if you intend to discard your native test state.** Stop all five
services first. From the repository root, preview the reset targets without
changing files:

```powershell
.\reset-state.ps1 -ValidateOnly
```

If those are the intended targets, run:

```powershell
.\reset-state.ps1
```

This resets native test accounts, wallet keys, registrations, token grants,
and the RP scope configuration. It does not reset Docker volumes or Firefox
extension storage. For a clean browser state as well, use a fresh Firefox
profile and load the extension again. After restarting the services, create
a test user and register the RP with the IdP's newly displayed Master DID.

If you changed the data directories, provide the corresponding
`-IdpDataDir`, `-RpDataDir`, and `-WalletDataDir` arguments when running the
reset script. The IdP web application and protocol backend must share the
same IdP data directory.

## Troubleshooting

This section covers preparing and starting the Windows services. Once they are
running, use the [prototype troubleshooting guide](TROUBLESHOOTING.md) for
errors in Firefox, RP registration, or sign-in.

| Symptom | What to check |
| --- | --- |
| `DIDComm runtime not found` or the wallet runtime is missing. | Check `py -3.11 --version` and rerun `.\setup-runtime.ps1` from the repository root. The setup creates two environments. An existing `DIDSSO_PYTHON` override affects only the IdP and RP backends; the wallet always uses its separate environment. |
| Building the proof host gives `LNK2019` or `LNK1120`, or Windows asks how to open `target/release/host`. | Build and run the Linux host in WSL, not directly in PowerShell. Close any file-opening dialog and use the [WSL build and check commands](../zk-risc0/README.md#rebuild-the-proof-host). |
| The proof tool cannot build or the IdP verifier fails to start. | Run the `method-id` check above. Confirm that the selected WSL distribution is the one with the toolchain and that `cargo` and the RISC Zero tools are available in its Bash login shell. Inspect the first build error in the WSL terminal. |
| PowerShell refuses to run a script. | Use `Get-ExecutionPolicy -List` to distinguish a script policy from other errors. See [PowerShell execution policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies/). On a managed device, ask the administrator rather than overriding policy. |
| A build or startup fails with access denied, or a generated executable disappears. | Check [Windows Security Protection History](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app) or your antivirus logs. Record the exact file and detection, verify its source, and follow your security policy before rebuilding. Do not disable protection or broadly exclude the repository. |
