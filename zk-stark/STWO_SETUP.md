# Local STWO Cairo setup

The DIDSSO repository does not vendor the complete `stwo-cairo` source tree.
Instead, `setup_stwo.sh` checks out the exact upstream revision recorded in
`STWO_COMMIT`, applies the local compatibility patch, and builds the two
binaries used by the prototype.

This keeps roughly 700 third-party files out of the main repository while
making the build reproducible for WSL, Linux, and a future Docker image.

## WSL setup from Windows

Install WSL and the normal Rust build prerequisites first. Then run this once
from the DIDSSO root in PowerShell:

```powershell
wsl bash ./zk-stark/setup_stwo.sh
```

By default, the source is installed at `$HOME/stwo-cairo` inside WSL. The
runtime wrappers therefore find the binaries at:

```text
$HOME/stwo-cairo/stwo_cairo_prover/target/release/run_and_prove
$HOME/stwo-cairo/stwo_cairo_prover/target/release/verify
```

For a different source directory, pass a Linux path and configure the runtime
wrapper consistently:

```powershell
wsl env STWO_SOURCE_DIR=/opt/stwo-cairo bash ./zk-stark/setup_stwo.sh
$env:STWO_WSL_PROVER_DIR = "/opt/stwo-cairo/stwo_cairo_prover"
```

Scarb 2.18.x and `cairo-execute` must also be available in WSL. The existing
`scarb_wsl.cmd` and `cairo_execute_wsl.cmd` wrappers expose those tools to the
Windows Python backend.

## Linux and Docker builds

The same setup script can be executed directly in Linux:

```bash
STWO_SOURCE_DIR=/opt/stwo-cairo bash ./zk-stark/setup_stwo.sh
```

A Docker build should invoke this command in a builder stage and copy only the
resulting `run_and_prove` and `verify` binaries into the runtime image. Neither
the Git checkout nor Cargo build artifacts need to be committed to DIDSSO.

Set `STWO_SKIP_BUILD=1` to validate the pinned checkout and patch without
rebuilding the binaries:

```bash
STWO_SKIP_BUILD=1 bash ./zk-stark/setup_stwo.sh
```

## Pinned compatibility patch

The current prototype carries one patch in
`patches/stwo-cairo-public-segment-context.patch`. It passes the builtins of the
executed Cairo program into `PublicSegmentContext` instead of using the
bootloader context. This is the same change that was already present in the
previous Windows and WSL working copies; the migration does not alter its
semantics.

The patch touches the STWO trace adapter. It therefore requires an independent
soundness review before production use. The current repository preserves it
explicitly so that Docker and clean WSL builds cannot silently use a different
prover implementation.

## Runtime selection

Select STWO in every PowerShell terminal that starts an IdP or RP backend:

```powershell
$env:DIDSSO_PROOF_BACKEND = "stwo"
```

Both backends must use the same proof backend. Switching between STWO and RISC
Zero requires a registration credential issued for the selected backend.

The Python adapter passes credential and nonce witnesses through a temporary
program-arguments file. It deletes argument, parameter, proof, and verifier
copies after use. The current STWO v3 proof still has the documented prototype
limitations: it is not zero knowledge and reduces the nonce binding to 20
bits.
