# Optional STWO Proof Backend

STWO is an experimental alternative for the native Windows setup. RISC Zero
remains the default, is included in the published Docker images, and is the
only proof backend used in the quantitative evaluation. The STWO integration
described here does not produce zero-knowledge proofs. Use it with test data
only.

- [Install the tools in WSL 2](#install-the-tools-in-wsl-2)
- [Switch to STWO](#switch-to-stwo)
- [Switch back to RISC Zero](#switch-back-to-risc-zero)
- [Implementation notes](#implementation-notes)

## Install the Tools in WSL 2

Follow the [native Windows prerequisites](../docs/NATIVE_SETUP_WINDOWS.md#requirements-for-native-setup)
and [prepare the Python environments](../docs/NATIVE_SETUP_WINDOWS.md#prepare-the-python-environments).
You do not need to build the RISC Zero host if you only plan to use STWO.

In the default WSL 2 distribution, install Git, Rust and Cargo with the Linux
build dependencies, [Scarb 2.18.x](https://docs.swmansion.com/scarb/download.html),
and `cairo-execute`. The two Cairo tools must be available inside WSL, not
only in Windows. From the DIDSSO repository root in PowerShell, check that the
Windows wrappers can find them and build the STWO tools:

```powershell
.\STWO\scarb_wsl.cmd --version
.\STWO\cairo_execute_wsl.cmd --help
wsl.exe bash -lc 'bash ./STWO/setup_stwo.sh'
```

> **Antivirus detection:** If your antivirus product flags a STWO
> `.cmd` wrapper as `IDP.Generic`, first check the detection history for
> the exact file path and the action taken. If the file was quarantined,
> leave it there. Verify the file's origin and ask your antivirus vendor to
> review the detection if you suspect a false positive. Do not disable
> protection or exclude the repository. If you only want to try the
> prototype, use the [standard RISC Zero Docker setup](../README.md#docker-quick-start)
> while the STWO detection is being reviewed.

The [setup script](setup_stwo.sh) fetches the upstream source revision pinned
in [`STWO_COMMIT`](STWO_COMMIT), applies the repository's compatibility
patch, and builds the `run_and_prove` and `verify` binaries. By default the
checkout is `~/stwo-cairo` in WSL, and both binaries are under
`~/stwo-cairo/stwo_cairo_prover/target/release/`.

For a custom checkout location, set `STWO_SOURCE_DIR` when calling the
setup script in WSL. Then set `STWO_WSL_PROVER_DIR` to that checkout's
`stwo_cairo_prover` directory using a Linux path in both backend PowerShell
terminals. If you only want to prepare the pinned checkout and apply the
patch without compiling, run the setup script with `STWO_SKIP_BUILD=1`.
That mode does not install the binaries needed to run the prototype.

## Switch to STWO

Stop the IdP and RP Python backends if they are running. From the repository
root, run these commands in the IdP backend's PowerShell terminal:

```powershell
$env:DIDSSO_PROOF_BACKEND = "stwo"
.\IdP\didcomm-backend\start.ps1
```

In a separate PowerShell terminal, also from the repository root, start the
RP backend with the same setting:

```powershell
$env:DIDSSO_PROOF_BACKEND = "stwo"
.\RP\didcomm-backend\start.ps1
```

Both terminals should show `Registration proof: STWO`. Start the web
applications and the wallet backend as in the
[native startup instructions](../docs/NATIVE_SETUP_WINDOWS.md#start-the-services),
and load the Firefox extension normally. No change to those components is
needed.

A RISC Zero registration credential cannot be used with STWO. If the RP
does not already have an accepted STWO credential for the current IdP,
[register and approve it again](../README.md#using-the-prototype) after
both backends are running with STWO. Then start Privacy-Enhanced SSO at the RP.
Switching backends does not require resetting runtime data.

## Switch Back to RISC Zero

Stop both Python protocol backends. In both PowerShell terminals, set
`$env:DIDSSO_PROOF_BACKEND = "risc0"` and restart them with the same start
scripts. Make sure the
[RISC Zero host is built in WSL](../docs/NATIVE_SETUP_WINDOWS.md#build-the-risc-zero-proof-tool).
The RP needs an accepted RISC Zero credential for the current IdP; obtain
one if it does not already have one.

## Implementation Notes

The [compatibility patch](patches/stwo-cairo-public-segment-context.patch)
changes the STWO trace adapter to use the executed Cairo program's builtins
for `PublicSegmentContext`. The pinned revision and patch keep that change
explicit in reproducible builds. The patch would need an independent soundness
review before production use.

The adapter passes witnesses to the Cairo program through temporary files.
In addition to lacking zero knowledge, the current STWO v3 implementation
reduces the nonce-binding value to 20 bits. It is not a drop-in replacement
for the RISC Zero backend when the evaluated privacy and security properties
are required.
