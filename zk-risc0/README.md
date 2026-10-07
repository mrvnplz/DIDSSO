# RISC Zero registration credential proof

This workspace implements the zero-knowledge registration proof used by the
DIDSSO demo. It is deliberately separate from `../zk-stark`: both backends are
kept, but one SSO flow uses exactly one backend.

## Proven statement

The zkVM guest proves that the prover knows a 256-bit credential secret and a
P-256 (secp256r1) ECDSA signature for that value which verifies under the
disclosed IdP public key. The secret is used as the 32-byte prehashed ECDSA
message; the IdP uses a dedicated key for this protocol.
The receipt is also bound to the current authorization nonce through a
domain-separated SHA-256 digest.

Private guest input:

- credential secret
- signature `r` and `s`
- P-256 IdP public-key coordinates before they are copied to the journal
- 256-bit request-context digest

Public journal:

- protocol version
- IdP public key
- 256-bit request-context digest

The credential, signature, and execution trace are not journal values. The
pairwise DID is intentionally not part of this proof. DIDComm authenticates the
sender separately; possession of the signed credential acts as the registration
authorization.

The method is universal across RPs and IdPs. A verifier must still compare the
journal public key with its own expected key and the context digest with the
current nonce. The IdP-side verifier performs both comparisons in addition to
checking the compiled RISC Zero method ID.

## Workspace

```text
host/                 JSON CLI for proving and verification
methods/guest/        zkVM guest that verifies the credential signature
types/                shared private-input and public-journal types
credential_risc0.py   Python adapter used by the RP and IdP backends
risc0_wsl.cmd         Windows entry point
risc0_wsl.ps1         PowerShell-to-WSL bridge
```

The CLI accepts JSON on stdin and writes JSON on stdout:

```powershell
.\risc0_wsl.cmd method-id
.\risc0_wsl.cmd prove
.\risc0_wsl.cmd verify
.\risc0_wsl.cmd verify-server
```

`prove` expects four fixed-width, big-endian 32-byte hex strings plus the
64-byte P-256 public key encoded as `x || y`. `verify` expects a Base64-encoded
serialized receipt, that expected IdP public key, and the expected context
digest.

The WSL bridge executes the prebuilt `target/release/host` binary directly.
It builds the binary once only when it does not exist. After changing Rust
guest, host, or shared-type sources, rebuild it explicitly:

```bash
cargo build --release -p host
```

`verify-server` uses newline-delimited JSON and stays alive for multiple
requests. The IdP starts this process once during backend startup and reuses it
for all receipt verifications.

## Selecting the SSO backend

Both DIDComm `start.ps1` scripts default to RISC Zero. Set the same value for
the RP and IdP before starting them:

```powershell
$env:DIDSSO_PROOF_BACKEND = "risc0" # zero-knowledge RISC Zero credential
$env:DIDSSO_PROOF_BACKEND = "stwo"  # existing STWO-Cairo v3 credential
```

Credentials are backend-specific. Switching backend requires registering the
RP again so that the IdP issues the matching credential. Existing STWO v3
credentials remain usable when `stwo` is selected.

The IdP keeps separate signing keys: STWO uses its native Stark curve in
`registration_signing_key.json`; RISC Zero uses P-256 in
`registration_signing_key_risc0_p256.json`. This prevents cross-backend key or
signature-format reuse.

## Security and operation

- The host enables RISC Zero's `disable-dev-mode` feature. The start scripts
  also remove `RISC0_DEV_MODE`; fake development receipts are not accepted.
- The SSO nonce is generated with 32 random bytes. SHA-256 with the fixed
  `did-sso:registration:risc0:v1` domain binds the receipt to that request.
- The outer proof envelope, its claimed method ID, and its copied nonce are not
  trusted. Verification uses the receipt, the locally compiled method ID, and
  IdP-side expected values.
- The RP does not verify its newly generated receipt. Only the IdP performs the
  security-relevant verification, including method ID, IdP key, and request
  context. Removing this duplicate RP check does not weaken the IdP boundary.
- There is no credential expiry or revocation mechanism in this prototype.
- Zero knowledge protects the receipt witness. It does not hide DIDComm/network
  metadata, application logs, or values deliberately published in the journal.
- P-256 verification uses the zkVM-only `risc0-crypto` acceleration. Version
  `0.1.0-rc.1` is an unaudited prerelease and must be replaced or independently
  reviewed before production use.

## Build and tests

Run inside WSL from this directory:

```bash
cargo fmt --all -- --check
cargo test -p host
cargo build --release -p host
./target/release/host method-id
```

Local benchmark on 2026-08-08 with a Composite Receipt:

- before direct-binary/persistent-verifier changes: prove 164.00 s, verify
  107.21 s, total 271.21 s;
- after the changes: verifier startup 4.56 s, prove 54.65 s, first warm verify
  0.027 s, second warm verify 0.025 s, first-flow total 54.67 s.

Both optimized verification runs accepted the receipt and reused the same
verifier process. Timings are machine-specific.

The STWO backend deliberately retains Stark-curve ECDSA because it is native to
that Cairo/STWO path. The RISC Zero backend uses accelerated P-256 instead of
emulating the Stark curve in general RISC-V instructions.
