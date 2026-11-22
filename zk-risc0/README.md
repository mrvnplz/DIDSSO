# RISC Zero Registration Credential Proof

RISC Zero is the default registration-proof backend in DIDSSO. During
Privacy-Enhanced SSO, it lets the IdP verify that the RP has a valid
registration credential without receiving the credential secret or signature
in the code exchange. Direct DID-Based Login does not generate a new
registration proof.

For installation, see the [native Windows setup](../docs/NATIVE_SETUP_WINDOWS.md#build-the-risc-zero-proof-tool)
or the [Docker quick start](../README.md#docker-quick-start). For measurements,
see [Reproduce the Evaluation](../evaluation/EVALUATION.md). The
[optional STWO backend](../STWO/STWO_SETUP.md) is documented separately.

## Credential Issuance, Proving, and Verification

1. **IdP issues the credential.** When the IdP accepts an RP registration,
   it generates a random 256-bit secret and signs it with a dedicated
   P-256 ECDSA registration key. The secret is passed to ECDSA as a
   prehashed 32-byte value, so it is not hashed again. The signature covers
   the secret rather than the complete credential object. The registration
   key is distinct from the IdP's DIDComm keys.
2. **RP creates the proof.** For each code exchange, the Python adapter
   derives a domain-separated SHA-256 digest from the SSO session's nonce
   and sends the proving inputs to the Rust host. The zkVM guest validates
   the P-256 public key and checks the signature against the credential
   secret. On success, the host serializes the receipt and returns it in
   Base64 for inclusion in the DIDComm code-exchange message.
3. **IdP verifies the receipt.** The IdP obtains the expected nonce from
   the authorization-code record and the expected public key from its
   locally stored registration key. The Rust verifier checks the receipt
   against the locally compiled guest's image ID and compares the journal's
   protocol version, public key, and context digest with the expected values.
   The IdP starts one verifier process at backend startup and verifies each
   received receipt separately.

## What the Proof Reveals

The credential secret and ECDSA signature components are private inputs.
The receipt's public journal contains the protocol version, the IdP
registration public key, and the request-context digest. The key and digest
are supplied to the guest and copied into the journal after the signature
check succeeds. See [RISC Zero's receipt documentation](https://dev.risczero.com/api/3.0/zkvm/receipts)
for how the journal and image ID relate to verification.

The adapter checks the outer proof envelope, but its claimed method ID
and request values are not trust anchors. The IdP uses its own expected
values and the locally compiled guest. The Rust host is built with
`disable-dev-mode` so development receipts are not accepted.

The receipt attests to a valid signature and the expected request context.
It does not bind the credential proof to the RP's public identity or establish
that the party redeeming the code is the RP that initiated authorization.
DIDComm authenticates the sending DID separately. The proof does not hide
network metadata, and the prototype does not implement credential expiration
or selective revocation.

## Source Layout and Host Interface

| Source | Responsibility |
| --- | --- |
| [`credential_risc0.py`](credential_risc0.py) | Issues credentials, prepares proof inputs, and manages calls to the Rust host for both protocol backends. |
| [`host/src/main.rs`](host/src/main.rs) | Runs the prover, serializes receipts, and verifies receipts and journal values. |
| [`methods/guest/src/main.rs`](methods/guest/src/main.rs) | Checks the P-256 signature inside the zkVM and commits the public journal. |
| [`types/src/lib.rs`](types/src/lib.rs) | Defines the input and journal formats shared by host and guest. |
| [`risc0_wsl.cmd`](risc0_wsl.cmd) and [`risc0_wsl.ps1`](risc0_wsl.ps1) | Run the Linux host binary from the native Windows setup. |

The host exposes `prove` and `verify` for single JSON requests and
`verify-server` for the IdP's persistent, newline-delimited JSON interface.
`method-id` prints the compiled guest's image ID without requiring a JSON
request.

## Rebuild the Proof Host

With the
[Linux toolchain set up](../docs/NATIVE_SETUP_WINDOWS.md#build-the-risc-zero-proof-tool),
open PowerShell in the repository's `zk-risc0/` directory and run:

```powershell
wsl.exe bash -lc 'cargo build --release --locked -p host && ./target/release/host method-id'
```

If you are already in WSL Bash in that directory, run:

```bash
cargo build --release --locked -p host && ./target/release/host method-id
```

The command prints the guest image ID after a successful build. Rebuild
explicitly after changing the Rust host, guest, or shared types: the
Windows wrapper builds a missing host but does not replace an existing one.

- If Cargo reports Windows linker errors such as `LNK2019` or `LNK1120`,
  check that the proof build ran inside WSL. A `PS C:\...` prompt is
  PowerShell on Windows; use the `wsl.exe` command above from that prompt.



The guest uses the pinned prerelease `risc0-crypto` dependency for P-256
verification. This integration is intended for the research prototype,
not production use.
