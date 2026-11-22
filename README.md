# DIDSSO

DIDSSO is a research prototype for privacy-enhanced single sign-on based on the
OpenID Connect (OIDC) Authorization Code Flow. Users manage a separate
decentralized identifier (DID) for each relying party (RP). During SSO, the RP
uses DIDComm and a RISC Zero registration proof to demonstrate that it holds a
valid credential without directly disclosing its public identity to the
identity provider (IdP) in the code exchange.

The prototype also supports **Direct DID-Based Login** for returning users and
**DID replacement** to restore an existing account after key loss. It is
intended for a controlled local environment, not as a production-ready or
drop-in OIDC implementation.

[Requirements for Docker setup](#requirements-for-docker-setup) ·
[Docker quick start](#docker-quick-start) ·
[Using the prototype](#using-the-prototype) ·
[Troubleshooting when using the prototype](#troubleshooting-when-using-the-prototype) ·
[Stopping and resetting the Docker setup](#stopping-and-resetting-the-docker-setup) ·
[Documentation](#documentation)

## Requirements for Docker Setup

The prototype was tested successfully in the Docker setup listed below. These
versions are not minimum requirements. If you encounter compatibility issues,
try using the listed versions.

| Component | Reference version |
| --- | --- |
| Host operating system | Windows 11 (x86-64) |
| Git | 2.53.0.windows.2 |
| Docker Desktop | 4.94.0 (build 241994) |
| Docker CLI | 29.8.2 |
| Docker Compose | 5.5.1 |
| Firefox | 160.0.1 |

The published images target `linux/amd64`. Running them on Apple Silicon Macs
requires AMD64 emulation, which Docker Desktop supports.

## Docker Quick Start

Start Docker Desktop and wait for the Linux container engine to become ready.

```sh
git clone https://github.com/mrvnplz/DIDSSO.git
cd DIDSSO
docker compose pull
docker compose up -d
docker compose ps
```

Compose uses the public GHCR images pinned by release tag in
[`compose.yaml`](compose.yaml).

1. In Firefox, open `about:debugging#/runtime/this-firefox`. Choose **Load
   Temporary Add-on** and select
   [`firefox-extension/manifest.json`](firefox-extension/manifest.json) from
   your local clone.
2. Open the extension from the Firefox toolbar. **Wallet loaded.** confirms
   that the wallet backend is reachable, even if no DIDs are listed yet.
   If you see **Could not reach the DID service.**, check that the backend is
   running (in Docker, use `docker compose ps wallet-backend`).
3. Open the IdP at <https://127.0.0.1:3001> and the RP at
   <http://127.0.0.1:3002>. Accept the self-signed certificate warning
   for the local IdP.

   > **Hint:** Docker Desktop may display an `http://127.0.0.1:3001` link
   > because the TCP port mapping does not indicate whether the application
   > uses HTTP or HTTPS. Open the IdP using `https://` instead.

The extension is loaded separately from the containers. Reload the temporary
add-on after restarting Firefox.

## Using the Prototype

1. Create a test user account at the IdP and copy the Master DID displayed on
   its homepage.
2. Open the RP's Admin-dashboard. Submit a registration request with an RP
   name and the copied Master DID, then accept the request in the IdP's Admin-dashboard.
3. Choose how to manage your DIDs in the Firefox extension. We recommend
   **automatic DID management**: it selects an existing Pairwise DID for
   the RP or creates one if needed. 
   
   With manual DID management, create a
   DID if needed and select the one you want to use before starting SSO.
4. On the RP homepage, select **Privacy-Enhanced SSO**. Sign in at the IdP
   if required, then consent to the requested claims. The browser returns to
   the RP account page. Processing the request might take a while (~55 seconds) due to the RISC Zero proof generation.
5. To sign in again, select **DID Login** on the RP homepage. This uses the
   established User Pairwise DID without generating another registration
   proof. The prototype still needs a usable token grant to retrieve current
   claims. Make sure to selec the DID which you have performed the SSO with.

## Troubleshooting When Using the Prototype

- **Could not reach the DID service.** Load or reload the temporary Firefox
  add-on, then check that the wallet backend is running on port `8765`.
- **No accepted RISC0 registration is bound to the configured IdP web
  origin.** Check **Accepted requests** in the RP's **Admin** dashboard.
  The registration must match the IdP used for SSO and the active proof
  backend.
- **The DIDSSO plugin did not attach a bound pairwise DID.** Use the same RP
  address and DID that you used for the successful SSO. If you have not yet
  signed in to that RP, start with **Privacy-Enhanced SSO**.
- **Current IdP claims could not be retrieved.** Check the rest of the error:
  if the grant is missing, expired, or rejected, run **Privacy-Enhanced SSO**
  again with the existing DID to obtain a new grant.

The [troubleshooting guide](docs/TROUBLESHOOTING.md) explains these and other
messages from the extension, the IdP and RP dashboards, sign-in, and DID
replacement. It applies to both Docker and native execution. For problems
installing or starting the Windows services, see
[Native setup troubleshooting](docs/NATIVE_SETUP_WINDOWS.md#troubleshooting).

## Stopping and Resetting the Docker Setup

Use `docker compose logs -f` to inspect service logs. Stop the Docker setup
with `docker compose down`; the named volumes retain test accounts, DIDs,
registration records, and other runtime state. **Use
`docker compose down --volumes` only for an intentional full reset.** It removes
that state, including private keys. The RP must be registered again after a
reset. The Firefox extension's browser-side storage is not cleared when
Docker volumes are removed.

## Documentation

- [Native setup on Windows](docs/NATIVE_SETUP_WINDOWS.md) — install the
  prerequisites, build the proof tooling in WSL, start the services, and
  troubleshoot or reset the local setup.
- [Reproduce the evaluation](evaluation/EVALUATION.md) — run the protocol and
  proof benchmarks in the instrumented native setup.
- [Working with benchmark outputs](evaluation/BENCHMARK_ANALYSIS.md) —
  identify the generated files, import the CSVs, and check that a report is
  complete.
- [RISC Zero proof component](zk-risc0/README.md) — how the prototype issues
  registration credentials, generates proofs, and verifies receipts.
- [Developer Guide](docs/DEVELOPER_GUIDE.md) — where to change protocol
  behavior, add a proof backend, or extend the RP to support multiple IdPs.
- [Extra Work — Optional STWO Proof Backend](STWO/STWO_SETUP.md) — set up STWO
  in WSL and switch proof backends in the native setup.

For builds from source, use the [Compose build overlay](compose.build.yaml)
and override `DIDSSO_REGISTRY` and `DIDSSO_VERSION` (for example, with
`didsso-local` and `local`) to keep local image tags separate from published
releases. For a custom IdP origin, set `DIDSSO_IDP_WEB_PUBLIC_URL` before
registering the RP.
