# Developer Guide

This guide is for modifying the prototype, not for integrating a public API.
Use the [native Windows setup](NATIVE_SETUP_WINDOWS.md) when changing code.
For usage, common errors, and measurements, see
[Using the Prototype](../README.md#using-the-prototype),
[Troubleshooting](TROUBLESHOOTING.md), and
[Reproduce the Evaluation](../evaluation/EVALUATION.md).

- [Codebase overview](#codebase-overview)
- [Configuration and persistent state](#configuration-and-persistent-state)
- [Current implementation limits](#current-implementation-limits)
- [Change a Firefox protocol header](#change-a-firefox-protocol-header)
- [Add a DIDComm message](#add-a-didcomm-message)
- [Add a protocol action](#add-a-protocol-action)
- [Add a proof backend](#add-a-proof-backend)
- [Support multiple IdPs or RPs](#support-multiple-idps-or-rps)
- [Check a change locally](#check-a-change-locally)
- [Build and run the Docker images locally](#build-and-run-the-docker-images-locally)

## Codebase Overview

The tree shows the main source files and entry points. Generated files and
local runtime data are omitted.

```text
DIDSSO/
├── IdP/
│   ├── src/
│   │   ├── main.rs                 # Rust web server for the IdP
│   │   ├── request_router.rs       # HTTP routing and forwarding of SSO requests
│   │   ├── auth_handlers.rs        # User registration, login, logout, and profile updates
│   │   ├── session_store.rs        # Creates, validates, and revokes browser sessions
│   │   ├── user_store.rs           # Stores and retrieves local IdP user accounts
│   │   └── idp_rp_admin.rs         # Forwards RP registration decisions to the backend
│   ├── web/sso.html                # IdP sign-in and consent page
│   └── didcomm-backend/
│       ├── server.py               # RP registration, code exchange, and token grants
│       ├── did_peer_service.py     # IdP Peer DIDs and local key material
│       └── didcomm_service.py      # Key resolution, message packing, and unpacking
├── RP/
│   ├── src/main.rs                 # Rust server for the RP web pages
│   ├── web/
│   │   ├── index.html              # Starts Privacy-Enhanced SSO or Direct DID-Based Login
│   │   ├── admin.html              # RP registration and scope configuration
│   │   └── sso-wait.html           # Polls the RP backend for the login result
│   └── didcomm-backend/
│       ├── server.py               # Login processing, RP accounts, and protocol state
│       ├── did_peer_service.py     # RP Peer DIDs and local key material
│       └── didcomm_service.py      # Key resolution, message packing, and unpacking
├── firefox-extension/
│   ├── manifest.json               # Add-on entry points and permissions
│   ├── background.js               # Request headers, IdP responses, and navigation
│   ├── frontend/popup.js           # Wallet controls in the Firefox toolbar
│   └── backend/
│       ├── server.py               # Wallet HTTP and DIDComm entry points
│       ├── did_peer_4_service.py   # User Peer DIDs and local key material
│       ├── didcomm_service.py      # Key resolution, message packing, and unpacking
│       ├── wallet_state_service.py # DID selection and relationship bindings
│       └── sso_service.py          # User-side SSO and direct-login processing
├── zk-risc0/
│   ├── credential_risc0.py          # Credential issuance and Python adapter
│   ├── host/src/main.rs            # Rust prover and verifier interface
│   └── methods/guest/src/main.rs   # Checks the registration signature in the zkVM
├── STWO/credential_stark.py        # Optional STWO proof backend
├── evaluation/
│   ├── benchmark-protocol.py       # Browser-driven authentication benchmark
│   └── benchmark-proofs.py         # Standalone registration-proof benchmark
├── sso_claims.py                   # Scope-to-claim mapping shared by IdP and RP
├── evaluation_trace.py             # Benchmark instrumentation shared by the Python backends
├── compose.yaml                    # Docker services and published image tags
└── compose.build.yaml              # Local Docker build definitions
```

The RP's browser-side JavaScript calls its Python backend directly, whereas
the IdP's Rust web server forwards browser-based SSO requests to its Python
backend.

## Configuration and Persistent State

Use this section when moving a service, changing an address, or working
with stored records. Startup settings control how a service runs.
Persistent state is what the service saves between runs, such as accounts,
registrations, and wallet keys. Changing a startup setting does not
rewrite those records.

### Runtime Configuration

The default setup does not require you to set these variables manually.
They apply to the process that reads them:

- **Native Windows:** Set an override with `$env:VARIABLE_NAME = "value"`
  in the PowerShell terminal that launches the affected service. The Python
  backends read their environment and use defaults when a value is not set;
  their start scripts configure some settings. For the Rust web servers,
  Cargo supplies the default `PORT` from the
  [IdP](../IdP/.cargo/config.toml) and [RP](../RP/.cargo/config.toml)
  configurations.
- **Docker:** Each container gets its settings from `environment:` in
  [`compose.yaml`](../compose.yaml) and defaults in its [Dockerfile](../docker/).
  A variable set in the host terminal only overrides a Compose setting
  where the YAML references it. For example, Compose passes a host override
  for `DIDSSO_IDP_WEB_PUBLIC_URL` to the RP backend, while
  `DIDSSO_RP_WEB_PUBLIC_URL` is set directly in the YAML.

For network changes, distinguish where a service listens, which URL Firefox
opens, and which DIDComm address other backends send messages to.

| Setting | Purpose |
| --- | --- |
| `DIDSSO_BIND_HOST` | Sets the listener address of the Rust web applications and Python backends. It does not set the address used by clients. |
| `PORT` in the Rust web applications; `DIDSSO_PORT` in Python | Selects the listening port. Changing it does not update the browser's backend URLs or existing DID Documents. |
| `DIDSSO_IDP_DIDCOMM_HOST` and `DIDSSO_IDP_DIDCOMM_PORT` | Tell the IdP web server where to forward requests to its Python backend. |
| `DIDSSO_IDP_WEB_PUBLIC_URL` and `DIDSSO_RP_WEB_PUBLIC_URL` | Set the browser-facing origins used by the RP backend. The IdP origin is associated with the accepted registration. |
| `DIDSSO_DIDCOMM_ENDPOINT` | Sets the service address used when generating DIDs. Check existing records separately: their DID Documents already contain a service endpoint. |
| `DIDSSO_WALLET_BACKEND_URL` | Sets the RP backend's HTTP destination for the wallet. It does not change the extension's `DID_SERVICE_URL`. |
| `DIDSSO_DATA_DIR` | Selects the directory the component reads and writes. It does not move any existing files. |

For example, if the IdP is already listening at `https://127.0.0.1:3011`
in a native setup, set `$env:DIDSSO_IDP_WEB_PUBLIC_URL = "https://127.0.0.1:3011"`
in the RP backend's terminal before starting it and registering the RP.
This changes the RP's browser destination, not the IdP's listening port.
The value must be an HTTPS origin without a path.

### Persistent State

Native services store persistent state under `IdP/data/`, `RP/data/`, and
`firefox-extension/data/`. In Docker, the corresponding named volumes are
mounted at `/data` in the containers that need persistent state.

The RP owns `idp_registrations.json`, `sso_sessions.json`, `user_accounts.json`,
and `token_grants.json`. The IdP owns its code, registration, and grant
records; its Rust and Python components use the same IdP data directory.
The wallet stores DID keys and bindings separately from its active SSO
request and result. When changing a persisted field, find both its readers
and writers. Define how older records are handled and update the
[reset script](../reset-state.ps1) if new files should be reset.
Keep runtime data out of Git and Docker images, as it may contain private
keys, credentials, and tokens.
See [stopping and resetting](NATIVE_SETUP_WINDOWS.md#stop-or-reset-the-native-setup)
for the operational steps.

### Changing Local Addresses and Ports

The [native setup](NATIVE_SETUP_WINDOWS.md#start-the-services) lists the
default addresses. If you change one, follow its callers as well as its
listener:

- **Browser origins:** The [manifest](../firefox-extension/manifest.json)
  and the host checks and listener URL filters in
  [`background.js`](../firefox-extension/background.js) are restricted to
  `127.0.0.1`. Changing a hostname requires reviewing both. Keep the
  method, path, origin, and session checks scoped to the intended services.
  The [IdP TLS certificate](../IdP/src/main.rs) must match the new hostname
  or IP address.
- **Browser-to-backend URLs:** The wallet URL is fixed in both
  [`background.js`](../firefox-extension/background.js) and
  [`popup.js`](../firefox-extension/frontend/popup.js). The RP backend URL
  is fixed in the [login](../RP/web/index.html),
  [admin](../RP/web/admin.html), [waiting](../RP/web/sso-wait.html), and
  [account](../RP/web/user.html) pages. Backend environment variables do
  not update these browser-side values.
- **Docker and DIDComm:** Check the host port mappings in
  [`compose.yaml`](../compose.yaml) separately from the container-to-container
  addresses. DIDComm endpoints must be reachable by the other backends,
  not just by Firefox. Changing the endpoint configuration does not rewrite
  existing DID Documents.
- **Existing bindings:** An origin includes the scheme, host, and port.
  Changing any of them can make wallet bindings or the accepted IdP
  registration no longer match. Check those records before reusing
  existing state, and verify wallet access, SSO, and direct login after
  changing addresses.

## Current Implementation Limits

These are constraints of the current implementation and deployment. Use
them to identify which components a proposed change must cover.

| If you want to change... | Current constraint and where to start |
| --- | --- |
| Browser or network deployment | The add-on targets Firefox, and the documented setup is local. See [Changing Local Addresses and Ports](#changing-local-addresses-and-ports) before adding an origin or moving a service. The default DIDComm transport is HTTP; DIDComm encryption does not protect the outer wrapper or transport metadata. |
| Multiple IdPs, multiple RPs, or concurrent sign-ins | The RP uses one configured IdP HTTPS origin for SSO. The extension and wallet track one active SSO context. See [Support Multiple IdPs or RPs](#support-multiple-idps-or-rps) for the separate changes needed for provider selection, additional instances, and parallel sessions. |
| Claims or consent | Supported scopes and claims are defined in [`sso_claims.py`](../sso_claims.py), with separate UI mappings on the [RP admin page](../RP/web/admin.html) and [IdP consent page](../IdP/web/sso.html). Update server validation and the relevant interfaces together. Existing grants do not pick up scope changes; those require fresh SSO consent. |
| Credential lifecycle or proof backends | The implementation does not bind code redemption to the initiating RP or support selective revocation of registration credentials. See [Add a Protocol Action](#add-a-protocol-action) and [Add a Proof Backend](#add-a-proof-backend). Both parties need the same proof backend and a matching registration credential. RISC Zero is used in the Docker images and benchmarks; [STWO](../STWO/STWO_SETUP.md) is an experimental native alternative that does not provide zero knowledge. |
| Timing, proof size, or benchmarks | SSO completion depends on proof processing and on polling by the extension and RP waiting page. For larger proofs, check the adapter and the ciphertext size limit in the start scripts and [Docker build](../docker/didcomm-risc0.Dockerfile). The [benchmark](../evaluation/EVALUATION.md) uses the instrumented local RISC Zero setup; after changing a browser flow, review the [benchmark driver](../evaluation/benchmark-protocol.py) as well. |

## Change a Firefox Protocol Header

- **Where:** In [`background.js`](../firefox-extension/background.js),
  `onBeforeSendHeaders` adds `X-DIDSSO-DID` to the RP's
  `POST /sso/start` and `POST /did-login/start`. On the response side,
  the [IdP backend](../IdP/didcomm-backend/server.py) adds headers in
  `/sso/issue-code`; the Rust router forwards them and
  `handleAuthorizationCodeResponse()` consumes them.
- **Watch for:** Keep matching by HTTP method, path, and intended origin.
  For authorization responses, retain the successful HTTP status check
  and the active tab, origin, and `state` checks. An IdP service marker
  alone does not authenticate an authorization response.
- **Approach:** Change the writer and reader together. For a new header sent
  by cross-origin page JavaScript to the RP, also review the allowlist in
  `RpDidCommHandler.end_headers()`. Header matching in the extension is
  case-insensitive.
- **Check:** Reload the add-on and inspect the affected request in Firefox's
  Network panel. Confirm unrelated requests do not carry the new header
  and complete the affected flow. Do not share captures containing codes
  or tokens.

## Add a DIDComm Message

- **Where:** Follow the sender into the receiver's `/didcomm/inbox` in the
  [RP](../RP/didcomm-backend/server.py),
  [IdP](../IdP/didcomm-backend/server.py), or
  [wallet](../firefox-extension/backend/server.py) backend. For example,
  `DID_LOGIN_CHALLENGE_TYPE` is sent by `send_direct_login_challenge()`
  at the RP and dispatched by the [wallet SSO service](../firefox-extension/backend/sso_service.py).
- **Watch for:** Put new protocol data in the encrypted message body,
  not beside `packedMessage` in the outer JSON wrapper. The outer
  `senderDid` helps resolve keys; authorization depends on the sender
  authenticated by unpacking and on the expected recipient and context.
- **Approach:** Define the type URI, body fields, and reply before wiring
  the sender and intended receiver. Follow the authenticated dispatch for
  that receiver, including `AUTHCRYPT_REQUIRED_TYPES` at the RP where
  applicable. Correlate replies by the appropriate session and DIDComm
  thread. The Firefox add-on does not dispatch backend DIDComm types.
- **Check:** Confirm the intended message and reply advance the expected
  session. Check that a message for an unexpected thread or state does
  not change it.

For future mediator support, start with DID service creation and the
participants' endpoint resolution and delivery functions (for example,
`didcomm_endpoint_from_did()` at the RP). The current resolver obtains the
service endpoint from the long-form DID; the short form does not carry it.
Changing the endpoint alone does not implement mediated delivery.

## Add a Protocol Action

- **Where:** Start with the [RP UI](../RP/web/index.html) and
  [RP backend](../RP/didcomm-backend/server.py). For a reference flow, follow
  `create_sso_session()`, `queue_sso_code_forward()`, and
  `store_authorization_response()`. The RP waiting page reads
  `GET /sso/session?session_id=...`; the extension also reads the
  wallet's `/sso/result` during SSO.
- **Watch for:** Keep the state in the component that decides success.
  The DIDComm inbox's `202` acknowledges the message; use the session
  result to determine whether login completed. Retries and terminal errors
  must refer to the same session. If an action changes an account's DID,
  check both account lookup and the token grants tied to the relationship.
- **Approach:** Define the trigger, expected state transitions, and
  success or error response. Update only the affected routes, handlers,
  and UI. Tracing an action through the wallet may require following both
  `session_id` in the RP and `sessionId` in the wallet's HTTP payloads.
- **Check:** Run the success path and an expected failure or retry. Verify
  that the page reaches the intended destination only after the
  corresponding backend result.

For future authorization-code binding, review RP session creation, the
carried authorization context, and `issue_sso_code()` and
`exchange_sso_code()` at the IdP. Treat this as a change to the parties'
shared protocol, not an extra header alone. Do not introduce a public RP
identifier into the code exchange.

## Add a Proof Backend

- **Where:** Use the [RISC Zero adapter](../zk-risc0/credential_risc0.py) or
  [STWO adapter](../STWO/credential_stark.py) as a reference. Update the
  `DIDSSO_PROOF_BACKEND` branches in the
  [IdP backend](../IdP/didcomm-backend/server.py) and
  [RP backend](../RP/didcomm-backend/server.py), plus the allowlists in their
  respective [IdP](../IdP/didcomm-backend/start.ps1) and
  [RP](../RP/didcomm-backend/start.ps1) start scripts.
- **Watch for:** Use distinct backend and credential-format identifiers.
  The RP filters accepted credentials by `ACTIVE_CREDENTIAL_FORMAT`.
  Decide how the IdP chooses the signing key and starts and stops any
  persistent verifier. The verifier must use the expected IdP key and
  authorization context, not those claimed by the proof sender.
- **Approach:** Connect `issue_registration_credential()`,
  `registration_verifier_config()`, and `verify_registration_proof()`
  in the IdP, and `create_registration_proof()` in the RP. Configure
  any external tools in the start scripts. [Switching between the existing
  backends](../STWO/STWO_SETUP.md#switch-to-stwo) is documented separately.
- **Check:** Start both parties with the same backend, obtain a matching
  credential, and complete SSO. A credential from another backend must
  not be accepted. Benchmark changes separately; the current
  [evaluation](../evaluation/EVALUATION.md) selects RISC Zero.

For selective revocation, the extension point is both issuance and proof
verification. The revocation check would have to apply to the credential
used in the proof without revealing which credential it was.

## Support Multiple IdPs or RPs

**Several IdPs at one RP.** This is an extension, not a configuration option:
`sso_registration_candidates()` currently uses one configured HTTPS origin.

- **Where:** Start with `POST /rp/register-at-idp`,
  `update_registration_from_idp_message()`, and
  `create_sso_session()` in the [RP backend](../RP/didcomm-backend/server.py).
  The current `/sso/start` rejects an `idpMasterDid` supplied by the page.
- **Watch for:** Keep an accepted registration's HTTPS origin, IdP Master
  DID, RP Pairwise DID, and credential together. Do not use the DIDComm
  inbox as the browser redirect destination. Decide explicitly whether
  existing RP accounts may change their IdP; grants are issuer-specific.
- **Approach:** Run IdP instances with separate web and DIDComm ports
  and data directories. Preserve the intended HTTPS origin in each RP
  registration through approval. In the [RP login page](../RP/web/index.html),
  offer only accepted registrations. Pass a registration reference to
  the backend, validate it there, and keep it in the session so that
  navigation and code exchange use the same registration.
- **Check:** Complete one sign-in through each IdP in turn. Check the
  browser destination, code exchange, and selected token grant. Unapproved
  registrations must not start SSO. For local same-host IdPs, use separate
  browser profiles when checking browser sessions: ports alone do not
  isolate cookies ([RFC 6265, Section 8.5](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.5)).
  Distinct hostnames require matching TLS certificates and corresponding
  [extension host permissions](../firefox-extension/manifest.json) and
  listener filters.

**Several RPs at one IdP.** Each RP instance needs a separate RP DID wallet,
registration state, and endpoints. Make the
[browser-to-backend URL](#changing-local-addresses-and-ports) configurable
for each instance.
Verify that each RP registers and signs in independently and that the
wallet selects a different user Pairwise DID for each RP relationship.

Choosing among several IdPs does not by itself support simultaneous SSO
attempts in separate tabs. The extension and wallet currently keep one
active authentication context. If you add parallel login, index both
contexts and result handling by session, and keep the expected tab and
IdP origin with each request.

## Check a Change Locally

- Restart the affected Python or Rust service after editing it. Reload
  the temporary Firefox add-on after changing its code or manifest.
  For proof guest changes, follow the [RISC Zero rebuild instructions](../zk-risc0/README.md#rebuild-the-proof-host).
- Find the last successful boundary: the browser request, the extension
  console, or the sender and receiver backend logs. Correlate by session
  or DIDComm thread in local logs, not by dumping a credential, token,
  or authorization code. For known messages, use the
  [troubleshooting guide](TROUBLESHOOTING.md).
- Record the affected flow and manual checks with your change. If the
  change affects performance, rerun the relevant benchmark rather than
  comparing against timestamps from an ad hoc run.

## Build and Run the Docker Images Locally

Use [`compose.yaml`](../compose.yaml) for image names and published defaults
and [`compose.build.yaml`](../compose.build.yaml) for the build definitions.
Run these commands from the repository root. The local tags keep these images
separate from the published ones.
Keep [`.dockerignore`](../.dockerignore) in sync when adding runtime files.

```powershell
$env:DIDSSO_REGISTRY = "didsso-local"
$env:DIDSSO_VERSION = "local"
docker compose config --images
docker compose -f compose.yaml -f compose.build.yaml build
```

Check that all five image references use the intended namespace and tag.
Stop any setup that uses the same host ports. Then run
`docker compose up -d --no-build --pull never` in the same PowerShell
terminal so that `DIDSSO_REGISTRY` and `DIDSSO_VERSION` still select the
local images. Complete one SSO and one direct login.
