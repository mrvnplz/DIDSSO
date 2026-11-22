# Developer Guide

This guide is for modifying the prototype, not for integrating a public API.
Use the [native Windows setup](NATIVE_SETUP_WINDOWS.md) when changing code.
For usage, common errors, and measurements, see
[Using the Prototype](../README.md#using-the-prototype),
[Troubleshooting](TROUBLESHOOTING.md), and
[Reproduce the Evaluation](../evaluation/EVALUATION.md).

- [Find the relevant code](#find-the-relevant-code)
- [Configuration and persistent state](#configuration-and-persistent-state)
- [Change a Firefox protocol header](#change-a-firefox-protocol-header)
- [Add a DIDComm message](#add-a-didcomm-message)
- [Add a protocol action](#add-a-protocol-action)
- [Add a proof backend](#add-a-proof-backend)
- [Support multiple IdPs or RPs](#support-multiple-idps-or-rps)
- [Check a change locally](#check-a-change-locally)
- [Build and publish a Docker release](#build-and-publish-a-docker-release)

## Find the Relevant Code

| Change | Start here |
| --- | --- |
| Browser request interception and navigation | [`firefox-extension/background.js`](../firefox-extension/background.js); for popup-only changes, use [`frontend/`](../firefox-extension/frontend/). |
| Wallet HTTP routes, DID selection, and SSO state | [`server.py`](../firefox-extension/backend/server.py) dispatches the routes; [`wallet_state_service.py`](../firefox-extension/backend/wallet_state_service.py) selects and binds DIDs; [`sso_service.py`](../firefox-extension/backend/sso_service.py) handles challenges, code forwarding, and results. |
| IdP browser sessions and consent | [`IdP/src/`](../IdP/src/) handles TLS, user accounts, and browser sessions. [`request_router.rs`](../IdP/src/request_router.rs) proxies the SSO JSON routes to the [Python IdP backend](../IdP/didcomm-backend/server.py). |
| RP UI and protocol state | The [Rust RP server](../RP/src/main.rs) serves [`RP/web/`](../RP/web/). The page JavaScript calls the [Python RP backend](../RP/didcomm-backend/server.py) directly for registration, login, and account operations. |
| DID construction, encryption, or routing | Look in the participant's `did_peer_service.py` (wallet: `did_peer_4_service.py`) and `didcomm_service.py`. Start in the message handler for protocol changes; change packing only if the transport contract changes. |

## Configuration and Persistent State

Distinguish the listener address, browser destination, and DIDComm address:

| Setting | Purpose |
| --- | --- |
| `PORT` in the Rust web applications; `DIDSSO_PORT` in Python | Selects the listening port. Changing it does not update the browser's backend URLs or existing DID Documents. |
| `DIDSSO_IDP_DIDCOMM_HOST` and `DIDSSO_IDP_DIDCOMM_PORT` | Tell the IdP web server where to forward requests to its Python backend. |
| `DIDSSO_IDP_WEB_PUBLIC_URL` and `DIDSSO_RP_WEB_PUBLIC_URL` | Set the browser-facing origins used by the RP backend. The IdP origin is associated with the accepted registration. |
| `DIDSSO_DIDCOMM_ENDPOINT` | Sets the service address used when generating DIDs. Check existing records separately: their DID Documents already contain a service endpoint. |
| `DIDSSO_WALLET_BACKEND_URL` | Sets the RP backend's HTTP destination for the wallet. It does not change the extension's `DID_SERVICE_URL`. |

The RP owns `idp_registrations.json`, `sso_sessions.json`, `user_accounts.json`,
and `token_grants.json`. The IdP owns its code, registration, and grant
records; its Rust and Python components use the same IdP data directory.
The wallet stores DID keys and bindings separately from its active SSO
request and result. When changing a persisted field, find both its readers
and writers. Define how older records are handled and update the
[reset script](../reset-state.ps1) if new files should be reset.
Keep keys, credentials, and tokens out of code, logs, and Docker images.
See [stopping and resetting](NATIVE_SETUP_WINDOWS.md#stop-or-reset-the-native-setup)
for the operational steps.

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
`didcomm_endpoint_from_did()` at the RP). Changing the endpoint alone
does not implement mediated delivery.

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
  must refer to the same session.
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
registration state, and endpoints. The [RP web pages](../RP/web/) refer to a
fixed backend URL; make that destination configurable for each instance.
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

## Build and Publish a Docker Release

Use [`compose.yaml`](../compose.yaml) for image names and published defaults
and [`compose.build.yaml`](../compose.build.yaml) for the build definitions.
Set `DIDSSO_REGISTRY` and `DIDSSO_VERSION` in the build terminal, using a new
tag for the release. Build from the repository root and keep
[`.dockerignore`](../.dockerignore) in sync when new runtime files are added.

```powershell
docker compose config --images
docker compose -f compose.yaml -f compose.build.yaml build
```

Check that all five image references use the intended namespace and tag.
Run the local images with `docker compose up -d --no-build --pull never`
after stopping any setup that uses the same host ports. Complete one SSO
and one direct login. Then publish with
[`docker compose push`](https://docs.docker.com/reference/cli/docker/compose/push/)
using the same settings and
[GHCR authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
Verify that the new tag can be pulled for every service before updating
the defaults in `compose.yaml`. Use the
[Docker quick start](../README.md#docker-quick-start) to check the published
images independently of the local build.
