# Troubleshooting Prototype Usage

Use this guide for errors that occur after starting the prototype, whether
you are running it in Docker or natively. For Windows installation or startup
problems, see [Native setup troubleshooting](NATIVE_SETUP_WINDOWS.md#troubleshooting).

- [Start with these checks](#start-with-these-checks)
- [Firefox extension and wallet](#firefox-extension-and-wallet)
- [IdP accounts and RP registration](#idp-accounts-and-rp-registration)
- [Privacy-Enhanced SSO and consent](#privacy-enhanced-sso-and-consent)
- [Direct DID-Based Login and claims](#direct-did-based-login-and-claims)
- [DID replacement](#did-replacement)
- [RP account page](#rp-account-page)

## Start with These Checks

1. Open the IdP at <https://127.0.0.1:3001> and the RP at
   <http://127.0.0.1:3002>. Use these exact addresses in the default setup.
   The extension is configured for the loopback IP, and wallet bindings
   distinguish different schemes, hostnames, and ports. If Firefox shows a
   self-signed certificate warning, accept an exception only for the expected
   local IdP.
2. Open the extension popup. **Wallet loaded.** means it can reach the wallet
   backend; it does not mean a DID is already bound to the RP. If the add-on
   is missing after a Firefox restart, load it again using the
   [Firefox setup instructions](../README.md#docker-quick-start).
3. If an error starts with `HTTP 500 from ...`, read the message after the
   address. The RP page can display a rejection from a different component,
   such as the wallet. With Docker, start with `docker compose ps` and use
   `docker compose logs --tail 50 wallet-backend` (or substitute
   `rp-didcomm` or `idp-didcomm`). With the native setup, check that
   component's terminal. For entries marked Firefox extension console, choose
   Inspect for the temporary add-on in `about:debugging`.

The first column indicates where to look. A backend response may appear inside
another component's error rather than as its own message. Statuses and
symptoms are labeled separately; a status is not necessarily an error.

Start a new attempt from the RP homepage if the current sign-in has failed.
Do not reset all state as a first troubleshooting step: the reset removes
accounts, DIDs, and registrations. 

## Firefox Extension and Wallet

| Message | Meaning and what to check |
| --- | --- |
| Firefox popup: **Could not reach the DID service.** / **DID-Service not responding or has an error.** | The popup could not load the wallet or complete DID creation. Check that the wallet backend is running at `127.0.0.1:8765` and reopen the popup. If the request still fails, check the wallet log rather than clicking Create DID repeatedly. |
| Firefox popup: **Please enter an alias for your DID.**<br>Wallet backend response: **A DID name is required** | Enter a non-empty alias when creating a DID manually. An alias is only a label in the wallet. |
| Wallet backend response: **No DID selected in the plugin**<br>Firefox extension console: **No DID is selected for manual DID management**<br>Wallet backend response: **Unknown DID** | Select a DID that is present in the popup. After a wallet reset, an old selection may no longer exist. For a first SSO, create and select a DID or enable automatic DID management. If the account already exists and its key was lost, use [DID replacement](#did-replacement). |
| Wallet backend response: **The manually selected DID is bound to another RP** / **This pairwise DID is already bound to another RP** / **This pairwise DID is already prepared for another RP** | Use a DID for the current RP. For a returning account, select the existing bound DID; for initial SSO with another RP, use a separate DID or enable automatic selection. Check that you did not switch between `localhost` and `127.0.0.1` or change the port. |
| RP page: **The DIDSSO plugin did not attach a pairwise DID** / **The DIDSSO plugin did not attach a bound pairwise DID** | Check that the add-on is loaded, that the wallet is reachable, and that the RP is open at its expected address. The bound variant comes from DID Login, which cannot create a new relationship. The extension console may show the underlying DID selection error. |
| Wallet backend response (can appear inside an RP page error): **SSO challenge does not match the RP origin observed by the plugin** / **The RP challenge DID does not match the stored RP binding** | The wallet could not match the challenge to the prepared browser origin or the stored RP identity. Use the original RP address and the correct DID. Keep the services running, close other sign-in attempts, and retry from the RP homepage. If the RP was reset or you switched setups, confirm that you are using the matching wallet and RP state. |

## IdP Accounts and RP Registration

| Message or symptom | Meaning and what to check |
| --- | --- |
| IdP page: **Invalid email or password** / **Authentication failed.** | At the IdP, use the email and password for the test account you created in this setup. The RP does not have a separate password. If recovery is intended, use the original IdP account, not a newly created one. |
| IdP page: **Invalid or expired session.** / **Session user was not found.**<br>IdP API response (not shown during normal SSO): **No active IdP session** | Sign in again at the IdP if the browser session is no longer usable. During SSO, being asked for credentials instead of reusing a browser session is normal. If the original user was removed by a reset, a new session alone cannot recover its old RP relationship. |
| IdP page: **Full name, preferred username, email, birthdate and password are required.** / **Email and password are required.** / **Preferred username is required.** | Complete the requested fields and submit the form again. |
| IdP page: **Could not hash password.** / **Could not update user profile.** / **Could not read user page.** | The IdP web server could not complete an account operation. Check its log. For a profile update, verify the IdP data directory is writable; if the page itself is missing in native execution, make sure the server was started from the `IdP` directory. |
| IdP page: **Could not load Master DID.** / **No Master DID available.**<br>IdP API response: **IdP backend is unavailable**<br>IdP admin API response: **Could not reach IdP DIDComm backend** | The IdP page depends on the Python IdP backend even if the Rust web server is up. Check `idp-didcomm` or its native terminal and reload the IdP page. If Copy failed. or Could not copy the value. appears for a displayed value, select and copy the full value manually. |
| RP admin page: **DIDComm backend error:**<br>IdP admin page: **Could not load RP requests.** / **The RP request response is invalid.** | Check the backend corresponding to the dashboard you are on. The RP dashboard calls the RP backend directly; the IdP dashboard reaches its backend through the IdP web server. Reload the request list after the service is available. |
| Symptom: Registration fails with a DID decoding, DIDComm endpoint, or connection error. | Copy the complete, current IdP Master DID from the IdP homepage using Copy Master DID. Use the IdP from the same Docker or native setup; the DID contains the endpoint used for delivery. A DID copied before a full reset may no longer be valid. |
| RP page (excerpt): **No accepted RISC0 registration is bound to the configured IdP web origin.**<br>RP backend response: **No accepted registration with a RISC0 credential found for the selected IdP** | Look under Accepted requests in RP Admin. Sending the request is not acceptance. Approve a pending request in IdP Admin and reload the RP list. The accepted registration must match the RP's configured IdP HTTPS origin and the proof backend used by both parties. Use the default origin unless intentionally configuring a different one. |
| RP backend response: **Multiple IdPs are associated with the configured SSO web origin** / **DIDSSO_IDP_WEB_PUBLIC_URL must be an HTTPS origin without a path** | In a custom setup, check the RP's IdP URL setting. Use the origin of the intended IdP (scheme, host, and port), without a page path. The origin must resolve to an unambiguous accepted IdP registration. Do not alter the browser's sign-in URL to work around this. |
| IdP admin page: **Unknown request** / **The registration decision failed.** | Reload the IdP's request list: the request might already have been handled. If it is still pending after an attempted approval, check whether the RP backend is reachable from the IdP and whether credential issuance succeeded. |
| RP admin page: **Could not load authorization scopes.** / **Could not save authorization scopes.**<br>RP backend response (prefix): **Unsupported scopes:** | Check the RP backend and its log, then use the scope checkboxes in RP Admin. To apply the changed scope selection to a user, run a new SSO with consent; existing grants do not pick up scope changes automatically. |

## Privacy-Enhanced SSO and Consent

| Message or symptom | Meaning and what to check |
| --- | --- |
| RP page: **Privacy-Enhanced SSO could not be started.** / **The RP backend did not return a login destination.**<br>Symptom: a network error at the RP login button | Check the RP backend on port `8771`, the accepted registration, and the extension's wallet status. If the backend returned an error, use the more specific message or the RP log. |
| IdP SSO page: **The authorization request is invalid.** / **The authorization request is missing required parameters or contains unsupported scopes.** | Start SSO from the RP button rather than opening or editing the IdP's generic SSO URL. If it recurs, check the RP's authorization scopes and the IdP backend log. |
| IdP SSO page: **Could not validate the IdP session.** / **Could not send request to IdP backend** / **Could not read response from IdP backend** | The IdP web server could not check the session or exchange data with its protocol backend. Check both IdP services, then start a fresh SSO from the RP. |
| IdP consent page: **Unknown or already used authentication** / **Authentication has expired** / **The consent response failed.** | The consent step needs a live authentication context. Start again from the RP if you reopened an old consent page, submitted it twice, or restarted the IdP backend. |
| RP waiting page (consent declined): **You must consent to sharing the requested data to use this service.** | The user declined consent. This is an expected end to the attempt. Start a new SSO only if you want to review the request again. |
| IdP status: **Consent recorded. Waiting for the DIDSSO plugin...**<br>Symptom: the browser stays on the IdP page | Verify that the add-on is active and can reach the wallet. Use the same tab for the whole sign-in. The extension console can show Could not process HTTPS DIDSSO authorization code or an authorization response rejection because the tab, origin, or state did not match. Close stale sign-in tabs and start a fresh attempt at the RP. |
| RP waiting page (normal progress): **Current status: proof_pending** / **Current status: code_exchange_sent** | The RP is processing the code or has sent the exchange request to the IdP. Proof generation can take about a minute on the reference setup and varies by machine. If the status never advances, check the RP and IdP backend logs rather than repeatedly submitting consent. |
| RP backend (can be shown on the RP waiting page): **Credential belongs to a different proof backend** / **Register this RP again to obtain a RISC Zero credential** | The RP could not use its stored credential to generate the proof. Use the same proof backend on both sides and obtain a registration credential from the current IdP for that backend. |
| RP waiting page: **The IdP rejected the DIDComm code exchange** / **The IdP rejected the SSO request.** | The RP may only show a summary. In the IdP backend log, OIDC code was already used, OIDC code has expired, Unknown OIDC code, or a nonce/state mismatch means you should start a fresh SSO. Registration proof was not accepted points instead to proof verification: check that both parties use the same proof backend and that the RP has a credential issued by the current IdP. For a native proof build issue, check the [RISC Zero setup](NATIVE_SETUP_WINDOWS.md#build-the-risc-zero-proof-tool). |
| RP waiting page error: **SSO status check failed:**<br>RP waiting page status: **Current status: unknown** | The RP page could not read the session or could not find a matching one. Check that the RP backend is responding and that you did not reopen a stale waiting page or switch between setups. Start again from the RP homepage. |

## Direct DID-Based Login and Claims

| Message | Meaning and what to check |
| --- | --- |
| Firefox extension console: **No pairwise DID is bound to this RP yet** / **The selected DID is not bound to this RP**<br>RP backend response: **Pairwise DID is not registered at this RP yet** | A DID in the wallet is not necessarily associated with an RP account. Use the DID from the last successful SSO or DID replacement at this RP. Run SSO first if this is a new account. |
| Wallet backend response (can appear inside an RP page error): **Direct DID login challenge does not match the selected plugin DID** / **No pairwise DID binding found for this direct DID login challenge** / **Direct DID login challenge does not match the bound RP** | The wallet could not match the challenge to its selected DID and RP binding. Do not change DID selection during login. After replacement, select the new DID in manual mode; if the replacement did not finish, check its result first. |
| RP backend error (can be shown inside an RP page error): **Current IdP claims could not be retrieved:** followed by **No IdP token grant is linked to this RP account**, **No unique active IdP token grant exists**, or **IdP refresh grant expired** | Direct DID-Based Login requires current claims in this prototype. A missing or unusable grant is not necessarily a DID error. Run Privacy-Enhanced SSO with the existing bound DID to authorize a new grant. |
| RP backend error (can appear inside an RP page error): **IdP did not answer the token request** / **IdP rejected the token request** | For a timeout or network error, check both protocol backends and their logs. If the IdP rejected the grant, run Privacy-Enhanced SSO again. An expired access token alone does not require new consent if the prototype can still refresh it. |
| RP page (fallback): **DID login failed.** | Check the accompanying RP or wallet error, if present. Confirm that a successful SSO has already established the account and that the intended DID is selected before retrying. |

## DID Replacement

| Message or symptom | Meaning and what to check |
| --- | --- |
| IdP SSO page: **An account already exists for this service. Re-enter your IdP credentials to authorize replacing its pairwise DID.**<br>IdP backend response: **An RP account already exists for this IdP account; activate Replace pairwise DID** | The IdP has an existing relationship and the current DID is different. If you intended an ordinary sign-in and still have the old key, return to the RP and choose the original DID. If replacing it, re-enter the credentials for the original IdP account and confirm Replace DID and continue. |
| IdP backend response: **Pairwise DID replacement requires password reauthentication**<br>IdP SSO page: **Pairwise DID replacement must be selected to continue this recovery flow.** | A reused browser session is not enough for replacement. Keep Replace pairwise DID selected and authenticate with your IdP password. |
| IdP SSO page (excerpt): **No existing account was found for this service.**<br>IdP backend response: **No existing RP account can be replaced for this IdP account** | No matching relationship was found for the active IdP account and RP. Check that you are using the original IdP account and the same RP setup. Leave the checkbox disabled only if you intend to create a new account, not to recover the old one. |
| IdP backend response: **This pairwise DID is already assigned to another account at this RP**<br>RP backend response: **New pairwise DID is already assigned to another RP account** | A DID already used by another account cannot replace yours. Select a fresh, unused DID for replacement. |
| RP waiting page: **The IdP rejected the pairwise DID replacement update**<br>RP backend response: **RP account to replace was not found** / **Account being replaced no longer exists** | Recovery requires the original relationship record at the IdP and the account at the RP. Check that those services are using their original data and inspect the RP and IdP logs. Losing only the wallet can be recoverable; deleting the required IdP or RP records cannot be fixed by creating a new wallet DID. |

## RP Account Page

| Message | Meaning and what to check |
| --- | --- |
| RP account page: **Session is not logged in.**<br>RP backend response: **Unknown SSO session**<br>RP account page (fallback): **Could not load the RP account.** | Use a fresh login from the RP homepage. An old account-page link may refer to a session that is no longer valid. If the new login finishes but the account still fails to load, check the RP backend log. |
| RP account page (fallback): **Could not save.** / **Logout failed.** | Check whether the RP backend is still available. If the session is invalid, sign in again before editing. If the failure recurs in a fresh session, use the RP log to identify which account operation failed. |
