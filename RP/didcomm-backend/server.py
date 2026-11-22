from __future__ import annotations

import json
import os
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from did_peer_4 import resolve as resolve_peer_4

WORKSPACE_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(WORKSPACE_DIR))
sys.path.append(str(WORKSPACE_DIR / "zk-stark"))
sys.path.append(str(WORKSPACE_DIR / "zk-risc0"))

from sso_claims import claims_for_scopes, normalize_scopes
from evaluation_trace import (
    clear_measurements,
    elapsed_seconds,
    evaluation_enabled,
    measurements_for,
    record_event,
)

PROOF_BACKEND = os.environ.get("DIDSSO_PROOF_BACKEND", "risc0").strip().lower()
if PROOF_BACKEND == "stwo":
    from credential_stark import CREDENTIAL_FORMAT as ACTIVE_CREDENTIAL_FORMAT
    from credential_stark import create_registration_proof
elif PROOF_BACKEND == "risc0":
    from credential_risc0 import CREDENTIAL_FORMAT as ACTIVE_CREDENTIAL_FORMAT
    from credential_risc0 import create_registration_proof
else:
    raise RuntimeError("DIDSSO_PROOF_BACKEND must be either 'risc0' or 'stwo'")

from did_peer_service import (
    DIDCOMM_SERVICE_ENDPOINT,
    create_and_store_did,
    didcomm_service_endpoint,
    ensure_idp_pairwise_did,
    list_public_records,
    load_wallet,
    short_form_did,
)
from didcomm_service import message_thread_id, pack_encrypted_message, unpack_message


HOST = os.environ.get("DIDSSO_BIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("DIDSSO_PORT", "8771"))
DATA_DIR = Path(
    os.environ.get("DIDSSO_DATA_DIR", Path(__file__).resolve().parent.parent / "data")
).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
REGISTRATIONS_FILE = DATA_DIR / "idp_registrations.json"
SSO_SESSIONS_FILE = DATA_DIR / "sso_sessions.json"
USER_ACCOUNTS_FILE = DATA_DIR / "user_accounts.json"
TOKEN_GRANTS_FILE = DATA_DIR / "token_grants.json"
AUTHORIZATION_CONFIG_FILE = DATA_DIR / "authorization_config.json"

REGISTER_REQUEST_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/request"
REGISTER_ACCEPTED_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/accepted"
REGISTER_REJECTED_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/rejected"
SSO_CODE_FORWARD_TYPE = "https://did-sso.local/protocol/sso/1.0/code-forward"
SSO_CODE_EXCHANGE_TYPE = "https://did-sso.local/protocol/sso/1.0/code-exchange"
SSO_AUTHORIZATION_RESPONSE_TYPE = (
    "https://did-sso.local/protocol/sso/1.0/authorization-response"
)
SSO_ERROR_TYPE = "https://did-sso.local/protocol/sso/1.0/error"
SSO_RESULT_TYPE = "https://did-sso.local/protocol/sso/1.0/result"
SSO_CLAIMS_REQUEST_TYPE = "https://did-sso.local/protocol/sso/1.0/claims-request"
SSO_CLAIMS_RESPONSE_TYPE = "https://did-sso.local/protocol/sso/1.0/claims-response"
SSO_TOKEN_REFRESH_TYPE = "https://did-sso.local/protocol/sso/1.0/token-refresh"
SSO_TOKEN_REFRESHED_TYPE = "https://did-sso.local/protocol/sso/1.0/token-refreshed"
DID_LOGIN_CHALLENGE_TYPE = "https://did-sso.local/protocol/did-login/1.0/challenge"
DID_LOGIN_RESPONSE_TYPE = "https://did-sso.local/protocol/did-login/1.0/response"
DID_LOGIN_RESULT_TYPE = "https://did-sso.local/protocol/did-login/1.0/result"
PAIRWISE_RECOVERY_UPDATE_TYPE = "https://did-sso.local/protocol/sso/1.0/pairwise-recovery-update"
PAIRWISE_RECOVERY_ACCEPTED_TYPE = "https://did-sso.local/protocol/sso/1.0/pairwise-recovery-accepted"
AUTHCRYPT_REQUIRED_TYPES = {
    REGISTER_ACCEPTED_TYPE,
    REGISTER_REJECTED_TYPE,
    SSO_CODE_FORWARD_TYPE,
    SSO_AUTHORIZATION_RESPONSE_TYPE,
    SSO_CLAIMS_RESPONSE_TYPE,
    SSO_TOKEN_REFRESHED_TYPE,
    SSO_ERROR_TYPE,
    DID_LOGIN_RESPONSE_TYPE,
    PAIRWISE_RECOVERY_ACCEPTED_TYPE,
}
DIDSSO_DID_HEADER = "X-DIDSSO-DID"
RP_WEB_BASE_URL = os.environ.get(
    "DIDSSO_RP_WEB_PUBLIC_URL", "http://127.0.0.1:3002"
).rstrip("/")
IDP_WEB_PUBLIC_URL = os.environ.get(
    "DIDSSO_IDP_WEB_PUBLIC_URL", "https://127.0.0.1:3001"
).strip().rstrip("/")
WALLET_BACKEND_URL = os.environ.get(
    "DIDSSO_WALLET_BACKEND_URL", "http://127.0.0.1:8765"
).rstrip("/")

_ACTIVE_SSO_WORKERS: set[str] = set()
_ACTIVE_SSO_WORKERS_LOCK = Lock()
_SSO_SESSIONS_LOCK = Lock()
_USER_ACCOUNTS_LOCK = Lock()
_TOKEN_GRANTS_LOCK = Lock()
_TOKEN_FLOW_LOCK = Lock()
_PENDING_TOKEN_REQUESTS_LOCK = Lock()
_PENDING_TOKEN_REQUESTS: dict[str, dict] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default):
    if not path.exists():
        return default

    contents = path.read_text(encoding="utf-8-sig").strip()
    return json.loads(contents) if contents else default


def save_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def authorization_config() -> dict:
    # Earlier Docker images stored this configuration one level below the
    # shared data volume. Preserve it when the volume is reused after an update.
    legacy_config = DATA_DIR / "data" / "authorization_config.json"
    if not AUTHORIZATION_CONFIG_FILE.exists() and legacy_config.is_file():
        legacy_config.replace(AUTHORIZATION_CONFIG_FILE)
    stored = load_json(AUTHORIZATION_CONFIG_FILE, {"scopes": ["profile", "email"]})
    return {"scopes": normalize_scopes(stored.get("scopes", []))}


def update_authorization_config(request: dict) -> dict:
    config = {"scopes": normalize_scopes(request.get("scopes", []))}
    AUTHORIZATION_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    save_json(AUTHORIZATION_CONFIG_FILE, config)
    return config


def did_named(name: str) -> str:
    for record in load_wallet()["dids"]:
        if (
            record["name"] == name
            and didcomm_service_endpoint(record) == DIDCOMM_SERVICE_ENDPOINT
        ):
            return record["did"]

    return create_and_store_did(name)["did"]


def didcomm_endpoint_from_did(did: str) -> str:
    document = resolve_peer_4(did)
    for service in document.get("service", []):
        if service.get("type") != "DIDCommMessaging":
            continue

        service_endpoint = service.get("serviceEndpoint", "")
        if isinstance(service_endpoint, dict):
            endpoint = service_endpoint.get("uri", "")
        else:
            endpoint = str(service_endpoint)

        if endpoint:
            return endpoint

    raise ValueError("IdP DID document does not contain a DIDCommMessaging service endpoint")


def post_json(url: str, payload: dict, timeout: float = 180) -> None:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            response.read()
    except HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {error_body}") from error


def declared_sender_did(unpacked: dict) -> str:
    sender_did = str(unpacked.get("message", {}).get("from", "")).strip()
    if not sender_did:
        raise ValueError("DIDComm message has no sender DID")
    return sender_did


def require_authcrypt_sender(unpacked: dict) -> str:
    sender_did = declared_sender_did(unpacked)
    metadata = unpacked.get("metadata", {})
    encrypted_from = str(metadata.get("encrypted_from") or "")
    if (
        not metadata.get("encrypted")
        or not metadata.get("authenticated")
        or encrypted_from.split("#", 1)[0] != sender_did
    ):
        raise ValueError("DIDComm message has no matching authenticated sender key")
    return sender_did


def require_message_recipient(message: dict, expected_recipient_did: str) -> None:
    recipients = message.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    if not isinstance(recipients, list) or recipients != [expected_recipient_did]:
        raise ValueError("DIDComm message has a different intended recipient")


def validate_returned_claims(claims: object, expected_claims: list[str]) -> dict:
    if not isinstance(claims, dict):
        raise ValueError("IdP response has no valid claims object")
    if set(claims) != set(expected_claims):
        raise ValueError("IdP response contains unexpected or missing claims")
    return claims


def public_registration(registration: dict) -> dict:
    public_fields = {
        "idp_master_did",
        "rp_pairwise_did",
        "status",
        "sent_at",
        "accepted_at",
        "rejected_at",
        "reason",
    }
    return {
        key: value
        for key, value in registration.items()
        if key in public_fields
    }


def registrations_by_status() -> dict:
    registrations = load_json(REGISTRATIONS_FILE, [])
    return {
        status: [
            public_registration(item)
            for item in registrations
            if item.get("status") == status
        ]
        for status in ("pending", "accepted", "rejected")
    }


def sso_registrations_for_origin(registrations: list[dict], web_origin: str) -> list[dict]:
    return [
        registration
        for registration in registrations
        if registration.get("status") == "accepted"
        and registration.get("idp_web_origin") == web_origin
        and registration.get("idp_master_did")
    ]


def sso_registration_candidates() -> tuple[str, list[dict]]:
    web_origin = configured_idp_web_origin()
    registrations = sso_registrations_for_origin(
        load_json(REGISTRATIONS_FILE, []), web_origin
    )
    if len({registration["idp_master_did"] for registration in registrations}) > 1:
        raise ValueError("Multiple IdPs are associated with the configured SSO web origin")
    return web_origin, [
        registration
        for registration in registrations
        if registration.get("credential", {}).get("format") == ACTIVE_CREDENTIAL_FORMAT
    ]


def accepted_registration_count_for_active_backend() -> int:
    try:
        _, registrations = sso_registration_candidates()
    except ValueError:
        return 0
    return len(registrations)


def update_registration_from_idp_message(sender_did: str, message: dict) -> None:
    message_type = message.get("type", "")
    if message_type not in (REGISTER_ACCEPTED_TYPE, REGISTER_REJECTED_TYPE):
        return

    body = message.get("body", {})
    thread_id = message_thread_id(message)
    if body.get("idp_master_did") and body["idp_master_did"] != sender_did:
        raise ValueError("Registration response sender does not match the IdP master DID")
    idp_master_did = body.get("idp_master_did") or sender_did
    registrations = load_json(REGISTRATIONS_FILE, [])
    registration = None
    for item in reversed(registrations):
        if (
            item.get("idp_master_did") == idp_master_did
            and item.get("status") == "pending"
            and item.get("didcomm_thread_id") == thread_id
        ):
            registration = item
            break

    if registration is None:
        raise ValueError("Registration response belongs to an unknown DIDComm thread")

    registration["idp_master_did"] = idp_master_did
    if message_type == REGISTER_ACCEPTED_TYPE:
        web_origin = configured_idp_web_origin()
        bound_registrations = sso_registrations_for_origin(registrations, web_origin)
        registration["status"] = "accepted"
        registration["accepted_at"] = body.get("accepted_at", utc_now())
        registration["credential"] = body.get("credential", {})
        registration["rp_pairwise_did"] = ensure_idp_pairwise_did(idp_master_did)
        # A later registration for a different IdP must not replace the active
        # IdP at this web origin.
        if all(item["idp_master_did"] == idp_master_did for item in bound_registrations):
            registration["idp_web_origin"] = web_origin
    else:
        registration["status"] = "rejected"
        registration["rejected_at"] = body.get("rejected_at", utc_now())
        registration["reason"] = body.get("reason", "")

    save_json(REGISTRATIONS_FILE, registrations)


def accepted_registration_for_idp(idp_master_did: str) -> dict:
    registrations = load_json(REGISTRATIONS_FILE, [])
    for registration in reversed(registrations):
        if registration.get("status") != "accepted":
            continue
        if registration.get("idp_master_did") != idp_master_did:
            continue
        credential = registration.get("credential", {})
        if credential.get("format") == ACTIVE_CREDENTIAL_FORMAT:
            if not registration.get("rp_pairwise_did"):
                registration["rp_pairwise_did"] = ensure_idp_pairwise_did(
                    registration["idp_master_did"]
                )
                save_json(REGISTRATIONS_FILE, registrations)
            return registration

    raise ValueError(
        f"No accepted registration with a {PROOF_BACKEND.upper()} credential found for the selected IdP"
    )


def session_by_id(session_id: str) -> dict | None:
    with _SSO_SESSIONS_LOCK:
        for session in load_json(SSO_SESSIONS_FILE, []):
            if session.get("session_id") == session_id:
                return session
    return None


def upsert_session(session: dict) -> None:
    with _SSO_SESSIONS_LOCK:
        sessions = load_json(SSO_SESSIONS_FILE, [])
        for index, existing in enumerate(sessions):
            if existing.get("session_id") == session.get("session_id"):
                sessions[index] = {**existing, **session}
                break
        else:
            sessions.append(session)
        save_json(SSO_SESSIONS_FILE, sessions)


def logout_session(session_id: str) -> dict:
    session_id = str(session_id).strip()
    if not session_id:
        raise ValueError("Session ID is required")

    with _SSO_SESSIONS_LOCK:
        sessions = load_json(SSO_SESSIONS_FILE, [])
        for session in sessions:
            if session.get("session_id") != session_id:
                continue
            if session.get("status") != "logged_out":
                session.update(
                    {
                        "status": "logged_out",
                        "logged_out_at": utc_now(),
                        "claims": {},
                    }
                )
                save_json(SSO_SESSIONS_FILE, sessions)
            return {"status": "logged_out", "sessionId": session_id}

    raise ValueError("Unknown session")


def account_identifier_for_session(session: dict) -> str:
    identifier = session.get("user_pairwise_did") or session.get("user_short_did", "")
    if not identifier:
        raise ValueError("Session has no user pairwise DID")
    return identifier


def account_identity_values(account: dict) -> set[str]:
    return {
        str(account.get(field, "")).strip()
        for field in ("identifier", "user_pairwise_did", "user_short_did")
        if str(account.get(field, "")).strip()
    }


def matching_account_indexes(accounts: list[dict], identity_values: set[str]) -> list[int]:
    return [
        index
        for index, account in enumerate(accounts)
        if account_identity_values(account) & identity_values
    ]


def account_by_identifier(identifier: str) -> dict | None:
    identifier = str(identifier).strip()
    if not identifier:
        raise ValueError("Account DID is required")

    with _USER_ACCOUNTS_LOCK:
        accounts = load_json(USER_ACCOUNTS_FILE, [])
        matches = matching_account_indexes(accounts, {identifier})
        if len(matches) > 1:
            raise ValueError("DID is assigned to multiple RP accounts")
        return accounts[matches[0]] if matches else None


def upsert_account(account: dict) -> dict:
    user_pairwise_did = str(
        account.get("user_pairwise_did") or account.get("identifier", "")
    ).strip()
    user_short_did = str(account.get("user_short_did", "")).strip()
    if user_pairwise_did and user_short_did:
        if short_form_did(user_pairwise_did) != user_short_did:
            raise ValueError("Account full and short pairwise DIDs do not match")

    identity_values = account_identity_values(account)
    if not identity_values:
        raise ValueError("Account has no pairwise DID")

    with _USER_ACCOUNTS_LOCK:
        accounts = load_json(USER_ACCOUNTS_FILE, [])
        matches = matching_account_indexes(accounts, identity_values)
        if len(matches) > 1:
            raise ValueError("Pairwise DID would merge multiple RP accounts")
        if matches:
            index = matches[0]
            accounts[index] = {**accounts[index], **account, "updated_at": utc_now()}
            save_json(USER_ACCOUNTS_FILE, accounts)
            return accounts[index]

        account = {
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "notes": "",
            **account,
        }
        accounts.append(account)
        save_json(USER_ACCOUNTS_FILE, accounts)
        return account


def replacement_account_index(
    accounts: list[dict],
    previous_user_short_did: str,
    new_user_pairwise_did: str,
) -> int:
    previous_user_short_did = str(previous_user_short_did).strip()
    new_user_pairwise_did = str(new_user_pairwise_did).strip()
    if not previous_user_short_did or not new_user_pairwise_did:
        raise ValueError("Pairwise DID replacement data is incomplete")

    previous_matches = matching_account_indexes(accounts, {previous_user_short_did})
    if not previous_matches:
        raise ValueError("RP account to replace was not found")
    if len(previous_matches) > 1:
        raise ValueError("Previous pairwise DID is assigned to multiple RP accounts")

    target_index = previous_matches[0]
    new_identity_values = {
        new_user_pairwise_did,
        short_form_did(new_user_pairwise_did),
    }
    collisions = [
        index
        for index in matching_account_indexes(accounts, new_identity_values)
        if index != target_index
    ]
    if collisions:
        raise ValueError("New pairwise DID is already assigned to another RP account")
    return target_index


def validate_pairwise_replacement(
    previous_user_short_did: str,
    new_user_pairwise_did: str,
) -> None:
    with _USER_ACCOUNTS_LOCK:
        replacement_account_index(
            load_json(USER_ACCOUNTS_FILE, []),
            previous_user_short_did,
            new_user_pairwise_did,
        )


def replace_account_pairwise_did(
    previous_user_short_did: str,
    new_user_pairwise_did: str,
    claims: dict,
    session_id: str,
) -> dict:
    with _USER_ACCOUNTS_LOCK:
        accounts = load_json(USER_ACCOUNTS_FILE, [])
        index = replacement_account_index(
            accounts,
            previous_user_short_did,
            new_user_pairwise_did,
        )
        account = accounts[index]
        updated = {
            **account,
            "identifier": new_user_pairwise_did,
            "previous_user_pairwise_did": account.get("user_pairwise_did", ""),
            "previous_user_short_did": previous_user_short_did,
            "user_pairwise_did": new_user_pairwise_did,
            "user_short_did": short_form_did(new_user_pairwise_did),
            "claims": claims,
            "idp_master_did": (session_by_id(session_id) or {}).get("idp_master_did", ""),
            "last_session_id": session_id,
            "last_login_at": utc_now(),
            "replaced_at": utc_now(),
            "updated_at": utc_now(),
        }
        accounts[index] = updated
        save_json(USER_ACCOUNTS_FILE, accounts)
        return updated


def account_for_session(session_id: str) -> dict:
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown SSO session")
    if session.get("status") != "logged_in":
        raise ValueError("Session is not logged in")

    identifier = account_identifier_for_session(session)
    account = account_by_identifier(identifier)
    if account is None:
        account = upsert_account(
            {
                "identifier": identifier,
                "user_pairwise_did": session.get("user_pairwise_did", ""),
                "user_short_did": session.get("user_short_did", short_form_did(identifier)),
                "idp_master_did": session.get("idp_master_did", ""),
                "claims": session.get("claims", {}),
                "last_session_id": session_id,
                "last_login_at": session.get("logged_in_at", utc_now()),
            }
        )
    return account


def public_session_status(session: dict | None) -> dict:
    if not session:
        return {"status": "unknown"}
    return {
        key: session[key]
        for key in ("session_id", "status", "login_method", "error", "error_code")
        if key in session
    }


def save_account_notes(session_id: str, notes: str) -> dict:
    account = account_for_session(session_id)
    account["notes"] = notes
    return upsert_account(account)


def send_direct_login_challenge(user_pairwise_did: str) -> dict:
    account = account_by_identifier(user_pairwise_did)
    if account is None:
        raise ValueError("Pairwise DID is not registered at this RP yet")

    rp_master_did = did_named("rp-master")
    session_id = f"did-login-{uuid.uuid4()}"
    thread_id = uuid.uuid4().hex
    nonce = str(uuid.uuid4())
    session = {
        "session_id": session_id,
        "status": "did_challenge_sent",
        "login_method": "did_challenge",
        "created_at": utc_now(),
        "nonce": nonce,
        "didcomm_thread_id": thread_id,
        "rp_master_did": rp_master_did,
        "user_pairwise_did": user_pairwise_did,
        "user_short_did": short_form_did(user_pairwise_did),
        "redirect_url": f"{RP_WEB_BASE_URL}/sso/wait?session_id={session_id}",
    }
    upsert_session(session)

    packed = pack_encrypted_message(
        sender_did=rp_master_did,
        recipient_did=user_pairwise_did,
        body={
            "session_id": session_id,
            "nonce": nonce,
            "rp_master_did": rp_master_did,
            "user_pairwise_did": user_pairwise_did,
            "created_at": session["created_at"],
        },
        message_type=DID_LOGIN_CHALLENGE_TYPE,
        message_id=thread_id,
    )
    post_json(
        didcomm_endpoint_from_did(user_pairwise_did),
        {
            "packedMessage": packed,
            "senderDid": rp_master_did,
        },
    )

    upsert_session(
        {
            "session_id": session_id,
            "challenge_delivered_at": utc_now(),
        }
    )
    return session


def send_direct_login_result(session: dict) -> None:
    rp_master_did = session["rp_master_did"]
    user_pairwise_did = session["user_pairwise_did"]
    packed = pack_encrypted_message(
        sender_did=rp_master_did,
        recipient_did=user_pairwise_did,
        body={
            "session_id": session["session_id"],
            "nonce": session["nonce"],
            "status": "logged_in",
            "rp_master_did": rp_master_did,
            "user_pairwise_did": user_pairwise_did,
            "redirect_url": f"{RP_WEB_BASE_URL}/user?session_id={session['session_id']}",
        },
        message_type=DID_LOGIN_RESULT_TYPE,
        thread_id=session["didcomm_thread_id"],
    )
    post_json(
        didcomm_endpoint_from_did(user_pairwise_did),
        {
            "packedMessage": packed,
            "senderDid": rp_master_did,
        },
    )


def complete_direct_login(sender_did: str, message: dict) -> None:
    body = message.get("body", {})
    session_id = body["session_id"]
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown DID login session")
    if message_thread_id(message) != session.get("didcomm_thread_id"):
        raise ValueError("Direct DID login response belongs to a different DIDComm thread")
    if sender_did != session.get("user_pairwise_did"):
        raise ValueError("Direct DID login response came from a different DIDComm sender")
    recipients = message.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    if session.get("rp_master_did") not in recipients:
        raise ValueError("Direct DID login response has a different DIDComm recipient")
    if body.get("nonce") != session.get("nonce"):
        raise ValueError("DID login nonce does not match the RP challenge")
    if body.get("rp_master_did") != session.get("rp_master_did"):
        raise ValueError("Direct DID login response is intended for a different RP")

    user_pairwise_did = body.get("user_pairwise_did", "")
    if user_pairwise_did != session.get("user_pairwise_did"):
        raise ValueError("DID login response came for a different DID")

    account = account_by_identifier(user_pairwise_did)
    if account is None:
        raise ValueError("Pairwise DID is not registered at this RP yet")

    if session.get("status") == "failed":
        raise ValueError("DID login has already failed; use full DID SSO")
    if session.get("status") != "logged_in":
        try:
            claims = fresh_claims_for_account(account, session_id=session_id)
            logged_in_at = utc_now()
            upsert_account(
                {
                    **account,
                    "identifier": account.get("identifier") or user_pairwise_did,
                    "user_pairwise_did": user_pairwise_did,
                    "user_short_did": account.get("user_short_did") or short_form_did(user_pairwise_did),
                    "claims": claims,
                    "last_session_id": session_id,
                    "last_login_at": logged_in_at,
                }
            )
            upsert_session(
                {
                    "session_id": session_id,
                    "status": "logged_in",
                    "login_method": "did_challenge",
                    "logged_in_at": logged_in_at,
                    "claims": claims,
                }
            )
            record_event(session_id, "rp_logged_in")
        except Exception as error:
            upsert_session(
                {
                    "session_id": session_id,
                    "status": "failed",
                    "failed_at": utc_now(),
                    "error": f"Current IdP claims could not be retrieved: {error}",
                }
            )
            raise

    current_session = session_by_id(session_id)
    try:
        send_direct_login_result(current_session)
    except Exception:
        upsert_session({"session_id": session_id, "status": "failed", "failed_at": utc_now()})
        raise


def configured_idp_web_origin() -> str:
    address_error = "DIDSSO_IDP_WEB_PUBLIC_URL must be an HTTPS origin without a path"
    try:
        origin = urlparse(IDP_WEB_PUBLIC_URL)
        _ = origin.port
    except ValueError as error:
        raise ValueError(address_error) from error
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path
        or origin.params
        or origin.query
        or origin.fragment
        or any(char.isspace() or char == "\\" for char in IDP_WEB_PUBLIC_URL)
    ):
        raise ValueError(address_error)
    return IDP_WEB_PUBLIC_URL


def create_sso_session(user_pairwise_did: str) -> dict:
    idp_web_url, registrations = sso_registration_candidates()
    if not registrations:
        raise ValueError(
            f"No accepted {PROOF_BACKEND.upper()} registration is bound to the configured "
            "IdP web origin. Register the RP with that IdP before starting SSO."
        )
    registration = registrations[-1]
    rp_master_did = did_named("rp-master")
    rp_pairwise_did = registration["rp_pairwise_did"]
    session_id = f"sso-{uuid.uuid4()}"
    thread_id = uuid.uuid4().hex
    nonce = secrets.token_hex(32)
    state = str(uuid.uuid4())
    scopes = authorization_config()["scopes"]
    requested_claims = claims_for_scopes(scopes)
    authorization_query = urlencode(
        {
            "response_type": "code",
            "nonce": nonce,
            "state": state,
            "scope": " ".join(scopes),
        }
    )
    authorization_request_url = f"{idp_web_url}/sso?{authorization_query}"
    session = {
        "session_id": session_id,
        "status": "auth_request_created",
        "created_at": utc_now(),
        "nonce": nonce,
        "state": state,
        "didcomm_thread_id": thread_id,
        "idp_master_did": registration["idp_master_did"],
        "rp_master_did": rp_master_did,
        "rp_pairwise_did": rp_pairwise_did,
        "user_pairwise_did": user_pairwise_did,
        "user_short_did": short_form_did(user_pairwise_did),
        "requested_claims": requested_claims,
        "scopes": scopes,
        "login_method": "privacy_enhanced_sso",
        "proof_method": PROOF_BACKEND,
        "redirect_url": f"{RP_WEB_BASE_URL}/sso/wait?session_id={session_id}",
        "authorization_request_url": authorization_request_url,
    }
    upsert_session(session)
    post_json(
        f"{WALLET_BACKEND_URL}/sso/store-auth-request",
        {
            "sessionId": session_id,
            "nonce": nonce,
            "state": state,
            "didcommThreadId": thread_id,
            "responseType": "code",
            "scope": " ".join(scopes),
            "idpMasterDid": registration["idp_master_did"],
            "rpMasterDid": rp_master_did,
            "userPairwiseDid": user_pairwise_did,
            "redirectUrl": session["redirect_url"],
            "authorizationUrl": authorization_request_url,
            "createdAt": session["created_at"],
        },
    )
    return session


def complete_sso_code_forward(sender_did: str, body: dict) -> None:
    session_id = body["session_id"]
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown SSO session")
    if body.get("nonce") != session.get("nonce"):
        raise ValueError("SSO nonce does not match the RP authorization request")
    if body.get("state") != session.get("state"):
        raise ValueError("SSO state does not match the RP authorization request")
    if sender_did != session.get("user_pairwise_did"):
        raise ValueError("SSO code forward came from a different user pairwise DID")

    registration = accepted_registration_for_idp(session["idp_master_did"])
    proof_started_ns = time.perf_counter_ns()
    try:
        proof = create_registration_proof(
            registration["credential"],
            nonce=session["nonce"],
        )
    except Exception:
        record_event(
            session_id,
            "proof_generation",
            duration_seconds=elapsed_seconds(proof_started_ns),
            details={"backend": PROOF_BACKEND, "outcome": "error"},
        )
        raise
    record_event(
        session_id,
        "proof_generation",
        duration_seconds=elapsed_seconds(proof_started_ns),
        details={"backend": PROOF_BACKEND, "outcome": "accepted"},
    )

    rp_pairwise_did = registration["rp_pairwise_did"]
    exchange_request = {
        "session_id": session_id,
        "code": body["code"],
        "nonce": body["nonce"],
        "state": body["state"],
        "proof": proof,
    }
    if body.get("replace_id"):
        exchange_request["replace_id"] = body["replace_id"]
    else:
        exchange_request["user_short_did"] = short_form_did(sender_did)

    upsert_session(
        {
            "session_id": session_id,
            "status": "code_exchange_sent",
            "code_forwarded_at": utc_now(),
            "rp_pairwise_did": rp_pairwise_did,
            "replace_id": body.get("replace_id", ""),
        }
    )
    packed = pack_encrypted_message(
        sender_did=rp_pairwise_did,
        recipient_did=registration["idp_master_did"],
        body=exchange_request,
        message_type=SSO_CODE_EXCHANGE_TYPE,
        thread_id=session["didcomm_thread_id"],
    )
    post_json(
        didcomm_endpoint_from_did(registration["idp_master_did"]),
        {
            "packedMessage": packed,
            "senderDid": rp_pairwise_did,
        },
    )


def process_sso_code_forward(sender_did: str, body: dict) -> None:
    session_id = str(body.get("session_id", ""))
    try:
        complete_sso_code_forward(sender_did, body)
    except Exception as error:
        session = session_by_id(session_id)
        if session and session.get("status") not in {"logged_in", "failed"}:
            upsert_session(
                {
                    "session_id": session_id,
                    "status": "failed",
                    "failed_at": utc_now(),
                    "error_code": "code_exchange_failed",
                    "error": str(error),
                }
            )
            notify_plugin_of_sso_result(
                session_by_id(session_id) or session,
                "error",
                error_code="code_exchange_failed",
                error_message=str(error),
            )
        print(f"Asynchronous SSO processing failed for {session_id}: {error}")
    finally:
        with _ACTIVE_SSO_WORKERS_LOCK:
            _ACTIVE_SSO_WORKERS.discard(session_id)


def queue_sso_code_forward(sender_did: str, message: dict) -> dict:
    body = message.get("body", {})
    session_id = str(body.get("session_id", "")).strip()
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown SSO session")
    if message_thread_id(message) != session.get("didcomm_thread_id"):
        raise ValueError("SSO code forward belongs to a different DIDComm thread")
    if body.get("nonce") != session.get("nonce"):
        raise ValueError("SSO nonce does not match the RP authorization request")
    if body.get("state") != session.get("state"):
        raise ValueError("SSO state does not match the RP authorization request")
    if sender_did != session.get("user_pairwise_did"):
        raise ValueError("SSO code forward came from a different user pairwise DID")

    with _ACTIVE_SSO_WORKERS_LOCK:
        if session_id in _ACTIVE_SSO_WORKERS:
            return {"status": "accepted", "sessionId": session_id}
        if session.get("status") == "logged_in":
            return {"status": "completed", "sessionId": session_id}
        _ACTIVE_SSO_WORKERS.add(session_id)

    upsert_session(
        {
            "session_id": session_id,
            "status": "proof_pending",
            "code_forwarded_at": utc_now(),
        }
    )
    Thread(
        target=process_sso_code_forward,
        args=(sender_did, dict(body)),
        daemon=True,
        name=f"sso-proof-{session_id}",
    ).start()
    return {"status": "accepted", "sessionId": session_id}


def send_replacement_update_to_idp(session: dict, replace_id: str) -> None:
    idp_master_did = session.get("idp_master_did", "")
    rp_pairwise_did = session.get("rp_pairwise_did", "")
    if not idp_master_did:
        raise ValueError("Session has no IdP master DID")
    if not rp_pairwise_did:
        raise ValueError("Session has no RP pairwise DID")

    packed = pack_encrypted_message(
        sender_did=rp_pairwise_did,
        recipient_did=idp_master_did,
        body={
            "replace_id": replace_id,
            "new_user_short_did": session.get("user_short_did", ""),
            "session_id": session.get("session_id", ""),
        },
        message_type=PAIRWISE_RECOVERY_UPDATE_TYPE,
        thread_id=session["didcomm_thread_id"],
    )
    post_json(
        didcomm_endpoint_from_did(idp_master_did),
        {"packedMessage": packed, "senderDid": rp_pairwise_did},
    )


def token_expiry(value: str) -> datetime:
    try:
        expiry = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError("Token has an invalid expiry") from error
    if expiry.tzinfo is None:
        raise ValueError("Token expiry must include a timezone")
    return expiry


def token_bundle(body: dict) -> dict:
    fields = ("access_token", "refresh_token", "access_expires_at", "refresh_expires_at")
    bundle = {field: body.get(field) for field in fields}
    if any(not isinstance(value, str) or not value for value in bundle.values()):
        raise ValueError("IdP response has an incomplete token grant")
    now = datetime.now(timezone.utc)
    if token_expiry(bundle["access_expires_at"]) <= now:
        raise ValueError("IdP access token is already expired")
    if token_expiry(bundle["refresh_expires_at"]) <= now:
        raise ValueError("IdP refresh token is already expired")
    return bundle


def store_initial_grant(session: dict, body: dict, *, staged: bool) -> None:
    bundle = token_bundle(body)
    grant = {
        "user_pairwise_did": session["user_pairwise_did"],
        "idp_master_did": session["idp_master_did"],
        "rp_pairwise_did": session["rp_pairwise_did"],
        "requested_claims": session["requested_claims"],
        "status": "staged" if staged else "active",
        "sso_session_id": session["session_id"],
        "created_at": utc_now(),
        **bundle,
    }
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        grants = [
            item for item in grants
            if not (
                item.get("user_pairwise_did") == grant["user_pairwise_did"]
                and item.get("idp_master_did") == grant["idp_master_did"]
            )
        ]
        grants.append(grant)
        save_json(TOKEN_GRANTS_FILE, grants)


def activate_staged_grant(session: dict, previous_user_did: str) -> None:
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        found = False
        for grant in grants:
            if grant.get("sso_session_id") == session["session_id"] and grant.get("status") == "staged":
                grant["status"] = "active"
                grant["activated_at"] = utc_now()
                found = True
        if not found:
            raise ValueError("Replacement has no staged token grant")
        grants = [
            grant for grant in grants
            if not (
                grant.get("user_pairwise_did") == previous_user_did
                and grant.get("idp_master_did") == session["idp_master_did"]
            )
        ]
        save_json(TOKEN_GRANTS_FILE, grants)


def grant_for_account(account: dict) -> dict:
    user_did = str(account.get("user_pairwise_did", ""))
    idp_did = str(account.get("idp_master_did", ""))
    if not user_did or not idp_did:
        raise ValueError("No IdP token grant is linked to this RP account; use full DID SSO")
    with _TOKEN_GRANTS_LOCK:
        matches = [
            grant for grant in load_json(TOKEN_GRANTS_FILE, [])
            if grant.get("status") == "active"
            and grant.get("user_pairwise_did") == user_did
            and grant.get("idp_master_did") == idp_did
        ]
    if len(matches) != 1:
        raise ValueError("No unique active IdP token grant exists; use full DID SSO")
    return matches[0]


def replace_grant_tokens(grant: dict, body: dict) -> dict:
    bundle = token_bundle(body)
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        for index, stored in enumerate(grants):
            if stored.get("sso_session_id") != grant.get("sso_session_id"):
                continue
            if stored.get("status") != "active" or stored.get("refresh_token") != grant.get("refresh_token"):
                raise ValueError("Token grant changed during refresh")
            grants[index] = {**stored, **bundle, "refreshed_at": utc_now()}
            save_json(TOKEN_GRANTS_FILE, grants)
            return grants[index]
    raise ValueError("Token grant disappeared during refresh")


def deliver_token_request(grant: dict, message_type: str, token_field: str, response_type: str) -> dict:
    request_id = secrets.token_hex(32)
    thread_id = uuid.uuid4().hex
    pending = {
        "request_id": request_id,
        "didcomm_thread_id": thread_id,
        "grant": grant,
        "response_type": response_type,
        "event": Event(),
        "response": None,
        "error": None,
    }
    with _PENDING_TOKEN_REQUESTS_LOCK:
        _PENDING_TOKEN_REQUESTS[request_id] = pending
    try:
        packed = pack_encrypted_message(
            sender_did=grant["rp_pairwise_did"],
            recipient_did=grant["idp_master_did"],
            body={"request_id": request_id, token_field: grant[token_field]},
            message_type=message_type,
            message_id=thread_id,
        )
        post_json(
            didcomm_endpoint_from_did(grant["idp_master_did"]),
            {"packedMessage": packed, "senderDid": grant["rp_pairwise_did"]},
            timeout=45,
        )
        if not pending["event"].wait(45):
            raise ValueError("IdP did not answer the token request; use full DID SSO")
        if pending["error"]:
            raise ValueError(f"IdP rejected the token request: {pending['error']}")
        return pending["response"]
    finally:
        with _PENDING_TOKEN_REQUESTS_LOCK:
            _PENDING_TOKEN_REQUESTS.pop(request_id, None)


def complete_token_response(sender_did: str, message: dict) -> None:
    message_type = message.get("type")
    body = message.get("body", {})
    if not isinstance(body, dict):
        raise ValueError("IdP token response has an invalid body")
    thread_id = message_thread_id(message)
    request_id = str(body.get("request_id", ""))
    with _PENDING_TOKEN_REQUESTS_LOCK:
        pending = _PENDING_TOKEN_REQUESTS.get(request_id)
    if not pending:
        raise ValueError("Unexpected or replayed IdP token response")
    if thread_id != pending["didcomm_thread_id"]:
        raise ValueError("IdP token response belongs to a different DIDComm thread")
    grant = pending["grant"]
    if pending["event"].is_set():
        raise ValueError("Duplicate IdP token response")
    if message_type != pending["response_type"]:
        raise ValueError("IdP token response has the wrong message type")
    if sender_did != grant["idp_master_did"] or body.get("idp_master_did") != sender_did:
        raise ValueError("IdP token response has a different authenticated sender")
    require_message_recipient(message, grant["rp_pairwise_did"])
    validate_returned_claims(
        body.get("claims"),
        grant["requested_claims"],
    )
    if message_type == SSO_TOKEN_REFRESHED_TYPE:
        # Persist the rotated pair before acknowledging the DIDComm callback.
        # The IdP can then safely retire the previous refresh token.
        replace_grant_tokens(grant, body)
    pending["response"] = body
    pending["event"].set()


def reject_token_request(sender_did: str, body: dict, thread_id: str) -> None:
    request_id = str(body.get("request_id", ""))
    with _PENDING_TOKEN_REQUESTS_LOCK:
        pending = _PENDING_TOKEN_REQUESTS.get(request_id)
    if not pending:
        raise ValueError("Unexpected IdP token error")
    if thread_id != pending["didcomm_thread_id"]:
        raise ValueError("IdP token error belongs to a different DIDComm thread")
    if sender_did != pending["grant"]["idp_master_did"]:
        raise ValueError("Token error came from a different IdP")
    pending["error"] = str(body.get("error_message") or body.get("error_code") or "token rejected")
    pending["event"].set()


def fresh_claims_for_account(account: dict, session_id: str = "") -> dict:
    # One refresh at a time avoids spending the same rotating token in concurrent logins.
    with _TOKEN_FLOW_LOCK:
        grant = grant_for_account(account)
        if token_expiry(grant["refresh_expires_at"]) <= datetime.now(timezone.utc):
            raise ValueError("IdP refresh grant expired; use full DID SSO")
        refresh_required = (
            token_expiry(grant["access_expires_at"])
            <= datetime.now(timezone.utc) + timedelta(seconds=30)
        )
        mode = "refresh" if refresh_required else "access"
        request_started_ns = time.perf_counter_ns()
        try:
            if refresh_required:
                response = deliver_token_request(
                    grant,
                    SSO_TOKEN_REFRESH_TYPE,
                    "refresh_token",
                    SSO_TOKEN_REFRESHED_TYPE,
                )
            else:
                response = deliver_token_request(
                    grant,
                    SSO_CLAIMS_REQUEST_TYPE,
                    "access_token",
                    SSO_CLAIMS_RESPONSE_TYPE,
                )
        except Exception:
            record_event(
                session_id,
                "token_claims_round_trip",
                duration_seconds=elapsed_seconds(request_started_ns),
                details={"mode": mode, "outcome": "error"},
            )
            raise
        record_event(
            session_id,
            "token_claims_round_trip",
            duration_seconds=elapsed_seconds(request_started_ns),
            details={"mode": mode, "outcome": "accepted"},
        )
        return response["claims"]


def evaluation_token_state() -> dict:
    now = datetime.now(timezone.utc)
    with _TOKEN_GRANTS_LOCK:
        active = [
            grant
            for grant in load_json(TOKEN_GRANTS_FILE, [])
            if grant.get("status") == "active"
        ]
    usable = []
    for grant in active:
        try:
            refresh_expiry = token_expiry(grant.get("refresh_expires_at", ""))
        except ValueError:
            continue
        if refresh_expiry > now:
            usable.append(grant)
    return {
        "active_grant_count": len(active),
        "usable_grant_count": len(usable),
        "grants": [
            {
                "user_pairwise_did": grant.get("user_pairwise_did", ""),
                "idp_master_did": grant.get("idp_master_did", ""),
                "access_expires_at": grant.get("access_expires_at", ""),
                "refresh_expires_at": grant.get("refresh_expires_at", ""),
            }
            for grant in usable
        ],
    }


def expire_active_access_tokens_for_evaluation() -> dict:
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        changed = 0
        for grant in grants:
            if grant.get("status") != "active":
                continue
            try:
                refresh_expiry = token_expiry(grant.get("refresh_expires_at", ""))
            except ValueError:
                continue
            if refresh_expiry <= datetime.now(timezone.utc):
                continue
            grant["access_expires_at"] = expired_at
            changed += 1
        if changed:
            save_json(TOKEN_GRANTS_FILE, grants)
    return {"expired_grant_count": changed, "access_expires_at": expired_at}


def send_sso_result_to_plugin(
    session: dict,
    status: str,
    error_code: str = "",
    error_message: str = "",
) -> None:
    rp_master_did = session.get("rp_master_did", "")
    user_pairwise_did = session.get("user_pairwise_did", "")
    if not rp_master_did or not user_pairwise_did:
        raise ValueError("SSO session has no RP or user DID")

    packed = pack_encrypted_message(
        sender_did=rp_master_did,
        recipient_did=user_pairwise_did,
        body={
            "session_id": session["session_id"],
            "status": status,
            "rp_master_did": rp_master_did,
            "redirect_url": f"{RP_WEB_BASE_URL}/user?session_id={session['session_id']}",
            "error_code": error_code,
            "error_message": error_message,
        },
        message_type=SSO_RESULT_TYPE,
        thread_id=session["didcomm_thread_id"],
    )
    post_json(
        didcomm_endpoint_from_did(user_pairwise_did),
        {
            "packedMessage": packed,
            "senderDid": rp_master_did,
        },
    )


def notify_plugin_of_sso_result(
    session: dict,
    status: str,
    error_code: str = "",
    error_message: str = "",
) -> None:
    try:
        send_sso_result_to_plugin(
            session,
            status,
            error_code=error_code,
            error_message=error_message,
        )
    except Exception as error:
        upsert_session(
            {
                "session_id": session["session_id"],
                "plugin_result_delivery_error": str(error),
            }
        )


def store_authorization_response(sender_did: str, message: dict) -> None:
    if message.get("type") != SSO_AUTHORIZATION_RESPONSE_TYPE:
        raise ValueError("Unexpected SSO authorization response type")
    body = message.get("body", {})
    if not isinstance(body, dict):
        raise ValueError("SSO authorization response has an invalid body")
    session_id = str(body.get("session_id", ""))
    existing_session = session_by_id(session_id)
    if not existing_session:
        raise ValueError("Unknown SSO session")
    if message_thread_id(message) != existing_session.get("didcomm_thread_id"):
        raise ValueError("SSO authorization response belongs to a different DIDComm thread")
    if sender_did != existing_session.get("idp_master_did"):
        raise ValueError("SSO authorization response came from a different IdP DID")
    if body.get("idp_master_did") != sender_did:
        raise ValueError("SSO response body does not match the authenticated IdP DID")
    require_message_recipient(message, existing_session.get("rp_pairwise_did", ""))
    if existing_session.get("status") != "code_exchange_sent":
        raise ValueError("SSO authorization response is not expected for this session")
    if body.get("nonce") != existing_session.get("nonce"):
        raise ValueError("SSO authorization response nonce does not match the session")

    claims = validate_returned_claims(
        body.get("claims"),
        existing_session.get("requested_claims", []),
    )
    expected_replace_id = str(existing_session.get("replace_id", ""))
    received_replace_id = str(body.get("replace_id", ""))
    if received_replace_id != expected_replace_id:
        raise ValueError("SSO authorization response replacement ID does not match the session")
    session_update = {
        "session_id": session_id,
        "claims": claims,
        "idp_master_did": body.get("idp_master_did", ""),
    }
    if expected_replace_id:
        validate_pairwise_replacement(
            body.get("previous_user_short_did", ""),
            existing_session.get("user_pairwise_did", ""),
        )
        store_initial_grant(existing_session, body, staged=True)
        session_update["replace_id"] = expected_replace_id
        session_update["previous_user_short_did"] = body.get("previous_user_short_did", "")
        session_update["status"] = "replacement_update_sent"
        upsert_session(session_update)
        current_session = session_by_id(session_id) or {
            **existing_session,
            **session_update,
        }
        send_replacement_update_to_idp(
            current_session,
            expected_replace_id,
        )
        return

    store_initial_grant(existing_session, body, staged=False)
    account_persisted_at = utc_now()
    upsert_account(
        {
            "identifier": account_identifier_for_session(existing_session),
            "user_pairwise_did": existing_session.get("user_pairwise_did", ""),
            "user_short_did": existing_session.get("user_short_did", ""),
            "idp_master_did": existing_session.get("idp_master_did", ""),
            "claims": claims,
            "last_session_id": session_id,
            "last_login_at": account_persisted_at,
        }
    )
    record_event(session_id, "rp_account_persisted")
    session_update["status"] = "logged_in"
    session_update["logged_in_at"] = account_persisted_at
    upsert_session(session_update)
    record_event(session_id, "rp_logged_in")
    notify_plugin_of_sso_result(
        session_by_id(session_id) or {**existing_session, **session_update},
        "success",
    )


def complete_replacement_update(sender_did: str, body: dict, thread_id: str) -> None:
    session_id = body["session_id"]
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown replacement session")
    if thread_id != session.get("didcomm_thread_id"):
        raise ValueError("Replacement confirmation belongs to a different DIDComm thread")
    if sender_did != session.get("idp_master_did"):
        raise ValueError("Replacement confirmation came from a different IdP DID")
    if body.get("replace_id") != session.get("replace_id"):
        raise ValueError("Replacement confirmation ID does not match the session")
    if session.get("status") != "replacement_update_sent":
        raise ValueError("Replacement confirmation is not expected for this session")

    previous_account = account_by_identifier(session.get("previous_user_short_did", ""))
    if not previous_account:
        raise ValueError("Account being replaced no longer exists")
    replace_account_pairwise_did(
        previous_user_short_did=session.get("previous_user_short_did", ""),
        new_user_pairwise_did=session.get("user_pairwise_did", ""),
        claims=session.get("claims", {}),
        session_id=session_id,
    )
    activate_staged_grant(session, previous_account.get("user_pairwise_did", ""))
    upsert_session(
        {
            "session_id": session_id,
            "status": "logged_in",
            "logged_in_at": utc_now(),
            "replacement_completed_at": utc_now(),
        }
    )
    record_event(session_id, "rp_logged_in")
    notify_plugin_of_sso_result(session_by_id(session_id) or session, "success")


def store_sso_error_message(sender_did: str, body: dict, thread_id: str) -> None:
    session_id = body["session_id"]
    session = session_by_id(session_id)
    if not session:
        raise ValueError("Unknown SSO session")
    if thread_id != session.get("didcomm_thread_id"):
        raise ValueError("SSO error belongs to a different DIDComm thread")
    if sender_did != session.get("idp_master_did"):
        raise ValueError("SSO error came from a different IdP DID")
    if session.get("status") == "logged_in":
        return

    error_code = str(body.get("error_code", "sso_failed"))
    error_message = str(body.get("error_message", "The IdP rejected the SSO request"))
    upsert_session(
        {
            "session_id": session_id,
            "status": "failed",
            "failed_at": utc_now(),
            "error_code": error_code,
            "error": error_message,
        }
    )
    notify_plugin_of_sso_result(
        session_by_id(session_id) or session,
        "error",
        error_code=error_code,
        error_message=error_message,
    )


class RpDidCommHandler(BaseHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}

        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_json(self, status_code: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/evaluation/measurements":
            if not evaluation_enabled():
                self.send_error(404, "Not Found")
                return
            session_id = parse_qs(parsed.query).get("session_id", [""])[0]
            self.send_json(
                200,
                {
                    "enabled": True,
                    "component": "rp",
                    "proof_backend": PROOF_BACKEND,
                    "accepted_registration_count": (
                        accepted_registration_count_for_active_backend()
                    ),
                    "session_id": session_id,
                    "events": measurements_for(session_id),
                },
            )
            return

        if parsed.path == "/evaluation/token-state":
            if not evaluation_enabled():
                self.send_error(404, "Not Found")
                return
            self.send_json(200, evaluation_token_state())
            return

        if self.path == "/dids":
            self.send_json(200, list_public_records())
            return

        if self.path == "/master-did":
            self.send_json(200, {"masterDid": did_named("rp-master")})
            return

        if self.path == "/rp/registrations":
            self.send_json(200, registrations_by_status())
            return

        if self.path == "/rp/authorization-config":
            self.send_json(200, authorization_config())
            return

        if parsed.path == "/sso/session":
            session_id = parse_qs(parsed.query).get("session_id", [""])[0]
            self.send_json(200, public_session_status(session_by_id(session_id)))
            return

        if parsed.path == "/sso/account":
            session_id = parse_qs(parsed.query).get("session_id", [""])[0]
            self.send_json(200, account_for_session(session_id))
            return

        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        try:
            request = self.read_json_body()

            if self.path == "/evaluation/measurements/clear":
                if not evaluation_enabled():
                    self.send_error(404, "Not Found")
                    return
                clear_measurements(str(request.get("session_id", "")))
                self.send_json(200, {"status": "cleared"})
                return

            if self.path == "/evaluation/expire-access-tokens":
                if not evaluation_enabled():
                    self.send_error(404, "Not Found")
                    return
                self.send_json(200, expire_active_access_tokens_for_evaluation())
                return

            if self.path == "/create-did":
                self.send_json(200, create_and_store_did(str(request.get("name", ""))))
                return

            if self.path == "/rp/register-at-idp":
                rp_master_did = did_named("rp-master")
                idp_master_did = request["idpMasterDid"]
                idp_inbox_url = didcomm_endpoint_from_did(idp_master_did)
                rp_name = request.get("rpName", "Demo RP")
                thread_id = uuid.uuid4().hex
                body = {
                    "rp_name": rp_name,
                    "rp_master_did": rp_master_did,
                    "sent_at": utc_now(),
                }
                packed = pack_encrypted_message(
                    sender_did=rp_master_did,
                    recipient_did=idp_master_did,
                    body=body,
                    message_type=REGISTER_REQUEST_TYPE,
                    message_id=thread_id,
                )
                post_json(
                    idp_inbox_url,
                    {
                        "packedMessage": packed,
                        "senderDid": rp_master_did,
                    },
                )

                registrations = load_json(REGISTRATIONS_FILE, [])
                registrations.append(
                    {
                        "idp_master_did": idp_master_did,
                        "rp_master_did": rp_master_did,
                        "status": "pending",
                        "sent_at": utc_now(),
                        "didcomm_thread_id": thread_id,
                    }
                )
                save_json(REGISTRATIONS_FILE, registrations)
                self.send_json(200, {"status": "sent"})
                return

            if self.path == "/rp/authorization-config":
                self.send_json(200, update_authorization_config(request))
                return

            if self.path == "/didcomm/inbox":
                unpacked = unpack_message(
                    request["packedMessage"],
                    sender_did=request.get("senderDid", ""),
                )
                message = unpacked["message"]
                sender_did = declared_sender_did(unpacked)
                message_type = message.get("type")
                thread_id = message_thread_id(message)
                if message_type in AUTHCRYPT_REQUIRED_TYPES:
                    require_authcrypt_sender(unpacked)
                update_registration_from_idp_message(sender_did, message)
                response_status = 200
                if message_type == SSO_CODE_FORWARD_TYPE:
                    response = queue_sso_code_forward(
                        sender_did,
                        message,
                    )
                    response_status = 202
                elif message_type == DID_LOGIN_RESPONSE_TYPE:
                    complete_direct_login(sender_did, message)
                elif message_type == SSO_AUTHORIZATION_RESPONSE_TYPE:
                    store_authorization_response(sender_did, message)
                elif message_type in {SSO_CLAIMS_RESPONSE_TYPE, SSO_TOKEN_REFRESHED_TYPE}:
                    complete_token_response(sender_did, message)
                elif message_type == SSO_ERROR_TYPE:
                    error_body = message.get("body", {})
                    if error_body.get("request_id"):
                        reject_token_request(sender_did, error_body, thread_id)
                    else:
                        store_sso_error_message(sender_did, error_body, thread_id)
                elif message_type == PAIRWISE_RECOVERY_ACCEPTED_TYPE:
                    complete_replacement_update(
                        sender_did,
                        message.get("body", {}),
                        thread_id,
                    )
                if message_type != SSO_CODE_FORWARD_TYPE:
                    response = {"status": "received"}
                self.send_json(response_status, response)
                return

            if self.path == "/sso/start":
                if "idpMasterDid" in request:
                    self.send_json(400, {"error": "The SSO identity provider is configured by the RP"})
                    return
                user_pairwise_did = self.headers.get(DIDSSO_DID_HEADER, "").strip()
                if not user_pairwise_did:
                    raise ValueError(
                        "The DIDSSO plugin did not attach a pairwise DID"
                    )
                session = create_sso_session(user_pairwise_did)
                self.send_json(200, session)
                return

            if self.path == "/did-login/start":
                user_pairwise_did = self.headers.get(DIDSSO_DID_HEADER, "").strip()
                if not user_pairwise_did:
                    raise ValueError(
                        "The DIDSSO plugin did not attach a bound pairwise DID"
                    )
                self.send_json(200, send_direct_login_challenge(user_pairwise_did))
                return

            if self.path == "/sso/account/notes":
                account = save_account_notes(
                    session_id=request["sessionId"],
                    notes=str(request.get("notes", "")),
                )
                self.send_json(200, {"status": "saved", "account": account})
                return

            if self.path == "/sso/logout":
                self.send_json(200, logout_session(request.get("sessionId", "")))
                return

            self.send_error(404, "Not Found")
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def log_message(self, format: str, *args) -> None:
        print(f"[rp-didcomm] {self.address_string()} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), RpDidCommHandler)
    print(f"RP DIDComm backend listening on http://{HOST}:{PORT}")
    print(f"Registration proof: {PROOF_BACKEND.upper()}")
    server.serve_forever()


if __name__ == "__main__":
    main()
