from __future__ import annotations

import json
import hashlib
import hmac
import os
import signal
import sys
import time
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from did_peer_4 import resolve as resolve_peer_4

WORKSPACE_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(WORKSPACE_DIR))
sys.path.append(str(WORKSPACE_DIR / "STWO"))
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
    from credential_stark import (
        issue_registration_credential,
        registration_verifier_config,
        verify_registration_proof,
    )
elif PROOF_BACKEND == "risc0":
    from credential_risc0 import (
        issue_registration_credential,
        registration_verifier_config,
        start_verifier_service,
        stop_verifier_service,
        verify_registration_proof,
    )
else:
    raise RuntimeError("DIDSSO_PROOF_BACKEND must be either 'risc0' or 'stwo'")

from did_peer_service import create_and_store_did, list_public_records, load_wallet
from didcomm_service import message_thread_id, pack_encrypted_message, unpack_message


HOST = os.environ.get("DIDSSO_BIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("DIDSSO_PORT", "8770"))
DATA_DIR = Path(
    os.environ.get("DIDSSO_DATA_DIR", Path(__file__).resolve().parent.parent / "data")
).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
PENDING_FILE = DATA_DIR / "pending_rp_requests.json"
REGISTERED_FILE = DATA_DIR / "registered_rps.json"
USERS_FILE = DATA_DIR / "users.json"
OIDC_CODES_FILE = DATA_DIR / "oidc_codes.json"
USER_DID_LINKS_FILE = DATA_DIR / "sso_user_did_links.json"
TOKEN_GRANTS_FILE = DATA_DIR / "sso_token_grants.json"
STWO_REGISTRATION_SIGNING_KEY_FILE = DATA_DIR / "registration_signing_key.json"
RISC0_REGISTRATION_SIGNING_KEY_FILE = (
    DATA_DIR / "registration_signing_key_risc0_p256.json"
)
REGISTER_REQUEST_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/request"
ACCEPTED_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/accepted"
REJECTED_TYPE = "https://did-sso.local/protocol/rp-registration/1.0/rejected"
SSO_CODE_EXCHANGE_TYPE = "https://did-sso.local/protocol/sso/1.0/code-exchange"
SSO_AUTHORIZATION_RESPONSE_TYPE = (
    "https://did-sso.local/protocol/sso/1.0/authorization-response"
)
SSO_CLAIMS_REQUEST_TYPE = "https://did-sso.local/protocol/sso/1.0/claims-request"
SSO_CLAIMS_RESPONSE_TYPE = "https://did-sso.local/protocol/sso/1.0/claims-response"
SSO_TOKEN_REFRESH_TYPE = "https://did-sso.local/protocol/sso/1.0/token-refresh"
SSO_TOKEN_REFRESHED_TYPE = "https://did-sso.local/protocol/sso/1.0/token-refreshed"
SSO_ERROR_TYPE = "https://did-sso.local/protocol/sso/1.0/error"
PAIRWISE_RECOVERY_UPDATE_TYPE = "https://did-sso.local/protocol/sso/1.0/pairwise-recovery-update"
PAIRWISE_RECOVERY_ACCEPTED_TYPE = "https://did-sso.local/protocol/sso/1.0/pairwise-recovery-accepted"
IDP_DIDCOMM_ENDPOINT = os.environ.get(
    "DIDSSO_DIDCOMM_ENDPOINT", "http://127.0.0.1:8770/didcomm/inbox"
)
DIDSSO_CODE_HEADER = "X-DIDSSO-Code"
DIDSSO_MESSAGE_TYPE_HEADER = "X-DIDSSO-Message-Type"
DIDSSO_REPLACE_ID_HEADER = "X-DIDSSO-Replace-ID"
INTERNAL_PROXY_HEADER = "X-DIDSSO-Internal-Proxy"
INTERNAL_USER_SUBJECT_HEADER = "X-DIDSSO-User-Subject-Hex"
DIDSSO_ERROR_HEADER = "X-DIDSSO-Error"
DIDSSO_STATE_HEADER = "X-DIDSSO-State"
SSO_AUTHENTICATIONS: dict[str, dict] = {}
AUTHENTICATION_LIFETIME_SECONDS = 300
CODE_LIFETIME_SECONDS = 300
ACCESS_TOKEN_LIFETIME = timedelta(minutes=30)
REFRESH_GRANT_LIFETIME = timedelta(days=7)
_USER_DID_LINKS_LOCK = Lock()
_TOKEN_GRANTS_LOCK = Lock()


def registration_signing_key_file() -> Path:
    if PROOF_BACKEND == "risc0":
        return RISC0_REGISTRATION_SIGNING_KEY_FILE
    return STWO_REGISTRATION_SIGNING_KEY_FILE


class SsoProtocolError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default):
    if not path.exists():
        return default

    contents = path.read_text(encoding="utf-8-sig").strip()
    return json.loads(contents) if contents else default


def save_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def did_named(name: str) -> str:
    for record in load_wallet()["dids"]:
        if record["name"] == name and didcomm_endpoint(record) == IDP_DIDCOMM_ENDPOINT:
            return record["did"]

    return create_and_store_did(name)["did"]


def didcomm_endpoint(record: dict) -> str:
    service_endpoint = record["inputDocument"]["service"][0]["serviceEndpoint"]
    if isinstance(service_endpoint, dict):
        return service_endpoint.get("uri", "")
    return str(service_endpoint)


def didcomm_endpoint_from_did(did: str) -> str:
    document = resolve_peer_4(did)
    for service in document.get("service", []):
        if service.get("type") != "DIDCommMessaging":
            continue

        service_endpoint = service.get("serviceEndpoint", "")
        endpoint = (
            service_endpoint.get("uri", "")
            if isinstance(service_endpoint, dict)
            else str(service_endpoint)
        )
        if endpoint and endpoint != "didcomm:transport/queue":
            return endpoint

    raise ValueError("DID document does not contain a DIDCommMessaging service endpoint")


def post_json(url: str, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=180) as response:
            response.read()
    except HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {error_body}") from error


def declared_sender_did(unpacked: dict) -> str:
    sender_did = str(unpacked.get("message", {}).get("from", "")).strip()
    if not sender_did:
        raise ValueError("DIDComm message has no sender DID")
    return sender_did


def authcrypt_sender_did(unpacked: dict) -> str:
    """Bind a logical sender to the authenticated DIDComm key."""
    sender_did = declared_sender_did(unpacked)
    metadata = unpacked.get("metadata", {})
    sender_key = str(metadata.get("encrypted_from") or "")
    if not metadata.get("encrypted") or not metadata.get("authenticated"):
        raise PermissionError("DIDComm message requires authenticated encryption")
    if not sender_key or sender_key.rpartition("#")[0] != sender_did:
        raise PermissionError("DIDComm sender DID does not match the authenticated key")
    return sender_did


def find_user_by_email(email: str) -> dict | None:
    for user in load_json(USERS_FILE, []):
        if user.get("email") == email:
            return user
    return None


def find_user_by_subject(subject: str) -> dict | None:
    for user in load_json(USERS_FILE, []):
        if user_subject(user) == subject:
            return user
    return None


def verify_user_password(user: dict, password: str) -> bool:
    try:
        return PasswordHasher().verify(user.get("password_hash", ""), password)
    except (InvalidHashError, VerifyMismatchError):
        return False


def user_subject(user: dict) -> str:
    return user.get("subject") or f"user:{user['email']}"


def selected_claims(user: dict, requested: list[str]) -> dict:
    allowed = {
        "name": user.get("name", ""),
        "preferred_username": user.get("username", ""),
        "email": user.get("email", ""),
        "birthdate": user.get("birthdate", ""),
    }
    return {name: value for name, value in allowed.items() if name in requested}


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)


def save_token_grants(grants: list[dict]) -> None:
    """Replace the grant file atomically while the caller holds its process lock."""
    temporary = TOKEN_GRANTS_FILE.with_name(
        f".{TOKEN_GRANTS_FILE.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        temporary.write_text(json.dumps(grants, indent=2), encoding="utf-8")
        os.replace(temporary, TOKEN_GRANTS_FILE)
    finally:
        temporary.unlink(missing_ok=True)


def issue_token_grant(code_record: dict, rp_pairwise_did: str) -> dict:
    """Issue a new seven-day grant only after the credential proof has passed."""
    now = datetime.now(timezone.utc)
    grant_expiry = now + REFRESH_GRANT_LIFETIME
    access_expiry = min(now + ACCESS_TOKEN_LIFETIME, grant_expiry)
    access_token = new_opaque_token()
    refresh_token = new_opaque_token()
    subject = code_record["user_subject"]
    grant = {
        "grant_id": f"grant-{uuid.uuid4()}",
        "user_subject": subject,
        "rp_pairwise_did": rp_pairwise_did,
        "allowed_scopes": normalize_scopes(code_record.get("scopes", [])),
        "access_token_hash": token_digest(access_token),
        "access_expires_at": access_expiry.isoformat(),
        "current_refresh_token_hash": token_digest(refresh_token),
        "consumed_refresh_token_hashes": [],
        "refresh_expires_at": grant_expiry.isoformat(),
        "issued_at": now.isoformat(),
        "revoked": False,
    }
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        grants.append(grant)
        save_token_grants(grants)
    return {
        "grant_id": grant["grant_id"],
        "access_token": access_token,
        "refresh_token": refresh_token,
        "access_expires_at": grant["access_expires_at"],
        "refresh_expires_at": grant["refresh_expires_at"],
    }


def revoke_previous_grants(
    user_subject: str,
    rp_pairwise_did: str,
    current_grant_id: str,
) -> None:
    """Retire old grants only after the RP acknowledged storing the new one."""
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        for grant in grants:
            if (
                grant.get("user_subject") == user_subject
                and grant.get("rp_pairwise_did") == rp_pairwise_did
                and grant.get("grant_id") != current_grant_id
            ):
                grant["revoked"] = True
        save_token_grants(grants)


def require_request_id(request: dict) -> str:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise ValueError("Token request has no valid request ID")
    return request_id


def current_grant_claims(grant: dict, request_id: str) -> dict:
    user = find_user_by_subject(grant["user_subject"])
    if not user:
        raise PermissionError("User account no longer exists")
    claims = selected_claims(user, claims_for_scopes(grant["allowed_scopes"]))
    idp_master_did = did_named("idp-master")
    return {
        "request_id": request_id,
        "claims": claims,
        "idp_master_did": idp_master_did,
    }


def claims_for_access_token(rp_pairwise_did: str, request: dict) -> dict:
    request_id = require_request_id(request)
    token = request.get("access_token")
    if not isinstance(token, str) or not token:
        raise PermissionError("Access token is missing")
    digest = token_digest(token)
    now = datetime.now(timezone.utc)
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        grant = next(
            (
                grant for grant in grants
                if hmac.compare_digest(grant.get("access_token_hash", ""), digest)
            ),
            None,
        )
        if (
            not grant
            or grant.get("revoked")
            or grant.get("rp_pairwise_did") != rp_pairwise_did
            or datetime.fromisoformat(grant["access_expires_at"]) <= now
            or datetime.fromisoformat(grant["refresh_expires_at"]) <= now
        ):
            raise PermissionError("Access token is invalid or expired")
        return current_grant_claims(grant, request_id)


def rotate_refresh_token(rp_pairwise_did: str, request: dict) -> dict:
    request_id = require_request_id(request)
    token = request.get("refresh_token")
    if not isinstance(token, str) or not token:
        raise PermissionError("Refresh token is missing")
    digest = token_digest(token)
    now = datetime.now(timezone.utc)
    with _TOKEN_GRANTS_LOCK:
        grants = load_json(TOKEN_GRANTS_FILE, [])
        for grant in grants:
            if any(
                hmac.compare_digest(consumed, digest)
                for consumed in grant.get("consumed_refresh_token_hashes", [])
            ):
                if grant.get("rp_pairwise_did") == rp_pairwise_did:
                    grant["revoked"] = True
                    save_token_grants(grants)
                raise PermissionError("Refresh token replay detected; grant revoked")
        grant = next(
            (
                grant for grant in grants
                if hmac.compare_digest(
                    grant.get("current_refresh_token_hash", ""), digest
                )
            ),
            None,
        )
        if (
            not grant
            or grant.get("revoked")
            or grant.get("rp_pairwise_did") != rp_pairwise_did
            or datetime.fromisoformat(grant["refresh_expires_at"]) <= now
        ):
            raise PermissionError("Refresh token is invalid or expired")

        # Resolve the current claims before committing the one-time rotation.
        body = current_grant_claims(grant, request_id)
        access_token = new_opaque_token()
        refresh_token = new_opaque_token()
        access_expiry = min(
            now + ACCESS_TOKEN_LIFETIME,
            datetime.fromisoformat(grant["refresh_expires_at"]),
        )
        grant["consumed_refresh_token_hashes"].append(digest)
        grant["current_refresh_token_hash"] = token_digest(refresh_token)
        grant["access_token_hash"] = token_digest(access_token)
        grant["access_expires_at"] = access_expiry.isoformat()
        save_token_grants(grants)
        body.update(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "access_expires_at": grant["access_expires_at"],
                "refresh_expires_at": grant["refresh_expires_at"],
            }
        )
        return body


def send_grant_response(
    rp_pairwise_did: str,
    body: dict,
    message_type: str,
    thread_id: str,
) -> None:
    idp_master_did = did_named("idp-master")
    packed = pack_encrypted_message(
        sender_did=idp_master_did,
        recipient_did=rp_pairwise_did,
        body=body,
        message_type=message_type,
        thread_id=thread_id,
    )
    post_json(
        didcomm_endpoint_from_did(rp_pairwise_did),
        {"packedMessage": packed, "senderDid": idp_master_did},
    )


def store_oidc_code(record: dict) -> None:
    codes = load_json(OIDC_CODES_FILE, [])
    codes.append(record)
    save_json(OIDC_CODES_FILE, codes)


def oidc_code(code: str) -> dict:
    codes = load_json(OIDC_CODES_FILE, [])
    for item in codes:
        if item.get("code") != code:
            continue
        if item.get("used"):
            raise ValueError("OIDC code was already used")
        if datetime.fromisoformat(item["expires_at"]) <= datetime.now(timezone.utc):
            raise ValueError("OIDC code has expired")
        return item
    raise ValueError("Unknown OIDC code")


def consume_oidc_code(code: str) -> dict:
    oidc_code(code)
    codes = load_json(OIDC_CODES_FILE, [])
    for item in codes:
        if item.get("code") == code:
            item["used"] = True
            item["used_at"] = utc_now()
            save_json(OIDC_CODES_FILE, codes)
            return item
    raise ValueError("Unknown OIDC code")


def latest_user_did_link(subject: str, rp_pairwise_did: str) -> dict | None:
    with _USER_DID_LINKS_LOCK:
        links = load_json(USER_DID_LINKS_FILE, [])
        for link in reversed(links):
            if link.get("user_subject") != subject:
                continue
            if link.get("rp_pairwise_did") != rp_pairwise_did:
                continue
            if link.get("user_short_did"):
                return link
    return None


def current_user_did_links(links: list[dict], rp_pairwise_did: str) -> list[dict]:
    current_by_subject: dict[str, dict] = {}
    for link in links:
        if link.get("rp_pairwise_did") != rp_pairwise_did:
            continue
        subject = str(link.get("user_subject", "")).strip()
        if subject and link.get("user_short_did"):
            current_by_subject[subject] = link
    return list(current_by_subject.values())


def reject_short_did_collision(
    links: list[dict],
    rp_pairwise_did: str,
    user_short_did: str,
    user_subject: str,
) -> None:
    conflicting_subjects = {
        str(link.get("user_subject", ""))
        for link in current_user_did_links(links, rp_pairwise_did)
        if link.get("user_short_did") == user_short_did
        and link.get("user_subject") != user_subject
    }
    if conflicting_subjects:
        raise SsoProtocolError(
            "did_already_assigned",
            "This pairwise DID is already assigned to another account at this RP",
        )


def validate_user_did_assignment(
    rp_pairwise_did: str,
    user_short_did: str,
    user_subject: str,
) -> None:
    with _USER_DID_LINKS_LOCK:
        reject_short_did_collision(
            load_json(USER_DID_LINKS_FILE, []),
            rp_pairwise_did,
            user_short_did,
            user_subject,
        )


def update_user_did_link_for_replacement(
    replace_id: str,
    new_user_short_did: str,
    rp_pairwise_did: str,
) -> dict:
    new_user_short_did = str(new_user_short_did).strip()
    if not new_user_short_did:
        raise ValueError("Replacement update has no new user short DID")

    with _USER_DID_LINKS_LOCK:
        links = load_json(USER_DID_LINKS_FILE, [])
        matches = [link for link in links if link.get("replace_id") == replace_id]
        if len(matches) != 1:
            raise ValueError("Replacement ID is unknown or ambiguous")

        link = matches[0]
        if link.get("rp_pairwise_did") != rp_pairwise_did:
            raise ValueError("Replacement update came from a different RP pairwise DID")
        reject_short_did_collision(
            links,
            rp_pairwise_did,
            new_user_short_did,
            str(link.get("user_subject", "")),
        )
        if link.get("user_short_did") == new_user_short_did and link.get("replaced_at"):
            return link
        link["previous_user_short_did"] = link.get("user_short_did", "")
        link["user_short_did"] = new_user_short_did
        link["replaced_at"] = utc_now()
        save_json(USER_DID_LINKS_FILE, links)
        return link


def mark_user_did_link_replacement(replace_id: str, link_to_mark: dict) -> dict:
    with _USER_DID_LINKS_LOCK:
        links = load_json(USER_DID_LINKS_FILE, [])
        matches = [
            link
            for link in links
            if link.get("linked_at") == link_to_mark.get("linked_at")
            and link.get("user_subject") == link_to_mark.get("user_subject")
            and link.get("rp_pairwise_did") == link_to_mark.get("rp_pairwise_did")
        ]
        if len(matches) != 1:
            raise ValueError("DID link to replace is unknown or ambiguous")
        link = matches[0]
        link["replace_id"] = replace_id
        link["replacement_started_at"] = utc_now()
        save_json(USER_DID_LINKS_FILE, links)
        return link


def authenticate_sso(request: dict) -> dict:
    user = find_user_by_email(str(request.get("email", "")))
    if not user or not verify_user_password(user, str(request.get("password", ""))):
        raise PermissionError("Invalid email or password")

    return authenticate_sso_user(user, request, authentication_method="password")


def authenticate_sso_session(request: dict, subject: str) -> dict:
    if request.get("replacePairwiseDid") is True:
        raise PermissionError(
            "Pairwise DID replacement requires password reauthentication"
        )
    user = find_user_by_subject(subject)
    if not user:
        raise PermissionError("The IdP session user no longer exists")

    return authenticate_sso_user(user, request, authentication_method="session")


def authenticate_sso_user(
    user: dict,
    request: dict,
    *,
    authentication_method: str,
) -> dict:
    if request.get("responseType") != "code":
        raise ValueError("Only the authorization code response type is supported")
    scopes = normalize_scopes(request.get("scopes", []))
    nonce = str(request.get("nonce", "")).strip()
    state = str(request.get("state", "")).strip()
    if not nonce:
        raise ValueError("Authorization nonce is required")
    if not state:
        raise ValueError("Authorization state is required")
    replacement_requested = request.get("replacePairwiseDid", False)
    if not isinstance(replacement_requested, bool):
        raise ValueError("Pairwise DID replacement flag must be a boolean")
    claims = selected_claims(user, claims_for_scopes(scopes))
    authentication_id = f"auth-{uuid.uuid4()}"
    expires_at = datetime.now(timezone.utc).timestamp() + AUTHENTICATION_LIFETIME_SECONDS
    SSO_AUTHENTICATIONS[authentication_id] = {
        "expires_at": expires_at,
        "user_subject": user_subject(user),
        "claims": claims,
        "scopes": scopes,
        "nonce": nonce,
        "state": state,
        "replace_pairwise_did": replacement_requested,
        "authentication_method": authentication_method,
    }
    return {
        "status": "authenticated",
        "authenticationId": authentication_id,
        "claims": claims,
        "expiresIn": AUTHENTICATION_LIFETIME_SECONDS,
    }


def issue_sso_code(request: dict) -> dict:
    authentication_id = str(request.get("authenticationId", ""))
    authentication = SSO_AUTHENTICATIONS.pop(authentication_id, None)
    if not authentication:
        raise ValueError("Unknown or already used authentication")
    if authentication["expires_at"] <= datetime.now(timezone.utc).timestamp():
        raise ValueError("Authentication has expired")
    if (
        authentication["replace_pairwise_did"]
        and authentication.get("authentication_method") != "password"
    ):
        raise PermissionError(
            "Pairwise DID replacement requires password reauthentication"
        )
    if request.get("consent") is not True:
        return {
            "status": "access_denied",
            "error": "access_denied",
            "state": authentication["state"],
        }

    idp_master_did = did_named("idp-master")
    code = f"oidc-code-{uuid.uuid4()}"
    replace_id = (
        f"replace-{uuid.uuid4()}"
        if authentication["replace_pairwise_did"]
        else ""
    )
    expires_at = datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() + CODE_LIFETIME_SECONDS,
        timezone.utc,
    ).isoformat()

    store_oidc_code(
        {
            "code": code,
            "created_at": utc_now(),
            "expires_at": expires_at,
            "used": False,
            "user_subject": authentication["user_subject"],
            "idp_master_did": idp_master_did,
            "claims": authentication["claims"],
            "scopes": authentication["scopes"],
            "nonce": authentication["nonce"],
            "state": authentication["state"],
            "replace_id": replace_id,
        }
    )

    return {
        "status": "code_issued",
        "code": code,
        "replaceId": replace_id,
        "state": authentication["state"],
    }


def store_user_did_link(
    code_record: dict,
    request: dict,
    rp_pairwise_did: str,
) -> None:
    user_short_did = str(request.get("user_short_did", "")).strip()
    if not user_short_did:
        raise ValueError("SSO code exchange has no user short DID")
    with _USER_DID_LINKS_LOCK:
        links = load_json(USER_DID_LINKS_FILE, [])
        user_subject = code_record["user_subject"]
        reject_short_did_collision(
            links,
            rp_pairwise_did,
            user_short_did,
            user_subject,
        )
        existing_links = [
            link
            for link in current_user_did_links(links, rp_pairwise_did)
            if link.get("user_subject") == user_subject
        ]
        if existing_links:
            if existing_links[0].get("user_short_did") != user_short_did:
                raise SsoProtocolError(
                    "account_exists_replacement_required",
                    "An RP account already exists for this IdP account; activate Replace pairwise DID",
                )
            return

        links.append(
            {
                "linked_at": utc_now(),
                "user_subject": user_subject,
                "user_short_did": user_short_did,
                "rp_pairwise_did": rp_pairwise_did,
                "session_id": request.get("session_id", ""),
            }
        )
        save_json(USER_DID_LINKS_FILE, links)


def reject_registered_master_did(sender_did: str) -> None:
    if any(
        registration.get("rp_master_did") == sender_did
        for registration in load_json(REGISTERED_FILE, [])
    ):
        raise ValueError("SSO messages must use an RP pairwise DID")


def exchange_sso_code(rp_pairwise_did: str, request: dict, thread_id: str) -> None:
    reject_registered_master_did(rp_pairwise_did)
    code_record = oidc_code(request["code"])
    if request.get("nonce") != code_record["nonce"]:
        raise ValueError("Authorization nonce does not match the issued code")
    if request.get("state") != code_record["state"]:
        raise ValueError("Authorization state does not match the issued code")

    verifier = registration_verifier_config(registration_signing_key_file())
    verification_started_ns = time.perf_counter_ns()
    try:
        verification = verify_registration_proof(
            request["proof"],
            expected_nonce=code_record["nonce"],
            expected_public_key=verifier["idp_public_key"],
            expected_program_fingerprint=verifier.get("program_fingerprint", ""),
        )
    except Exception:
        record_event(
            request.get("session_id", ""),
            "proof_verification",
            duration_seconds=elapsed_seconds(verification_started_ns),
            details={"backend": PROOF_BACKEND, "outcome": "error"},
        )
        raise
    record_event(
        request.get("session_id", ""),
        "proof_verification",
        duration_seconds=elapsed_seconds(verification_started_ns),
        details={
            "backend": PROOF_BACKEND,
            "outcome": "accepted" if verification.get("accepted") else "rejected",
        },
    )
    if not verification.get("accepted"):
        raise ValueError(
            f"Registration proof was not accepted: {verification.get('error', 'unknown error')}"
        )

    code_record = consume_oidc_code(request["code"])
    replace_id = code_record.get("replace_id", "")
    if request.get("replace_id", "") != replace_id:
        raise ValueError("Replacement ID does not match the issued code")
    previous_link = latest_user_did_link(
        code_record["user_subject"],
        rp_pairwise_did,
    )
    previous_user_short_did = ""
    if replace_id:
        if not previous_link:
            raise SsoProtocolError(
                "replacement_not_available",
                "No existing RP account can be replaced for this IdP account",
            )
        previous_user_short_did = previous_link.get("user_short_did", "")
        mark_user_did_link_replacement(
            replace_id=replace_id,
            link_to_mark=previous_link,
        )
    else:
        current_user_short_did = str(request.get("user_short_did", "")).strip()
        if not current_user_short_did:
            raise ValueError("SSO code exchange has no user short DID")
        validate_user_did_assignment(
            rp_pairwise_did,
            current_user_short_did,
            code_record["user_subject"],
        )
        if previous_link:
            if previous_link.get("user_short_did") != current_user_short_did:
                raise SsoProtocolError(
                    "account_exists_replacement_required",
                    "An RP account already exists for this IdP account; activate Replace pairwise DID",
                )
        else:
            store_user_did_link(code_record, request, rp_pairwise_did)

    token_issuance_started_ns = time.perf_counter_ns()
    tokens = issue_token_grant(code_record, rp_pairwise_did)
    record_event(
        request.get("session_id", ""),
        "token_issuance",
        duration_seconds=elapsed_seconds(token_issuance_started_ns),
    )
    current_grant_id = tokens.pop("grant_id")
    body = {
        "session_id": request["session_id"],
        "nonce": code_record["nonce"],
        "claims": code_record.get("claims", {}),
        "idp_master_did": code_record["idp_master_did"],
        **tokens,
    }
    if replace_id:
        body.update(
            {
                "replace_id": replace_id,
                "previous_user_short_did": previous_user_short_did,
            }
        )
    packed = pack_encrypted_message(
        sender_did=code_record["idp_master_did"],
        recipient_did=rp_pairwise_did,
        body=body,
        message_type=SSO_AUTHORIZATION_RESPONSE_TYPE,
        thread_id=thread_id,
    )
    post_json(
        didcomm_endpoint_from_did(rp_pairwise_did),
        {"packedMessage": packed, "senderDid": code_record["idp_master_did"]},
    )
    revoke_previous_grants(
        code_record["user_subject"], rp_pairwise_did, current_grant_id
    )
def send_sso_error(
    rp_pairwise_did: str,
    session_id: str,
    error_code: str,
    error_message: str,
    thread_id: str,
) -> None:
    send_grant_response(
        rp_pairwise_did,
        {
            "session_id": session_id,
            "error_code": error_code,
            "error_message": error_message,
        },
        SSO_ERROR_TYPE,
        thread_id,
    )


def send_grant_error(
    rp_pairwise_did: str,
    request_id: str,
    error_code: str,
    thread_id: str,
) -> None:
    send_grant_response(
        rp_pairwise_did,
        {
            "request_id": request_id,
            "error_code": error_code,
            "error_message": "The IdP rejected the token request",
        },
        SSO_ERROR_TYPE,
        thread_id,
    )


def handle_pairwise_replacement_update(
    rp_pairwise_did: str,
    body: dict,
    thread_id: str,
) -> None:
    update_user_did_link_for_replacement(
        replace_id=body["replace_id"],
        new_user_short_did=body["new_user_short_did"],
        rp_pairwise_did=rp_pairwise_did,
    )
    response_body = {
        "session_id": body["session_id"],
        "replace_id": body["replace_id"],
        "status": "accepted",
    }
    send_grant_response(
        rp_pairwise_did,
        response_body,
        PAIRWISE_RECOVERY_ACCEPTED_TYPE,
        thread_id,
    )


def pending_request(request_id: str) -> dict | None:
    for request in load_json(PENDING_FILE, []):
        if request["request_id"] == request_id:
            return request

    return None


def remove_pending_request(request_id: str) -> None:
    pending = load_json(PENDING_FILE, [])
    save_json(
        PENDING_FILE,
        [request for request in pending if request.get("request_id") != request_id],
    )


class IdpDidCommHandler(BaseHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Accept, Content-Type")
        self.send_header("X-DIDSSO-Service", "idp")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}

        return json.loads(self.rfile.read(length).decode("utf-8"))

    def send_json(
        self,
        status_code: int,
        payload: dict | list,
        headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            if value:
                self.send_header(name, value)
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
                    "component": "idp",
                    "proof_backend": PROOF_BACKEND,
                    "session_id": session_id,
                    "events": measurements_for(session_id),
                },
            )
            return

        if self.path == "/dids":
            self.send_json(200, list_public_records())
            return

        if self.path == "/master-did":
            self.send_json(200, {"masterDid": did_named("idp-master")})
            return

        if self.path == "/rp-registration/pending":
            self.send_json(200, load_json(PENDING_FILE, []))
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

            if self.path == "/create-did":
                self.send_json(200, create_and_store_did(str(request.get("name", ""))))
                return

            if self.path == "/didcomm/inbox":
                unpacked = unpack_message(
                    request["packedMessage"],
                    sender_did=request.get("senderDid", ""),
                )
                message = unpacked["message"]
                sender_did = declared_sender_did(unpacked)
                message_type = message.get("type")
                body = message.get("body", {})
                thread_id = message_thread_id(message)

                if message_type in {SSO_CLAIMS_REQUEST_TYPE, SSO_TOKEN_REFRESH_TYPE}:
                    # message.from and the outer senderDid hint are not proof of
                    # possession of the pairwise DID's key-agreement key.
                    sender_did = authcrypt_sender_did(unpacked)
                    if not isinstance(body, dict):
                        self.send_json(400, {"error": "Malformed token request"})
                        return
                    try:
                        reject_registered_master_did(sender_did)
                        if message_type == SSO_CLAIMS_REQUEST_TYPE:
                            response_body = claims_for_access_token(sender_did, body)
                            response_type = SSO_CLAIMS_RESPONSE_TYPE
                        else:
                            response_body = rotate_refresh_token(sender_did, body)
                            response_type = SSO_TOKEN_REFRESHED_TYPE
                        send_grant_response(
                            sender_did,
                            response_body,
                            response_type,
                            thread_id,
                        )
                    except (ValueError, PermissionError, KeyError) as error:
                        print(f"[idp-didcomm] Token request rejected: {type(error).__name__}")
                        try:
                            send_grant_error(
                                sender_did,
                                str(body.get("request_id", ""))[:128],
                                "access_token_rejected"
                                if message_type == SSO_CLAIMS_REQUEST_TYPE
                                else "refresh_token_rejected",
                                thread_id,
                            )
                        except Exception:
                            self.send_json(502, {"error": "Token response delivery failed"})
                            return
                    except Exception:
                        self.send_json(502, {"error": "Token response delivery failed"})
                        return
                    self.send_json(202, {"status": "received"})
                    return

                if message_type in {
                    SSO_CODE_EXCHANGE_TYPE,
                    PAIRWISE_RECOVERY_UPDATE_TYPE,
                }:
                    sender_did = authcrypt_sender_did(unpacked)
                    try:
                        reject_registered_master_did(sender_did)
                    except ValueError:
                        self.send_json(
                            400,
                            {"error": "SSO messages require an RP pairwise DID"},
                        )
                        return

                if message_type == SSO_CODE_EXCHANGE_TYPE:
                    try:
                        exchange_sso_code(sender_did, body, thread_id)
                    except SsoProtocolError as error:
                        print(f"[idp-didcomm] SSO code exchange rejected: {error}")
                        send_sso_error(
                            sender_did,
                            str(body.get("session_id", "")),
                            error.code,
                            str(error),
                            thread_id,
                        )
                    except Exception as error:
                        print(f"[idp-didcomm] SSO code exchange rejected: {error}")
                        send_sso_error(
                            sender_did,
                            str(body.get("session_id", "")),
                            "code_exchange_rejected",
                            "The IdP rejected the DIDComm code exchange",
                            thread_id,
                        )
                    self.send_json(202, {"status": "received"})
                    return

                if message_type == PAIRWISE_RECOVERY_UPDATE_TYPE:
                    try:
                        handle_pairwise_replacement_update(
                            sender_did,
                            body,
                            thread_id,
                        )
                    except SsoProtocolError as error:
                        print(f"[idp-didcomm] Pairwise replacement rejected: {error}")
                        send_sso_error(
                            sender_did,
                            str(body.get("session_id", "")),
                            error.code,
                            str(error),
                            thread_id,
                        )
                    except Exception as error:
                        print(f"[idp-didcomm] Pairwise replacement rejected: {error}")
                        send_sso_error(
                            sender_did,
                            str(body.get("session_id", "")),
                            "replacement_update_rejected",
                            "The IdP rejected the pairwise DID replacement update",
                            thread_id,
                        )
                    self.send_json(202, {"status": "received"})
                    return

                if message_type != REGISTER_REQUEST_TYPE:
                    self.send_json(400, {"error": "Unsupported DIDComm message type"})
                    return

                sender_did = authcrypt_sender_did(unpacked)
                if sender_did != body.get("rp_master_did"):
                    raise ValueError(
                        "RP registration sender does not match the RP master DID"
                    )
                pending = load_json(PENDING_FILE, [])
                request_id = f"rp-reg-{uuid.uuid4()}"
                pending.append(
                    {
                        "request_id": request_id,
                        "status": "pending",
                        "received_at": utc_now(),
                        "rp_name": body["rp_name"],
                        "rp_master_did": body["rp_master_did"],
                        "didcomm_thread_id": thread_id,
                    }
                )
                save_json(PENDING_FILE, pending)
                self.send_json(200, {"status": "pending", "requestId": request_id})
                return

            if self.path == "/admin/rp-requests/accept":
                request_id = request["requestId"]
                rp_request = pending_request(request_id)
                if not rp_request:
                    self.send_json(404, {"error": "Unknown request"})
                    return

                idp_master_did = did_named("idp-master")
                credential = issue_registration_credential(
                    idp_master_did=idp_master_did,
                    request_id=request_id,
                    signing_key_path=registration_signing_key_file(),
                )
                registered = load_json(REGISTERED_FILE, [])
                registered.append(
                    {
                        "rp_name": rp_request["rp_name"],
                        "rp_master_did": rp_request["rp_master_did"],
                        "registered_at": utc_now(),
                        "idp_public_key": credential["idp_public_key"],
                        "proof_method": credential.get("proof_method", PROOF_BACKEND),
                        "proof_program_id": credential.get(
                            "risc0_program_id",
                            credential.get("stark_program_id", ""),
                        ),
                        "stark_program_id": credential.get("stark_program_id", ""),
                    }
                )
                save_json(REGISTERED_FILE, registered)

                body = {
                    "status": "accepted",
                    "request_id": request_id,
                    "rp_name": rp_request["rp_name"],
                    "rp_master_did": rp_request["rp_master_did"],
                    "idp_master_did": idp_master_did,
                    "accepted_at": utc_now(),
                    "credential": credential,
                }
                packed = pack_encrypted_message(
                    sender_did=idp_master_did,
                    recipient_did=rp_request["rp_master_did"],
                    body=body,
                    message_type=ACCEPTED_TYPE,
                    thread_id=rp_request["didcomm_thread_id"],
                )
                post_json(
                    didcomm_endpoint_from_did(rp_request["rp_master_did"]),
                    {
                        "packedMessage": packed,
                        "senderDid": idp_master_did,
                    },
                )
                remove_pending_request(request_id)
                self.send_json(200, {"status": "accepted"})
                return

            if self.path == "/admin/rp-requests/reject":
                request_id = request["requestId"]
                rp_request = pending_request(request_id)
                if not rp_request:
                    self.send_json(404, {"error": "Unknown request"})
                    return

                idp_master_did = did_named("idp-master")
                body = {
                    "status": "rejected",
                    "request_id": request_id,
                    "reason": request.get("reason", "Rejected by IdP admin"),
                    "rejected_at": utc_now(),
                }
                packed = pack_encrypted_message(
                    sender_did=idp_master_did,
                    recipient_did=rp_request["rp_master_did"],
                    body=body,
                    message_type=REJECTED_TYPE,
                    thread_id=rp_request["didcomm_thread_id"],
                )
                post_json(
                    didcomm_endpoint_from_did(rp_request["rp_master_did"]),
                    {
                        "packedMessage": packed,
                        "senderDid": idp_master_did,
                    },
                )
                remove_pending_request(request_id)
                self.send_json(200, {"status": "rejected"})
                return

            if self.path in {
                "/sso/authenticate",
                "/sso/session-authenticate",
                "/sso/issue-code",
            }:
                if self.headers.get(INTERNAL_PROXY_HEADER) != "https-idp":
                    self.send_json(
                        403,
                        {"error": "Authorization codes are only issued through the HTTPS IdP"},
                    )
                    return

            if self.path == "/sso/authenticate":
                self.send_json(200, authenticate_sso(request))
                return

            if self.path == "/sso/session-authenticate":
                subject_hex = self.headers.get(INTERNAL_USER_SUBJECT_HEADER, "")
                try:
                    subject = bytes.fromhex(subject_hex).decode("utf-8")
                except (ValueError, UnicodeDecodeError) as error:
                    raise PermissionError("Invalid internal IdP session identity") from error
                if not subject:
                    raise PermissionError("No internal IdP session identity")
                self.send_json(200, authenticate_sso_session(request, subject))
                return

            if self.path == "/sso/issue-code":
                result = issue_sso_code(request)
                if result.get("error") == "access_denied":
                    self.send_json(
                        200,
                        {"status": result["status"]},
                        headers={
                            DIDSSO_MESSAGE_TYPE_HEADER: "authorization-error",
                            DIDSSO_ERROR_HEADER: "access_denied",
                            DIDSSO_STATE_HEADER: result["state"],
                        },
                    )
                    return
                headers = {
                    DIDSSO_MESSAGE_TYPE_HEADER: "authorization-code",
                    DIDSSO_CODE_HEADER: result["code"],
                    DIDSSO_REPLACE_ID_HEADER: result["replaceId"],
                    DIDSSO_STATE_HEADER: result["state"],
                }
                self.send_json(
                    200,
                    {"status": result["status"]},
                    headers=headers,
                )
                return

            self.send_error(404, "Not Found")
        except PermissionError as error:
            self.send_json(401, {"error": str(error)})
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def log_message(self, format: str, *args) -> None:
        print(f"[idp-didcomm] {self.address_string()} - {format % args}")


def _handle_console_interrupt(_signal_number: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> None:
    signal.signal(signal.SIGINT, _handle_console_interrupt)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _handle_console_interrupt)

    server: ThreadingHTTPServer | None = None
    try:
        if PROOF_BACKEND == "risc0":
            start_verifier_service()
            print("Persistent RISC Zero verifier is ready")
        server = ThreadingHTTPServer((HOST, PORT), IdpDidCommHandler)
        print(f"IdP DIDComm backend listening on http://{HOST}:{PORT}")
        print(f"Registration proof: {PROOF_BACKEND.upper()}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping IdP DIDComm backend...")
    finally:
        if server is not None:
            server.server_close()
        if PROOF_BACKEND == "risc0":
            stop_verifier_service(permanent=True)


if __name__ == "__main__":
    main()
