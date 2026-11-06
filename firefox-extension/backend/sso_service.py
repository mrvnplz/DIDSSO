from __future__ import annotations

import json
import sys
from threading import Lock
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from did_peer_4 import resolve as resolve_peer_4

WORKSPACE_DIR = Path(__file__).resolve().parents[2]
sys.path.append(str(WORKSPACE_DIR))

from evaluation_trace import record_event
from didcomm_service import message_thread_id, pack_encrypted_message, unpack_message
from json_storage import load_json, save_json
from wallet_state_service import (
    DATA_STORAGE_DIR,
    bind_pairwise_did_to_rp,
    binding_for_pairwise_did,
    ensure_pairwise_did_can_bind,
    forget_prepared_did,
    normalize_rp_origin,
    same_binding_value,
    selected_did_record,
    utc_now,
    validate_prepared_did,
)


AUTH_REQUEST_FILE = DATA_STORAGE_DIR / "sso_auth_request.json"
SSO_RESULT_FILE = DATA_STORAGE_DIR / "sso_result.json"
SSO_CODE_FORWARD_TYPE = "https://did-sso.local/protocol/sso/1.0/code-forward"
SSO_RESULT_TYPE = "https://did-sso.local/protocol/sso/1.0/result"
DID_LOGIN_CHALLENGE_TYPE = "https://did-sso.local/protocol/did-login/1.0/challenge"
DID_LOGIN_RESPONSE_TYPE = "https://did-sso.local/protocol/did-login/1.0/response"
DID_LOGIN_RESULT_TYPE = "https://did-sso.local/protocol/did-login/1.0/result"

_DIRECT_LOGIN_ATTEMPTS: dict[str, dict] = {}
_DIRECT_LOGIN_ATTEMPTS_LOCK = Lock()


def origin_from_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""

    return f"{parsed.scheme}://{parsed.netloc}"


def load_current_auth_request() -> dict:
    return load_json(AUTH_REQUEST_FILE, {})


def clear_current_auth_request() -> None:
    save_json(AUTH_REQUEST_FILE, {})


def load_matching_auth_request(response: dict) -> dict:
    auth_request = load_current_auth_request()
    if not auth_request:
        raise ValueError("No active RP authorization request found")
    if response.get("sessionId") != auth_request.get("sessionId"):
        raise ValueError("Authorization response has a different session")
    if response.get("state") != auth_request.get("state"):
        raise ValueError("Authorization response has a different state")
    return auth_request


def load_sso_result(session_id: str = "") -> dict:
    result = load_json(SSO_RESULT_FILE, {})
    if not result or (session_id and result.get("sessionId") != session_id):
        return {"status": "pending", "sessionId": session_id}
    if result.get("status") == "sso-retry-required":
        save_sso_result({})
    return result


def save_sso_result(result: dict) -> None:
    save_json(SSO_RESULT_FILE, result)


def store_sso_auth_request(request: dict) -> dict:
    auth_request = {
        **request,
        "storedAt": utc_now(),
    }
    if auth_request.get("responseType") != "code":
        raise ValueError("Only the authorization code response type is supported")
    if not str(auth_request.get("nonce", "")).strip():
        raise ValueError("Authorization request has no nonce")
    if not str(auth_request.get("state", "")).strip():
        raise ValueError("Authorization request has no state")
    if not str(auth_request.get("didcommThreadId", "")).strip():
        raise ValueError("Authorization request has no DIDComm thread ID")
    if not isinstance(auth_request.get("scope"), str):
        raise ValueError("Authorization request scope must be a string")
    rp_master_did = str(auth_request.get("rpMasterDid", "")).strip()
    if not rp_master_did:
        raise ValueError("Authorization request has no RP master DID")
    rp_origin = normalize_rp_origin(
        origin_from_url(auth_request.get("redirectUrl", ""))
    )
    ensure_pairwise_did_can_bind(
        pairwise_did=auth_request["userPairwiseDid"],
        rp_origin=rp_origin,
        rp_master_did=rp_master_did,
    )
    validate_prepared_did(
        pairwise_did=auth_request["userPairwiseDid"],
        rp_origin=rp_origin,
    )
    save_sso_result({})
    save_json(AUTH_REQUEST_FILE, auth_request)
    forget_prepared_did(auth_request["userPairwiseDid"])
    return {"status": "stored", "authRequest": auth_request}


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

    raise ValueError("DID document does not contain an HTTP DIDComm endpoint")


def post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {error_body}") from error


def forward_https_authorization_code(request: dict) -> dict:
    auth_request = load_matching_auth_request(request)

    code = str(request.get("code", "")).strip()
    if not code:
        raise ValueError("Authorization code is required")

    user_pairwise_did = auth_request["userPairwiseDid"]
    rp_master_did = auth_request["rpMasterDid"]
    session_id = auth_request["sessionId"]
    thread_id = str(auth_request.get("didcommThreadId", "")).strip()
    if not thread_id:
        raise ValueError("The active SSO authorization request has no DIDComm thread ID")
    idp_master_did = auth_request.get("idpMasterDid", "")
    if not idp_master_did:
        raise ValueError("The active SSO authorization request has no IdP DID")

    forward_body = {
        "code": code,
        "nonce": auth_request["nonce"],
        "state": auth_request["state"],
        "session_id": session_id,
        "rp_master_did": rp_master_did,
        "idp_master_did": idp_master_did,
    }
    replace_id = str(request.get("replaceId", "")).strip()
    if replace_id:
        forward_body["replace_id"] = replace_id

    packed = pack_encrypted_message(
        sender_did=user_pairwise_did,
        recipient_did=rp_master_did,
        body=forward_body,
        message_type=SSO_CODE_FORWARD_TYPE,
        message_id=thread_id,
    )
    post_json(
        didcomm_endpoint_from_did(rp_master_did),
        {"packedMessage": packed["packedMessage"], "senderDid": user_pairwise_did},
    )
    result = {
        "status": "accepted",
        "redirectUrl": auth_request["redirectUrl"],
    }
    return result


def authorization_error_redirect(request: dict) -> dict:
    auth_request = load_matching_auth_request(request)
    if request.get("error") != "access_denied":
        raise ValueError("Unsupported authorization error")

    redirect_url = auth_request["redirectUrl"]
    parts = urlsplit(redirect_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["error"] = "access_denied"
    result = {
        "status": "authorization_denied",
        "redirectUrl": urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        ),
    }
    clear_current_auth_request()
    return result


def respond_to_direct_login_challenge(sender_did: str, message: dict) -> dict:
    body = message["body"]
    thread_id = message_thread_id(message)
    session_id = str(body.get("session_id", "")).strip()
    nonce = str(body.get("nonce", "")).strip()
    user_pairwise_did = body["user_pairwise_did"]
    selected = selected_did_record()
    rp_master_did = body.get("rp_master_did") or sender_did
    binding = binding_for_pairwise_did(user_pairwise_did)

    if not session_id or not nonce:
        raise ValueError("Direct DID login challenge has no session or nonce")
    if sender_did != rp_master_did:
        raise ValueError("Direct DID login challenge body does not match its DIDComm sender")
    recipients = message.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    if user_pairwise_did not in recipients:
        raise ValueError("Direct DID login challenge has a different DIDComm recipient")
    if selected["did"] != user_pairwise_did:
        raise ValueError("Direct DID login challenge does not match the selected plugin DID")
    if not binding:
        raise ValueError("No pairwise DID binding found for this direct DID login challenge")
    if not same_binding_value(binding.get("rpMasterDid", ""), rp_master_did):
        raise ValueError("Direct DID login challenge does not match the bound RP")

    validate_prepared_did(
        pairwise_did=user_pairwise_did,
        rp_origin=normalize_rp_origin(binding.get("rpOrigin", "")),
    )

    packed = pack_encrypted_message(
        sender_did=user_pairwise_did,
        recipient_did=rp_master_did,
        body={
            "session_id": session_id,
            "nonce": nonce,
            "user_pairwise_did": user_pairwise_did,
            "rp_master_did": rp_master_did,
        },
        message_type=DID_LOGIN_RESPONSE_TYPE,
        thread_id=thread_id,
    )

    with _DIRECT_LOGIN_ATTEMPTS_LOCK:
        _DIRECT_LOGIN_ATTEMPTS[session_id] = {
            "session_id": session_id,
            "nonce": nonce,
            "user_pairwise_did": user_pairwise_did,
            "rp_master_did": rp_master_did,
            "didcomm_thread_id": thread_id,
            "result": None,
        }

    try:
        post_json(
            didcomm_endpoint_from_did(rp_master_did),
            {
                "packedMessage": packed["packedMessage"],
                "senderDid": user_pairwise_did,
            },
        )
        with _DIRECT_LOGIN_ATTEMPTS_LOCK:
            result = (_DIRECT_LOGIN_ATTEMPTS.get(session_id) or {}).get("result")
        if not result:
            raise ValueError("The RP did not return a DIDComm direct-login result")

        return {"status": "received"}
    finally:
        with _DIRECT_LOGIN_ATTEMPTS_LOCK:
            _DIRECT_LOGIN_ATTEMPTS.pop(session_id, None)


def handle_direct_login_result(sender_did: str, message: dict) -> dict:
    body = message.get("body", {})
    session_id = str(body.get("session_id", "")).strip()
    with _DIRECT_LOGIN_ATTEMPTS_LOCK:
        attempt = _DIRECT_LOGIN_ATTEMPTS.get(session_id)
        if not attempt:
            raise ValueError("No matching direct DID login attempt is active")
        if sender_did != attempt["rp_master_did"]:
            raise ValueError("Direct DID login result came from a different RP")
        if body.get("rp_master_did") != attempt["rp_master_did"]:
            raise ValueError("Direct DID login result body does not match the RP sender")
        if body.get("user_pairwise_did") != attempt["user_pairwise_did"]:
            raise ValueError("Direct DID login result is for a different user DID")
        if body.get("nonce") != attempt["nonce"]:
            raise ValueError("Direct DID login result does not match the challenge nonce")
        if body.get("status") != "logged_in":
            raise ValueError("Direct DID login result does not confirm a successful login")
        if message_thread_id(message) != attempt["didcomm_thread_id"]:
            raise ValueError("Direct DID login result belongs to a different DIDComm thread")

        recipients = message.get("to", [])
        if isinstance(recipients, str):
            recipients = [recipients]
        if attempt["user_pairwise_did"] not in recipients:
            raise ValueError("Direct DID login result has a different DIDComm recipient")

        result = {
            "status": body["status"],
            "sessionId": session_id,
            "redirectUrl": body.get("redirect_url", ""),
        }
        attempt["result"] = result
        return {"status": "received"}


def handle_sso_result(sender_did: str, message: dict) -> dict:
    auth_request = load_current_auth_request()
    if not auth_request:
        raise ValueError("No active RP authorization request found")

    body = message.get("body", {})
    if body.get("session_id") != auth_request.get("sessionId"):
        raise ValueError("SSO result does not match the active session")
    if message_thread_id(message) != auth_request.get("didcommThreadId"):
        raise ValueError("SSO result belongs to a different DIDComm thread")

    rp_master_did = auth_request.get("rpMasterDid", "")
    if sender_did != rp_master_did or body.get("rp_master_did") != rp_master_did:
        raise ValueError("SSO result did not come from the challenged RP")
    recipients = message.get("to", [])
    if isinstance(recipients, str):
        recipients = [recipients]
    if auth_request.get("userPairwiseDid") not in recipients:
        raise ValueError("SSO result has a different DIDComm recipient")

    status = body.get("status")
    if status == "success":
        redirect_url = str(body.get("redirect_url", "")).strip()
        expected_origin = origin_from_url(auth_request.get("redirectUrl", ""))
        if not redirect_url or origin_from_url(redirect_url) != expected_origin:
            raise ValueError("SSO result has an invalid RP redirect URL")
        binding = bind_pairwise_did_to_rp(
            pairwise_did=auth_request["userPairwiseDid"],
            rp_master_did=rp_master_did,
            rp_origin=origin_from_url(auth_request.get("redirectUrl", "")),
            source="successful-sso",
        )
        result = {
            "status": "sso-completed",
            "sessionId": auth_request["sessionId"],
            "redirectUrl": redirect_url,
            "binding": binding,
        }
        record_event(auth_request["sessionId"], "wallet_result_validated")
        save_sso_result(result)
        clear_current_auth_request()
        return result

    if status == "error":
        error_code = body.get("error_code", "sso_failed")
        retry_parameters = {
            "account_exists_replacement_required": "replacement_required",
            "replacement_not_available": "replacement_unavailable",
        }
        if error_code in retry_parameters:
            authorization_url = auth_request.get("authorizationUrl", "")
            if not authorization_url:
                raise ValueError("The active SSO request has no authorization URL")
            parts = urlsplit(authorization_url)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query[retry_parameters[error_code]] = "1"
            result = {
                "status": "sso-retry-required",
                "sessionId": auth_request["sessionId"],
                "redirectUrl": urlunsplit(
                    (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
                ),
                "errorCode": error_code,
                "error": body.get(
                    "error_message",
                    "An existing RP account requires pairwise DID replacement",
                ),
            }
            save_sso_result(result)
            return result

        redirect_url = auth_request.get("redirectUrl", "")
        parts = urlsplit(redirect_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["error"] = error_code
        result = {
            "status": "sso-failed",
            "sessionId": auth_request["sessionId"],
            "redirectUrl": urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
            ),
            "errorCode": error_code,
            "error": body.get("error_message", "The SSO request failed"),
        }
        save_sso_result(result)
        clear_current_auth_request()
        return result

    raise ValueError("Unsupported SSO result status")


def receive_didcomm_message(packed_message: dict | str, sender_did: str = "") -> dict:
    unpacked = unpack_message(packed_message, sender_did=sender_did)
    message = unpacked["message"]
    authenticated_sender = str(message.get("from", "")).strip()
    if not authenticated_sender:
        raise ValueError("DIDComm message has no authenticated sender DID")

    if message.get("type") == DID_LOGIN_CHALLENGE_TYPE:
        return respond_to_direct_login_challenge(authenticated_sender, message)

    if message.get("type") == DID_LOGIN_RESULT_TYPE:
        return handle_direct_login_result(authenticated_sender, message)

    if message.get("type") == SSO_RESULT_TYPE:
        return handle_sso_result(authenticated_sender, message)

    return {"status": "received"}
