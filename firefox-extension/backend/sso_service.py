from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from did_peer_4 import resolve as resolve_peer_4

from didcomm_service import pack_encrypted_message, unpack_message
from json_storage import load_json, save_json
from wallet_state_service import (
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


CHALLENGE_FILE = Path(__file__).resolve().parent / "sso_challenge.json"
SSO_CODE_FORWARD_TYPE = "https://did-sso.local/protocol/sso/1.0/code-forward"
DID_LOGIN_CHALLENGE_TYPE = "https://did-sso.local/protocol/did-login/1.0/challenge"


def origin_from_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""

    return f"{parsed.scheme}://{parsed.netloc}"


def load_current_challenge() -> dict:
    return load_json(CHALLENGE_FILE, {})


def clear_current_challenge() -> None:
    save_json(CHALLENGE_FILE, {})


def store_sso_challenge(request: dict) -> dict:
    challenge = {
        **request,
        "storedAt": utc_now(),
    }
    rp_origin = normalize_rp_origin(
        origin_from_url(challenge.get("redirectUrl", ""))
    )
    ensure_pairwise_did_can_bind(
        pairwise_did=challenge["userPairwiseDid"],
        rp_origin=rp_origin,
    )
    validate_prepared_did(
        pairwise_did=challenge["userPairwiseDid"],
        rp_origin=rp_origin,
    )
    save_json(CHALLENGE_FILE, challenge)
    forget_prepared_did(challenge["userPairwiseDid"])
    return {"status": "stored", "challenge": challenge}


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
    challenge = load_current_challenge()
    if not challenge:
        raise ValueError("No active RP nonce challenge found")
    if request.get("sessionId") != challenge.get("sessionId"):
        raise ValueError("Authorization code does not match the active SSO session")

    code = str(request.get("code", "")).strip()
    if not code:
        raise ValueError("Authorization code is required")

    user_pairwise_did = challenge["userPairwiseDid"]
    rp_master_did = challenge["rpMasterDid"]
    session_id = challenge["sessionId"]
    idp_master_did = challenge.get("idpMasterDid", "")
    if not idp_master_did:
        raise ValueError("The active SSO challenge has no IdP DID")

    forward_body = {
        "code": code,
        "nonce": challenge["nonce"],
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
    )
    rp_response = post_json(
        didcomm_endpoint_from_did(rp_master_did),
        {"packedMessage": packed["packedMessage"], "senderDid": user_pairwise_did},
    )
    binding = bind_pairwise_did_to_rp(
        pairwise_did=user_pairwise_did,
        rp_master_did=rp_master_did,
        rp_origin=origin_from_url(challenge.get("redirectUrl", "")),
        source="successful-sso",
    )
    result = {
        "status": "forwarded",
        "redirectUrl": challenge.get(
            "redirectUrl",
            f"http://127.0.0.1:9000/sso/wait?session_id={session_id}",
        ),
        "rpResponse": rp_response,
        "authorizationCodeTransport": "https",
        "authenticationOrigin": request.get("authenticationOrigin", ""),
        "binding": binding,
    }
    clear_current_challenge()
    return result


def respond_to_direct_login_challenge(sender_did: str, message: dict) -> dict:
    body = message["body"]
    user_pairwise_did = body["user_pairwise_did"]
    selected = selected_did_record()
    rp_master_did = body.get("rp_master_did") or sender_did
    binding = binding_for_pairwise_did(user_pairwise_did)

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

    didcomm_inbox = didcomm_endpoint_from_did(rp_master_did)
    expected_response_endpoint = (
        didcomm_inbox.rstrip("/").removesuffix("/didcomm/inbox")
        + "/did-login/complete"
    )
    response_endpoint = body.get("response_endpoint")
    if not response_endpoint:
        response_endpoint = expected_response_endpoint
    if response_endpoint.rstrip("/") != expected_response_endpoint.rstrip("/"):
        raise ValueError(
            "Direct DID login response endpoint does not match the RP DIDComm service"
        )

    rp_response = post_json(
        response_endpoint,
        {
            "session_id": body["session_id"],
            "nonce": body["nonce"],
            "user_pairwise_did": user_pairwise_did,
            "rp_master_did": rp_master_did,
        },
    )
    return {
        "status": "direct-login-response-sent",
        "redirectUrl": rp_response.get("redirectUrl"),
        "rpResponse": rp_response,
        "rpSenderDid": sender_did,
    }


def receive_didcomm_message(packed_message: dict | str, sender_did: str = "") -> dict:
    unpacked = unpack_message(packed_message, sender_did=sender_did)
    message = unpacked["message"]

    if message.get("type") == DID_LOGIN_CHALLENGE_TYPE:
        return respond_to_direct_login_challenge(sender_did, message)

    return {"status": "received"}
