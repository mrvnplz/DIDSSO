from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from did_peer_4 import resolve as resolve_peer_4

from did_peer_4_service import create_and_store_did, find_record, list_public_records, public_record
from didcomm_service import pack_encrypted_message, unpack_message


HOST = "127.0.0.1"
PORT = 8765
DATA_DIR = Path(__file__).resolve().parent
INBOX_FILE = DATA_DIR / "sso_messages.json"
CHALLENGE_FILE = DATA_DIR / "sso_challenge.json"
SELECTED_DID_FILE = DATA_DIR / "selected_did.json"
RP_BINDINGS_FILE = DATA_DIR / "rp_bindings.json"
SSO_CODE_TYPE = "https://did-sso.local/protocol/sso/1.0/authorization-code"
SSO_CODE_FORWARD_TYPE = "https://did-sso.local/protocol/sso/1.0/code-forward"
DID_LOGIN_CHALLENGE_TYPE = "https://did-sso.local/protocol/did-login/1.0/challenge"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path, default):
    if not path.exists():
        return default
    contents = path.read_text(encoding="utf-8-sig").strip()
    return json.loads(contents) if contents else default


def save_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def origin_from_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def selected_did_record() -> dict:
    selected = load_json(SELECTED_DID_FILE, {})
    did = selected.get("did", "")
    if not did:
        raise ValueError("No DID selected in the plugin")

    return public_record(find_record(did))


def store_selected_did(did: str) -> dict:
    if not did:
        save_json(SELECTED_DID_FILE, {})
        return {"status": "cleared"}

    record = public_record(find_record(did))
    save_json(
        SELECTED_DID_FILE,
        {
            "did": record["did"],
            "shortDid": record["shortDid"],
            "name": record["name"],
            "selectedAt": utc_now(),
        },
    )
    return {"status": "selected", "selectedDid": record}


def load_rp_bindings() -> dict:
    bindings = load_json(RP_BINDINGS_FILE, {"bindings": []})
    if isinstance(bindings, list):
        return {"bindings": bindings}
    bindings.setdefault("bindings", [])
    return bindings


def save_rp_bindings(bindings: dict) -> None:
    save_json(RP_BINDINGS_FILE, bindings)


def same_binding_value(left: str, right: str) -> bool:
    return bool(left and right and left == right)


def bind_pairwise_did_to_rp(
    pairwise_did: str,
    rp_master_did: str,
    rp_origin: str,
    source: str,
) -> dict:
    record = public_record(find_record(pairwise_did))
    bindings = load_rp_bindings()

    for binding in bindings["bindings"]:
        same_pairwise_did = binding.get("pairwiseDid") == record["did"]
        same_rp = (
            same_binding_value(binding.get("rpMasterDid", ""), rp_master_did)
            or same_binding_value(binding.get("rpOrigin", ""), rp_origin)
        )

        if same_pairwise_did and not same_rp:
            raise ValueError("This pairwise DID is already bound to another RP")
        if same_pairwise_did and same_rp:
            binding.update(
                {
                    "rpMasterDid": rp_master_did or binding.get("rpMasterDid", ""),
                    "rpOrigin": rp_origin or binding.get("rpOrigin", ""),
                    "pairwiseDid": record["did"],
                    "pairwiseShortDid": record["shortDid"],
                    "updatedAt": utc_now(),
                    "lastSource": source,
                }
            )
            save_rp_bindings(bindings)
            return binding

    binding = {
        "rpMasterDid": rp_master_did,
        "rpOrigin": rp_origin,
        "pairwiseDid": record["did"],
        "pairwiseShortDid": record["shortDid"],
        "createdAt": utc_now(),
        "updatedAt": utc_now(),
        "lastSource": source,
    }
    bindings["bindings"].append(binding)
    save_rp_bindings(bindings)
    return binding


def binding_for_rp(rp_master_did: str = "", rp_origin: str = "") -> dict | None:
    for binding in reversed(load_rp_bindings()["bindings"]):
        if same_binding_value(binding.get("rpMasterDid", ""), rp_master_did):
            return binding
        if same_binding_value(binding.get("rpOrigin", ""), rp_origin):
            return binding
    return None


def binding_for_pairwise_did(pairwise_did: str) -> dict | None:
    record = public_record(find_record(pairwise_did))
    for binding in load_rp_bindings()["bindings"]:
        if binding.get("pairwiseDid") == record["did"]:
            return binding
    return None


def select_bound_did_for_rp(rp_master_did: str = "", rp_origin: str = "") -> dict:
    binding = binding_for_rp(rp_master_did, rp_origin)
    if not binding:
        return {"status": "not-bound"}

    selected = load_json(SELECTED_DID_FILE, {})
    selected_did = selected.get("did", "")
    if selected_did:
        selected_binding = binding_for_pairwise_did(selected_did)
        if selected_binding is None and selected_did != binding["pairwiseDid"]:
            return {
                "status": "kept-unbound-selection",
                "binding": binding,
                "selectedDid": public_record(find_record(selected_did)),
            }

    selected = store_selected_did(binding["pairwiseDid"])
    return {
        "status": "selected",
        "binding": binding,
        "selectedDid": selected["selectedDid"],
    }


def didcomm_endpoint_from_did(did: str) -> str:
    document = resolve_peer_4(did)
    for service in document.get("service", []):
        if service.get("type") != "DIDCommMessaging":
            continue
        service_endpoint = service.get("serviceEndpoint", "")
        endpoint = service_endpoint.get("uri", "") if isinstance(service_endpoint, dict) else str(service_endpoint)
        if endpoint and endpoint != "didcomm:transport/queue":
            return endpoint
    raise ValueError("DID document does not contain an HTTP DIDComm endpoint")


def post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {error_body}") from error


def forward_code_to_rp(sender_did: str, message: dict) -> dict:
    body = message["body"]
    challenge = load_json(CHALLENGE_FILE, {})
    if not challenge:
        raise ValueError("No active RP nonce challenge found")

    user_pairwise_did = challenge["userPairwiseDid"]
    rp_master_did = challenge["rpMasterDid"]
    session_id = challenge["sessionId"]
    forward_body = {
        "code": body["code"],
        "nonce": challenge["nonce"],
        "session_id": session_id,
        "rp_master_did": rp_master_did,
        "idp_master_did": challenge.get("idpMasterDid") or body["idp_master_did"],
    }
    if body.get("replace_id"):
        forward_body["replace_id"] = body["replace_id"]
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
    return {
        "status": "forwarded",
        "redirectUrl": challenge.get("redirectUrl", f"http://127.0.0.1:9000/sso/wait?session_id={session_id}"),
        "rpResponse": rp_response,
        "idpSenderDid": sender_did,
    }


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

    response_endpoint = body.get("response_endpoint")
    if not response_endpoint:
        didcomm_inbox = didcomm_endpoint_from_did(rp_master_did)
        response_endpoint = didcomm_inbox.rstrip("/").removesuffix("/didcomm/inbox") + "/did-login/complete"

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


class DidPeerRequestHandler(BaseHTTPRequestHandler):
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

    def send_redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/dids":
            origin = self.headers.get("Origin", "")
            if origin.startswith("http://") or origin.startswith("https://"):
                self.send_json(403, {"error": "Wallet DID list is only available to the plugin UI"})
                return

            self.send_json(200, list_public_records())
            return

        if self.path == "/sso/selected-did":
            self.send_json(200, selected_did_record())
            return

            if self.path == "/sso/messages":
                self.send_json(200, load_json(INBOX_FILE, []))
                return

            if self.path == "/wallet/rp-bindings":
                self.send_json(200, load_rp_bindings())
                return

        if self.path == "/sso/current-challenge":
            self.send_json(200, load_json(CHALLENGE_FILE, {}))
            return

        if self.path == "/sso/continue":
            challenge = load_json(CHALLENGE_FILE, {})
            redirect_url = challenge.get("redirectUrl")
            if not redirect_url:
                self.send_json(404, {"error": "No active SSO redirect found"})
                return

            self.send_redirect(redirect_url)
            return

        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        try:
            request = self.read_json_body()

            if self.path == "/create-did":
                record = create_and_store_did(str(request.get("name", "")))
                self.send_json(200, record)
                return

            if self.path == "/wallet/selected-did":
                self.send_json(200, store_selected_did(str(request.get("did", ""))))
                return

            if self.path == "/wallet/select-for-rp":
                self.send_json(
                    200,
                    select_bound_did_for_rp(
                        rp_master_did=str(request.get("rpMasterDid", "")),
                        rp_origin=str(request.get("rpOrigin", "")),
                    ),
                )
                return

            if self.path == "/didcomm/pack-encrypted":
                self.send_json(
                    200,
                    pack_encrypted_message(
                        sender_did=request["from"],
                        recipient_did=request["to"],
                        body=request["body"],
                        message_type=request.get(
                            "type",
                            "https://didcomm.org/basicmessage/2.0/message",
                        ),
                    ),
                )
                return

            if self.path == "/sso/store-challenge":
                challenge = {
                    **request,
                    "storedAt": utc_now(),
                }
                binding = bind_pairwise_did_to_rp(
                    pairwise_did=challenge["userPairwiseDid"],
                    rp_master_did=challenge["rpMasterDid"],
                    rp_origin=origin_from_url(challenge.get("redirectUrl", "")),
                    source="sso-challenge",
                )
                save_json(CHALLENGE_FILE, challenge)
                self.send_json(200, {"status": "stored", "challenge": challenge, "binding": binding})
                return

            if self.path == "/didcomm/unpack":
                self.send_json(200, unpack_message(request["packedMessage"], request.get("senderDid", "")))
                return

            if self.path == "/didcomm/inbox":
                unpacked = unpack_message(
                    request["packedMessage"],
                    sender_did=request.get("senderDid", ""),
                )
                message = unpacked["message"]
                result = {"status": "received"}
                if message.get("type") == SSO_CODE_TYPE:
                    result = forward_code_to_rp(request.get("senderDid", ""), message)
                elif message.get("type") == DID_LOGIN_CHALLENGE_TYPE:
                    result = respond_to_direct_login_challenge(request.get("senderDid", ""), message)

                messages = load_json(INBOX_FILE, [])
                messages.append(
                    {
                        "received_at": utc_now(),
                        "sender_did": request.get("senderDid", ""),
                        "unpacked": unpacked,
                        "result": result,
                    }
                )
                save_json(INBOX_FILE, messages)
                self.send_json(200, result)
                return

            self.send_error(404, "Not Found")
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def log_message(self, format: str, *args) -> None:
        print(f"[did-peer-4-service] {self.address_string()} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DidPeerRequestHandler)
    print(f"DID peer 4 service listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
