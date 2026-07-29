from __future__ import annotations
from pathlib import Path

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from did_peer_4_service import create_and_store_did, list_public_records
from didcomm_service import pack_encrypted_message, unpack_message
from sso_service import (
    clear_current_challenge,
    forward_https_authorization_code,
    load_current_challenge,
    receive_didcomm_message,
    store_sso_challenge,
)
from wallet_state_service import (
    ensure_data_storage,
    prepare_did_for_rp,
    select_did_for_service,
    selected_did_record,
    store_selected_did,
)


HOST = "127.0.0.1"
PORT = 8765

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

    def is_plugin_request(self) -> bool:
        origin = self.headers.get("Origin", "")
        return not origin or origin.startswith("moz-extension://")

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

        if self.path == "/sso/current-challenge":
            self.send_json(200, load_current_challenge())
            return

        if self.path == "/sso/continue":
            challenge = load_current_challenge()
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

            if self.path in {
                "/create-did",
                "/wallet/selected-did",
                "/wallet/select-for-service",
                "/wallet/prepare-for-rp",
                "/sso/authorization-code",
            } and not self.is_plugin_request():
                self.send_json(
                    403,
                    {"error": "This wallet endpoint is only available to the plugin"},
                )
                return

            if self.path == "/create-did":
                self.send_json(
                    200,
                    create_and_store_did(str(request.get("name", ""))),
                )
                return

            if self.path == "/wallet/selected-did":
                self.send_json(
                    200,
                    store_selected_did(str(request.get("did", ""))),
                )
                return

            if self.path == "/wallet/select-for-service":
                self.send_json(
                    200,
                    select_did_for_service(
                        service_origin=str(request.get("serviceOrigin", "")),
                    ),
                )
                return

            if self.path == "/wallet/prepare-for-rp":
                prepared = prepare_did_for_rp(
                    rp_origin=str(request.get("rpOrigin", "")),
                    automatic=bool(request.get("automatic", True)),
                    selected_did=str(request.get("selectedDid", "")),
                )
                clear_current_challenge()
                self.send_json(
                    200,
                    prepared,
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
                self.send_json(200, store_sso_challenge(request))
                return

            if self.path == "/sso/authorization-code":
                self.send_json(200, forward_https_authorization_code(request))
                return

            if self.path == "/didcomm/unpack":
                self.send_json(
                    200,
                    unpack_message(
                        request["packedMessage"],
                        request.get("senderDid", ""),
                    ),
                )
                return

            if self.path == "/didcomm/inbox":
                self.send_json(
                    200,
                    receive_didcomm_message(
                        request["packedMessage"],
                        request.get("senderDid", ""),
                    ),
                )
                return

            self.send_error(404, "Not Found")
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def log_message(self, format: str, *args) -> None:
        print(f"[did-peer-4-service] {self.address_string()} - {format % args}")


def main() -> None:
    ensure_data_storage()
    server = ThreadingHTTPServer((HOST, PORT), DidPeerRequestHandler)
    print(f"DID peer 4 service listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
