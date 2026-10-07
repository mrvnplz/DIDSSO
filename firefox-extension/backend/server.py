from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from did_peer_4_service import create_and_store_did, list_public_records
from sso_service import (
    authorization_error_redirect,
    clear_current_auth_request,
    forward_https_authorization_code,
    load_current_auth_request,
    load_sso_result,
    receive_didcomm_message,
    store_sso_auth_request,
)
from wallet_state_service import (
    ensure_data_storage,
    prepare_did_for_rp,
    select_did_for_service,
    selected_did_record,
    store_selected_did,
)


HOST = os.environ.get("DIDSSO_BIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("DIDSSO_PORT", "8765"))

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

    def is_plugin_request(self) -> bool:
        origin = self.headers.get("Origin", "")
        return not origin or origin.startswith("moz-extension://")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        match self.path:
            case "/dids":
                origin = self.headers.get("Origin", "")
                if origin.startswith("http://") or origin.startswith("https://"):
                    self.send_json(
                        403,
                        {"error": "Wallet DID list is only available to the plugin UI"},
                    )
                    return

                self.send_json(200, list_public_records())
                return

            case "/sso/selected-did":
                try:
                    self.send_json(200, selected_did_record())
                except ValueError as error:
                    self.send_json(409, {"error": str(error)})
                return

            case "/sso/current-auth-request":
                self.send_json(200, load_current_auth_request())
                return

            case _ if parsed.path == "/sso/result":
                if not self.is_plugin_request():
                    self.send_json(
                        403,
                        {"error": "SSO results are only available to the plugin"},
                    )
                    return
                session_id = parse_qs(parsed.query).get("session_id", [""])[0]
                self.send_json(200, load_sso_result(session_id))
                return

            case _:
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
                "/sso/authorization-error",
            } and not self.is_plugin_request():
                self.send_json(
                    403,
                    {"error": "This wallet endpoint is only available to the plugin"},
                )
                return

            match self.path:
                case "/create-did":
                    self.send_json(
                        200,
                        create_and_store_did(str(request.get("name", ""))),
                    )
                case "/wallet/selected-did":
                    self.send_json(
                        200,
                        store_selected_did(str(request.get("did", ""))),
                    )
                case "/wallet/select-for-service":
                    self.send_json(
                        200,
                        select_did_for_service(
                            service_origin=str(request.get("serviceOrigin", "")),
                        ),
                    )
                case "/wallet/prepare-for-rp":
                    prepared = prepare_did_for_rp(
                        rp_origin=str(request.get("rpOrigin", "")),
                        automatic=bool(request.get("automatic", True)),
                        selected_did=str(request.get("selectedDid", "")),
                    )
                    clear_current_auth_request()
                    self.send_json(200, prepared)
                case "/sso/store-auth-request":
                    self.send_json(200, store_sso_auth_request(request))
                case "/sso/authorization-code":
                    self.send_json(202, forward_https_authorization_code(request))
                case "/sso/authorization-error":
                    self.send_json(200, authorization_error_redirect(request))
                case "/didcomm/inbox":
                    self.send_json(
                        200,
                        receive_didcomm_message(
                            request["packedMessage"],
                            request.get("senderDid", ""),
                        ),
                    )
                case _:
                    self.send_error(404, "Not Found")
        except (BrokenPipeError, ConnectionAbortedError):
            return
        except Exception as error:
            try:
                self.send_json(500, {"error": str(error)})
            except (BrokenPipeError, ConnectionAbortedError):
                return

    def log_message(self, format: str, *args) -> None:
        print(f"[did-peer-4-service] {self.address_string()} - {format % args}")


def main() -> None:
    ensure_data_storage()
    server = ThreadingHTTPServer((HOST, PORT), DidPeerRequestHandler)
    print(f"DID peer 4 service listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
