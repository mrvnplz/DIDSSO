"""Independent checks of RP token storage and freshness at direct DID login."""

import json
import importlib.util
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))
SERVER_SPEC = importlib.util.spec_from_file_location(
    "rp_token_flow_server",
    BACKEND_DIR / "server.py",
)
assert SERVER_SPEC and SERVER_SPEC.loader
server = importlib.util.module_from_spec(SERVER_SPEC)
SERVER_SPEC.loader.exec_module(server)


def future(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def protocol_message(
    message_type: str,
    body: dict,
    thread_id: str,
    recipient: str = "did:peer:rp-pair",
) -> dict:
    return {
        "id": f"message-{thread_id}",
        "type": message_type,
        "thid": thread_id,
        "to": [recipient],
        "body": body,
    }


class TokenFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        for name in (
            "TOKEN_GRANTS_FILE",
            "SSO_SESSIONS_FILE",
            "USER_ACCOUNTS_FILE",
            "REGISTRATIONS_FILE",
        ):
            replacement = patch.object(server, name, base / f"{name}.json")
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_initial_sso_stores_tokens_only_in_backend_grant(self) -> None:
        session = {
            "session_id": "sso-1",
            "status": "code_exchange_sent",
            "idp_master_did": "did:peer:idp",
            "rp_pairwise_did": "did:peer:rp-pair",
            "user_pairwise_did": "did:peer:user",
            "user_short_did": "did:peer:user",
            "requested_claims": ["name"],
            "nonce": "initial-nonce",
            "didcomm_thread_id": "thread-sso-1",
        }
        server.upsert_session(session)
        body = {
            "session_id": "sso-1",
            "idp_master_did": "did:peer:idp",
            "nonce": "initial-nonce",
            "claims": {"name": "Updated"},
            "access_token": "secret-access",
            "refresh_token": "secret-refresh",
            "access_expires_at": future(30),
            "refresh_expires_at": future(1440),
        }
        message = protocol_message(
            server.SSO_AUTHORIZATION_RESPONSE_TYPE,
            body,
            "thread-sso-1",
        )
        with patch.object(server, "notify_plugin_of_sso_result"):
            server.store_authorization_response("did:peer:idp", message)

        grant = server.grant_for_account(server.account_by_identifier("did:peer:user"))
        self.assertEqual(grant["refresh_token"], "secret-refresh")
        self.assertEqual(grant["status"], "active")
        self.assertNotIn("claims_token", server.session_by_id("sso-1"))
        self.assertNotIn("secret-refresh", json.dumps(server.session_by_id("sso-1")))
        self.assertNotIn(
            "secret-refresh",
            json.dumps(server.account_by_identifier("did:peer:user")),
        )

    def test_initial_sso_rejects_wrong_nonce_recipient_and_claims(self) -> None:
        session = {
            "session_id": "sso-invalid",
            "status": "code_exchange_sent",
            "idp_master_did": "did:peer:idp",
            "rp_pairwise_did": "did:peer:rp-pair",
            "user_pairwise_did": "did:peer:user",
            "user_short_did": "did:peer:user",
            "requested_claims": ["name"],
            "nonce": "expected-nonce",
            "didcomm_thread_id": "thread-invalid",
        }
        server.upsert_session(session)
        body = {
            "session_id": "sso-invalid",
            "idp_master_did": "did:peer:idp",
            "nonce": "wrong-nonce",
            "claims": {"name": "Alice"},
            "access_token": "access",
            "refresh_token": "refresh",
            "access_expires_at": future(30),
            "refresh_expires_at": future(1440),
        }
        message = protocol_message(
            server.SSO_AUTHORIZATION_RESPONSE_TYPE,
            body,
            "thread-invalid",
        )
        with self.assertRaisesRegex(ValueError, "nonce"):
            server.store_authorization_response("did:peer:idp", message)

        body["nonce"] = "expected-nonce"
        message["to"] = ["did:peer:rp-master"]
        with self.assertRaisesRegex(ValueError, "intended recipient"):
            server.store_authorization_response("did:peer:idp", message)

        message["to"] = ["did:peer:rp-pair"]
        body["claims"] = {"name": "Alice", "email": "alice@example.test"}
        with self.assertRaisesRegex(ValueError, "unexpected or missing claims"):
            server.store_authorization_response("did:peer:idp", message)

    def test_public_views_exclude_registration_and_session_secrets(self) -> None:
        registration = server.public_registration(
            {
                "idp_master_did": "did:peer:idp",
                "status": "accepted",
                "credential": {"secret": "private"},
                "signed_message": "ciphertext",
            }
        )
        session = server.public_session_status(
            {
                "session_id": "sso-1",
                "status": "logged_in",
                "nonce": "private-nonce",
                "state": "private-state",
                "claims": {"name": "Alice"},
            }
        )

        self.assertEqual(
            registration,
            {"idp_master_did": "did:peer:idp", "status": "accepted"},
        )
        self.assertEqual(session, {"session_id": "sso-1", "status": "logged_in"})

    def test_registration_selection_uses_the_active_proof_backend(self) -> None:
        other_format = (
            "did-sso-registration-credential-v3"
            if server.ACTIVE_CREDENTIAL_FORMAT != "did-sso-registration-credential-v3"
            else "did-sso-registration-credential-risc0-p256-v2"
        )
        server.save_json(
            server.REGISTRATIONS_FILE,
            [
                {
                    "status": "accepted",
                    "idp_master_did": "did:peer:idp",
                    "rp_pairwise_did": "did:peer:active-pairwise",
                    "credential": {"format": server.ACTIVE_CREDENTIAL_FORMAT},
                },
                {
                    "status": "accepted",
                    "idp_master_did": "did:peer:idp",
                    "rp_pairwise_did": "did:peer:other-pairwise",
                    "credential": {"format": other_format},
                },
            ],
        )

        registration = server.accepted_registration_for_idp("did:peer:idp")
        self.assertEqual(registration["rp_pairwise_did"], "did:peer:active-pairwise")

    def test_direct_login_updates_claims_before_success(self) -> None:
        server.upsert_account({
            "identifier": "did:peer:user",
            "user_pairwise_did": "did:peer:user",
            "user_short_did": "did:peer:user",
            "idp_master_did": "did:peer:idp",
            "claims": {"name": "Old"},
        })
        server.upsert_session({
            "session_id": "did-login-1",
            "status": "did_challenge_sent",
            "nonce": "challenge",
            "rp_master_did": "did:peer:rp-master",
            "user_pairwise_did": "did:peer:user",
            "didcomm_thread_id": "thread-login-1",
        })
        message = {
            "id": "response-login-1",
            "thid": "thread-login-1",
            "to": ["did:peer:rp-master"],
            "body": {
                "session_id": "did-login-1",
                "nonce": "challenge",
                "rp_master_did": "did:peer:rp-master",
                "user_pairwise_did": "did:peer:user",
            },
        }
        with patch.object(server, "fresh_claims_for_account", return_value={"name": "New"}), patch.object(
            server, "send_direct_login_result", return_value={"status": "received"}
        ) as send_result:
            server.complete_direct_login("did:peer:user", message)
        self.assertEqual(server.session_by_id("did-login-1")["status"], "logged_in")
        self.assertEqual(server.account_by_identifier("did:peer:user")["claims"], {"name": "New"})
        send_result.assert_called_once()

    def test_direct_login_fails_closed_when_idp_cannot_supply_claims(self) -> None:
        server.upsert_account({
            "identifier": "did:peer:user",
            "user_pairwise_did": "did:peer:user",
            "user_short_did": "did:peer:user",
            "idp_master_did": "did:peer:idp",
            "claims": {"name": "Old"},
        })
        server.upsert_session({
            "session_id": "did-login-2",
            "status": "did_challenge_sent",
            "nonce": "challenge",
            "rp_master_did": "did:peer:rp-master",
            "user_pairwise_did": "did:peer:user",
            "didcomm_thread_id": "thread-login-2",
        })
        message = {
            "id": "response-login-2",
            "thid": "thread-login-2",
            "to": ["did:peer:rp-master"],
            "body": {
                "session_id": "did-login-2",
                "nonce": "challenge",
                "rp_master_did": "did:peer:rp-master",
                "user_pairwise_did": "did:peer:user",
            },
        }
        with patch.object(server, "fresh_claims_for_account", side_effect=ValueError("IdP offline")), patch.object(
            server, "send_direct_login_result"
        ) as send_result:
            with self.assertRaisesRegex(ValueError, "IdP offline"):
                server.complete_direct_login("did:peer:user", message)
        self.assertEqual(server.session_by_id("did-login-2")["status"], "failed")
        self.assertEqual(server.account_by_identifier("did:peer:user")["claims"], {"name": "Old"})
        send_result.assert_not_called()

    def test_claims_response_requires_fresh_authenticated_request_binding(self) -> None:
        pending = {
            "event": Event(),
            "grant": {
                "idp_master_did": "did:peer:idp",
                "rp_pairwise_did": "did:peer:rp-pair",
                "requested_claims": ["name"],
            },
            "response_type": server.SSO_CLAIMS_RESPONSE_TYPE,
            "response": None,
            "error": None,
            "didcomm_thread_id": "thread-claims",
        }
        server._PENDING_TOKEN_REQUESTS["fresh-request-id"] = pending
        self.addCleanup(server._PENDING_TOKEN_REQUESTS.pop, "fresh-request-id", None)
        response = {
            "request_id": "fresh-request-id",
            "idp_master_did": "did:peer:idp",
            "claims": {"name": "Current"},
        }
        message = protocol_message(
            server.SSO_CLAIMS_RESPONSE_TYPE,
            response,
            "thread-claims",
        )
        with self.assertRaisesRegex(ValueError, "different authenticated sender"):
            server.complete_token_response("did:peer:other", message)
        self.assertFalse(pending["event"].is_set())

        wrong_thread = {**message, "thid": "another-thread"}
        with self.assertRaisesRegex(ValueError, "different DIDComm thread"):
            server.complete_token_response("did:peer:idp", wrong_thread)

        wrong_recipient = {**message, "to": ["did:peer:rp-master"]}
        with self.assertRaisesRegex(ValueError, "intended recipient"):
            server.complete_token_response("did:peer:idp", wrong_recipient)

        wrong_claims = {
            **message,
            "body": {**response, "claims": {"name": "Current", "email": "extra"}},
        }
        with self.assertRaisesRegex(ValueError, "unexpected or missing claims"):
            server.complete_token_response("did:peer:idp", wrong_claims)

        server.complete_token_response("did:peer:idp", message)
        self.assertTrue(pending["event"].is_set())
        self.assertEqual(pending["response"]["claims"], {"name": "Current"})

    def test_refresh_callback_persists_rotated_tokens_before_ack(self) -> None:
        session = {
            "session_id": "sso-rotating",
            "idp_master_did": "did:peer:idp",
            "rp_pairwise_did": "did:peer:rp-pair",
            "user_pairwise_did": "did:peer:user",
            "requested_claims": ["name"],
        }
        server.store_initial_grant(session, {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "access_expires_at": future(30),
            "refresh_expires_at": future(1440),
        }, staged=False)
        account = {"user_pairwise_did": "did:peer:user", "idp_master_did": "did:peer:idp"}
        grant = server.grant_for_account(account)
        pending = {
            "event": Event(),
            "grant": grant,
            "response_type": server.SSO_TOKEN_REFRESHED_TYPE,
            "response": None,
            "error": None,
            "didcomm_thread_id": "thread-refresh",
        }
        server._PENDING_TOKEN_REQUESTS["rotate-request"] = pending
        self.addCleanup(server._PENDING_TOKEN_REQUESTS.pop, "rotate-request", None)
        response = {
            "request_id": "rotate-request",
            "idp_master_did": "did:peer:idp",
            "claims": {"name": "Current"},
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "access_expires_at": future(30),
            "refresh_expires_at": future(1440),
        }
        message = protocol_message(
            server.SSO_TOKEN_REFRESHED_TYPE,
            response,
            "thread-refresh",
        )
        server.complete_token_response("did:peer:idp", message)
        self.assertTrue(pending["event"].is_set())
        self.assertEqual(server.grant_for_account(account)["refresh_token"], "new-refresh")

    def test_did_login_sender_requires_authcrypt_not_plaintext_from(self) -> None:
        for message_type in (
            server.SSO_CODE_FORWARD_TYPE,
            server.PAIRWISE_RECOVERY_ACCEPTED_TYPE,
            server.SSO_ERROR_TYPE,
            server.DID_LOGIN_RESPONSE_TYPE,
            server.SSO_AUTHORIZATION_RESPONSE_TYPE,
            server.SSO_CLAIMS_RESPONSE_TYPE,
            server.SSO_TOKEN_REFRESHED_TYPE,
            server.REGISTER_ACCEPTED_TYPE,
            server.REGISTER_REJECTED_TYPE,
        ):
            self.assertIn(message_type, server.AUTHCRYPT_REQUIRED_TYPES)
        unpacked = {
            "message": {"from": "did:peer:user"},
            "metadata": {"encrypted": True, "authenticated": False},
        }
        with self.assertRaisesRegex(ValueError, "authenticated sender key"):
            server.require_authcrypt_sender(unpacked)
        unpacked["metadata"] = {
            "encrypted": True,
            "authenticated": True,
            "encrypted_from": "did:peer:other#key-0",
        }
        with self.assertRaisesRegex(ValueError, "authenticated sender key"):
            server.require_authcrypt_sender(unpacked)
        unpacked["metadata"]["encrypted_from"] = "did:peer:user#key-0"
        self.assertEqual(server.require_authcrypt_sender(unpacked), "did:peer:user")


if __name__ == "__main__":
    unittest.main()
