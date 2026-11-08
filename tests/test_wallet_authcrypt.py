"""Independent wallet-ingress checks with isolated state and real DIDComm crypto."""

from __future__ import annotations

import asyncio
from contextlib import ExitStack
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from didcomm import Message, PackEncryptedConfig, pack_encrypted


PROJECT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_DIR / "firefox-extension" / "backend"


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, BACKEND_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_wallet_backend():
    with patch.object(sys, "path", [str(BACKEND_DIR), str(PROJECT_DIR), *sys.path]):
        with patch.dict(sys.modules):
            peer = load_module("wallet_authcrypt_peer", "did_peer_4_service.py")
            sys.modules["did_peer_4_service"] = peer
            didcomm = load_module("wallet_authcrypt_didcomm", "didcomm_service.py")
            sys.modules["didcomm_service"] = didcomm
            wallet = load_module("wallet_authcrypt_state", "wallet_state_service.py")
            sys.modules["wallet_state_service"] = wallet
            sso = load_module("wallet_authcrypt_sso", "sso_service.py")
    return peer, didcomm, wallet, sso


class WalletAuthcryptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.peer, cls.didcomm, cls.wallet, cls.sso = load_wallet_backend()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="didsso-wallet-authcrypt-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.user = self.peer.create_did_peer_4_record("test-user")
        self.rp = self.peer.create_did_peer_4_record("test-rp")
        self.other = self.peer.create_did_peer_4_record("test-unrelated-rp")
        for module, name, value in (
            (self.peer, "WALLET_FILE", root / "wallet.json"),
            (self.wallet, "SELECTED_DID_FILE", root / "selected_did.json"),
            (self.sso, "AUTH_REQUEST_FILE", root / "sso_auth_request.json"),
            (self.sso, "SSO_RESULT_FILE", root / "sso_result.json"),
            (self.peer, "load_wallet", lambda: {"dids": [self.user]}),
            (self.didcomm, "load_wallet", lambda: {"dids": [self.user]}),
            (self.wallet, "load_wallet", lambda: {"dids": [self.user]}),
            (self.sso, "_DIRECT_LOGIN_ATTEMPTS", {}),
        ):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.handlers = (
            (self.sso.DID_LOGIN_CHALLENGE_TYPE, "respond_to_direct_login_challenge"),
            (self.sso.DID_LOGIN_RESULT_TYPE, "handle_direct_login_result"),
            (self.sso.SSO_RESULT_TYPE, "handle_sso_result"),
        )
        self.auth_request = {
            "sessionId": "test-session",
            "didcommThreadId": "test-thread",
            "rpMasterDid": self.rp["did"],
            "userPairwiseDid": self.user["did"],
            "redirectUrl": "https://rp.example/sso/wait",
            "authorizationUrl": "https://idp.example/sso?scope=profile",
        }

    def message(self, message_type: str, *, sender: str | None = None,
                body: dict | None = None, thread: str = "test-thread") -> dict:
        return {
            "id": "test-message",
            "type": message_type,
            "from": sender or self.rp["did"],
            "to": [self.user["did"]],
            "thid": thread,
            "body": body if body is not None else {},
        }

    def metadata(self) -> dict:
        return {
            "encrypted": True,
            "authenticated": True,
            "encrypted_from": self.rp["did"] + "#key-0",
            "encrypted_to": [self.user["did"] + "#key-0"],
        }

    def pack(self, message: dict, *, sender=None, anonymous=False):
        record = sender or self.rp
        with patch.object(self.peer, "load_wallet", return_value={"dids": [record]}), \
                patch.object(self.didcomm, "load_wallet", return_value={"dids": [record]}):
            resolvers = self.didcomm.build_resolvers_config([self.user["did"]])
            return asyncio.run(pack_encrypted(
                resolvers_config=resolvers,
                message=Message.from_dict(copy.deepcopy(message)),
                frm=None if anonymous else record["did"],
                to=self.user["did"],
                pack_config=PackEncryptedConfig(forward=False),
            )).packed_msg

    def assert_rejected_before_dispatch(self, packed, *, unpacked=None,
                                        sender_hint=None) -> None:
        with ExitStack() as stack:
            handlers = [stack.enter_context(patch.object(self.sso, name))
                        for _, name in self.handlers]
            writes = [stack.enter_context(patch.object(self.sso, name)) for name in (
                "save_sso_result", "clear_current_auth_request", "bind_pairwise_did_to_rp"
            )]
            if unpacked is not None:
                stack.enter_context(patch.object(self.sso, "unpack_message", return_value=unpacked))
            attempts_before = copy.deepcopy(self.sso._DIRECT_LOGIN_ATTEMPTS)
            with self.assertRaises((ValueError, PermissionError)):
                self.sso.receive_didcomm_message(
                    packed, sender_did=sender_hint or self.rp["did"]
                )
            for handler in handlers + writes:
                handler.assert_not_called()
            self.assertEqual(self.sso._DIRECT_LOGIN_ATTEMPTS, attempts_before)
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_all_supported_types_require_authenticated_encryption(self) -> None:
        invalid = (
            {},
            {"encrypted": False, "authenticated": False},
            {"encrypted": True, "authenticated": False},
            {"encrypted": False, "authenticated": True},
        )
        for message_type, _ in self.handlers:
            for metadata in invalid:
                with self.subTest(message_type=message_type, metadata=metadata):
                    self.assert_rejected_before_dispatch("unused", unpacked={
                        "message": self.message(message_type), "metadata": metadata,
                    })

    def test_authenticated_sender_must_match_the_declared_sender(self) -> None:
        for message_type, _ in self.handlers:
            for key in (None, "", self.other["did"] + "#key-0",
                        self.rp["did"], self.rp["did"] + "#"):
                with self.subTest(message_type=message_type, key=key):
                    metadata = {**self.metadata(), "encrypted_from": key}
                    self.assert_rejected_before_dispatch("unused", unpacked={
                        "message": self.message(message_type), "metadata": metadata,
                    })

    def test_declared_sender_is_required_even_with_authcrypt_metadata(self) -> None:
        for sender in (None, "", "   "):
            message = self.message(self.sso.SSO_RESULT_TYPE)
            if sender is None:
                message.pop("from")
            else:
                message["from"] = sender
            with self.subTest(sender=sender):
                self.assert_rejected_before_dispatch("unused", unpacked={
                    "message": message, "metadata": self.metadata(),
                })

    def test_outer_sender_hint_is_not_an_authentication_proof(self) -> None:
        self.assert_rejected_before_dispatch("unused", sender_hint=self.rp["did"], unpacked={
            "message": self.message(self.sso.SSO_RESULT_TYPE), "metadata": {},
        })

    def test_valid_authcrypt_dispatches_each_supported_message_type(self) -> None:
        for message_type, expected_handler in self.handlers:
            message = self.message(message_type)
            with self.subTest(message_type=message_type), ExitStack() as stack:
                handlers = {name: stack.enter_context(patch.object(
                    self.sso, name, return_value={"status": "handler-reached"}
                )) for _, name in self.handlers}
                result = self.sso.receive_didcomm_message(
                    self.pack(message), sender_did=self.rp["did"]
                )
                self.assertEqual(result, {"status": "handler-reached"})
                handlers[expected_handler].assert_called_once()
                authenticated_sender, delivered = handlers[expected_handler].call_args.args
                self.assertEqual(authenticated_sender, self.rp["did"])
                for field, expected in message.items():
                    self.assertEqual(delivered[field], expected)
                for name, handler in handlers.items():
                    if name != expected_handler:
                        handler.assert_not_called()

    def test_real_plaintext_messages_are_rejected_before_dispatch(self) -> None:
        for message_type, _ in self.handlers:
            with self.subTest(message_type=message_type):
                self.assert_rejected_before_dispatch(self.message(message_type))

    def test_real_anoncrypt_messages_are_rejected_before_dispatch(self) -> None:
        for message_type, _ in self.handlers:
            with self.subTest(message_type=message_type):
                self.assert_rejected_before_dispatch(
                    self.pack(self.message(message_type), anonymous=True)
                )

    def test_unknown_plaintext_type_cannot_bypass_the_gate(self) -> None:
        self.assert_rejected_before_dispatch(self.message("https://example.test/unknown/1.0"))

    def test_authcrypt_from_an_unexpected_rp_is_not_authorized_by_session(self) -> None:
        body = {"session_id": "test-session", "status": "success",
                "rp_master_did": self.rp["did"],
                "redirect_url": "https://rp.example/user"}
        message = self.message(self.sso.SSO_RESULT_TYPE, sender=self.other["did"], body=body)
        with patch.object(self.sso, "load_current_auth_request", return_value=self.auth_request), \
                patch.object(self.sso, "bind_pairwise_did_to_rp") as bind, \
                patch.object(self.sso, "save_sso_result") as save:
            with self.assertRaises(ValueError):
                self.sso.receive_didcomm_message(
                    self.pack(message, sender=self.other), sender_did=self.other["did"]
                )
            bind.assert_not_called()
            save.assert_not_called()

    def test_authcrypt_does_not_bypass_sso_session_or_thread_checks(self) -> None:
        for session, thread in (("another-session", "test-thread"),
                                ("test-session", "another-thread")):
            message = self.message(self.sso.SSO_RESULT_TYPE, thread=thread, body={
                "session_id": session, "status": "success", "rp_master_did": self.rp["did"],
                "redirect_url": "https://rp.example/user",
            })
            with self.subTest(session=session, thread=thread), \
                    patch.object(self.sso, "load_current_auth_request", return_value=self.auth_request), \
                    patch.object(self.sso, "bind_pairwise_did_to_rp") as bind, \
                    patch.object(self.sso, "save_sso_result") as save:
                with self.assertRaises(ValueError):
                    self.sso.receive_didcomm_message(self.pack(message), sender_did=self.rp["did"])
                bind.assert_not_called()
                save.assert_not_called()

    def test_valid_authcrypt_sso_success_keeps_existing_handler_behavior(self) -> None:
        message = self.message(self.sso.SSO_RESULT_TYPE, body={
            "session_id": "test-session", "status": "success", "rp_master_did": self.rp["did"],
            "redirect_url": "https://rp.example/user",
        })
        with patch.object(self.sso, "load_current_auth_request", return_value=self.auth_request), \
                patch.object(self.sso, "bind_pairwise_did_to_rp", return_value={"bound": True}) as bind, \
                patch.object(self.sso, "save_sso_result") as save, \
                patch.object(self.sso, "clear_current_auth_request") as clear, \
                patch.object(self.sso, "record_event"):
            result = self.sso.receive_didcomm_message(self.pack(message), sender_did=self.rp["did"])
            self.assertEqual(result["status"], "sso-completed")
            bind.assert_called_once()
            save.assert_called_once_with(result)
            clear.assert_called_once()

    def direct_login_attempt(self) -> dict:
        attempt = {
            "rp_master_did": self.rp["did"],
            "user_pairwise_did": self.user["did"],
            "nonce": "expected-nonce",
            "didcomm_thread_id": "test-thread",
            "result": None,
        }
        self.sso._DIRECT_LOGIN_ATTEMPTS["test-session"] = attempt
        return attempt

    def test_authcrypt_does_not_bypass_direct_login_nonce_checks(self) -> None:
        attempt = self.direct_login_attempt()
        message = self.message(self.sso.DID_LOGIN_RESULT_TYPE, body={
            "session_id": "test-session", "status": "logged_in",
            "rp_master_did": self.rp["did"], "user_pairwise_did": self.user["did"],
            "nonce": "wrong-nonce", "redirect_url": "https://rp.example/user",
        })
        with self.assertRaises(ValueError):
            self.sso.receive_didcomm_message(self.pack(message), sender_did=self.rp["did"])
        self.assertIsNone(attempt["result"])

    def test_valid_authcrypt_direct_login_result_keeps_existing_handler_behavior(self) -> None:
        attempt = self.direct_login_attempt()
        message = self.message(self.sso.DID_LOGIN_RESULT_TYPE, body={
            "session_id": "test-session", "status": "logged_in",
            "rp_master_did": self.rp["did"], "user_pairwise_did": self.user["did"],
            "nonce": "expected-nonce", "redirect_url": "https://rp.example/user",
        })
        result = self.sso.receive_didcomm_message(self.pack(message), sender_did=self.rp["did"])
        self.assertEqual(result, {"status": "received"})
        self.assertEqual(attempt["result"]["status"], "logged_in")
        self.assertEqual(attempt["result"]["sessionId"], "test-session")

    def test_valid_authcrypt_replacement_signal_keeps_existing_handler_behavior(self) -> None:
        message = self.message(self.sso.SSO_RESULT_TYPE, body={
            "session_id": "test-session", "status": "error", "rp_master_did": self.rp["did"],
            "error_code": "account_exists_replacement_required",
        })
        with patch.object(self.sso, "load_current_auth_request", return_value=self.auth_request), \
                patch.object(self.sso, "save_sso_result") as save, \
                patch.object(self.sso, "clear_current_auth_request") as clear:
            result = self.sso.receive_didcomm_message(self.pack(message), sender_did=self.rp["did"])
            self.assertEqual(result["status"], "sso-retry-required")
            self.assertIn("replacement_required=1", result["redirectUrl"])
            save.assert_called_once_with(result)
            clear.assert_not_called()


if __name__ == "__main__":
    unittest.main()
