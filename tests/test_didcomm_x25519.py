"""Independent real-crypto checks of the X25519-only participant backends.

Wallet access is isolated in memory; existing prototype state is never read or reset.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from didcomm.errors import DIDUrlNotFoundError, MalformedMessageError


PROJECT_DIR = Path(__file__).resolve().parents[1]
DIRECTIONS = (("user", "rp"), ("rp", "user"), ("rp", "idp"), ("idp", "rp"))
MESSAGE_TYPE = "https://did-sso.local/test/1.0/x25519"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_backend(actor: str, directory: str, peer_name: str):
    backend_dir = PROJECT_DIR / directory
    with patch.object(sys, "path", [str(backend_dir), *sys.path]):
        peer = load_module(f"x25519_{actor}_peer", backend_dir / f"{peer_name}.py")
        with patch.dict(sys.modules, {peer_name: peer}):
            service = load_module(
                f"x25519_{actor}_didcomm", backend_dir / "didcomm_service.py"
            )
    return peer, service


class X25519DidCommTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backends = {
            "user": load_backend(
                "user", "firefox-extension/backend", "did_peer_4_service"
            ),
            "rp": load_backend("rp", "RP/didcomm-backend", "did_peer_service"),
            "idp": load_backend("idp", "IdP/didcomm-backend", "did_peer_service"),
        }

    def setUp(self) -> None:
        self.records = {}
        for actor, (peer, service) in self.backends.items():
            record = peer.create_did_peer_4_record(f"test-{actor}")
            self.records[actor] = record
            wallet = {"dids": [record]}
            for module in (peer, service):
                patcher = patch.object(module, "load_wallet", return_value=wallet)
                patcher.start()
                self.addCleanup(patcher.stop)

    def pack(self, sender: str, recipient: str):
        packed = self.backends[sender][1].pack_encrypted_message(
            sender_did=self.records[sender]["did"],
            recipient_did=self.records[recipient]["did"],
            body={"claims": {"name": "Alice"}, "nonce": "test-nonce"},
            message_type=MESSAGE_TYPE,
            message_id=f"message-{sender}-{recipient}",
            thread_id="test-thread",
        )
        if isinstance(packed, dict) and "packedMessage" in packed:
            return packed["packedMessage"]
        return packed

    def test_fresh_peer_dids_and_secrets_contain_only_x25519(self) -> None:
        for actor, record in self.records.items():
            with self.subTest(actor=actor):
                self.assertEqual(
                    set(record["keys"]),
                    {"agreementPublicMultikey", "agreementPrivateRawBase58btc"},
                )
                for document in (record["inputDocument"], record["resolvedDocument"]):
                    self.assertEqual(document["keyAgreement"], ["#key-0"])
                    self.assertEqual(len(document["verificationMethod"]), 1)
                    method = document["verificationMethod"][0]
                    self.assertEqual(method["id"], "#key-0")
                    self.assertEqual(
                        method["publicKeyMultibase"],
                        record["keys"]["agreementPublicMultikey"],
                    )
                    for relationship in (
                        "authentication", "assertionMethod",
                        "capabilityInvocation", "capabilityDelegation",
                    ):
                        self.assertNotIn(relationship, document)
                secrets = self.backends[actor][1].didcomm_secrets(record, record["did"])
                self.assertEqual(len(secrets), 1)
                self.assertEqual(secrets[0].kid, f"{record['did']}#key-0")
                jwk = json.loads(secrets[0].verification_material.value)
                self.assertEqual(jwk["crv"], "X25519")

    def test_real_authcrypt_round_trips_in_all_protocol_directions(self) -> None:
        for sender, recipient in DIRECTIONS:
            with self.subTest(sender=sender, recipient=recipient):
                sender_did = self.records[sender]["did"]
                recipient_did = self.records[recipient]["did"]
                unpacked = self.backends[recipient][1].unpack_message(
                    self.pack(sender, recipient), sender_did=sender_did
                )
                message, metadata = unpacked["message"], unpacked["metadata"]
                self.assertEqual(message["from"], sender_did)
                self.assertEqual(message["to"], [recipient_did])
                self.assertEqual(message["type"], MESSAGE_TYPE)
                self.assertEqual(message["thid"], "test-thread")
                self.assertEqual(
                    message["body"],
                    {"claims": {"name": "Alice"}, "nonce": "test-nonce"},
                )
                self.assertTrue(metadata["encrypted"])
                self.assertTrue(metadata["authenticated"])
                self.assertFalse(metadata["non_repudiation"])
                self.assertIsNone(metadata.get("sign_from"))
                self.assertEqual(metadata["encrypted_from"], f"{sender_did}#key-0")
                self.assertEqual(metadata["encrypted_to"], [f"{recipient_did}#key-0"])

    def test_unrelated_wallet_cannot_decrypt(self) -> None:
        for sender, recipient in DIRECTIONS:
            unrelated = next(
                actor for actor in self.backends if actor not in (sender, recipient)
            )
            with self.subTest(sender=sender, recipient=recipient):
                with self.assertRaises(DIDUrlNotFoundError):
                    self.backends[unrelated][1].unpack_message(
                        self.pack(sender, recipient),
                        sender_did=self.records[sender]["did"],
                    )

    def test_modified_ciphertext_is_rejected(self) -> None:
        for sender, recipient in DIRECTIONS:
            with self.subTest(sender=sender, recipient=recipient):
                packed = self.pack(sender, recipient)
                envelope = json.loads(packed) if isinstance(packed, str) else dict(packed)
                ciphertext = bytearray(
                    base64.urlsafe_b64decode(envelope["ciphertext"] + "==")
                )
                ciphertext[0] ^= 1
                envelope["ciphertext"] = (
                    base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("=")
                )
                with self.assertRaises(MalformedMessageError):
                    self.backends[recipient][1].unpack_message(
                        envelope, sender_did=self.records[sender]["did"]
                    )


if __name__ == "__main__":
    unittest.main()
