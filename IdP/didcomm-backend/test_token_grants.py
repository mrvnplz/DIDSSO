from __future__ import annotations

import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from didcomm.unpack import Metadata

import server


class TokenGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.grants_file = Path(self.temporary.name) / "grants.json"
        patcher = patch.object(server, "TOKEN_GRANTS_FILE", self.grants_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.user = {
            "subject": "user:alice",
            "name": "Alice",
            "username": "alice",
            "email": "alice@example.test",
        }
        user_patcher = patch.object(
            server,
            "find_user_by_subject",
            side_effect=lambda subject: self.user if subject == "user:alice" else None,
        )
        user_patcher.start()
        self.addCleanup(user_patcher.stop)
        did_patcher = patch.object(server, "did_named", return_value="did:peer:idp")
        did_patcher.start()
        self.addCleanup(did_patcher.stop)

    def issue(self) -> dict:
        return server.issue_token_grant(
            {"user_subject": "user:alice", "scopes": ["profile"]},
            "did:peer:rp-pairwise",
        )

    def test_grant_uses_hashes_and_limits_current_claims_to_scopes(self) -> None:
        tokens = self.issue()
        stored = server.load_json(self.grants_file, [])[0]
        self.assertNotIn(tokens["access_token"], self.grants_file.read_text())
        self.assertNotIn(tokens["refresh_token"], self.grants_file.read_text())
        self.assertNotIn("rp_master_did", stored)
        access_expiry = datetime.fromisoformat(tokens["access_expires_at"])
        refresh_expiry = datetime.fromisoformat(tokens["refresh_expires_at"])
        self.assertAlmostEqual(
            (access_expiry - datetime.now(access_expiry.tzinfo)).total_seconds(),
            timedelta(minutes=30).total_seconds(),
            delta=5,
        )
        self.assertAlmostEqual(
            (refresh_expiry - datetime.now(refresh_expiry.tzinfo)).total_seconds(),
            timedelta(days=7).total_seconds(),
            delta=5,
        )
        self.user["username"] = "alice-updated"
        response = server.claims_for_access_token(
            "did:peer:rp-pairwise",
            {"request_id": "request-1", "access_token": tokens["access_token"]},
        )
        self.assertEqual(response["claims"]["preferred_username"], "alice-updated")
        self.assertNotIn("email", response["claims"])
        self.assertEqual(response["request_id"], "request-1")
        self.assertEqual(response["idp_master_did"], "did:peer:idp")
        self.assertNotIn("claims_token", response)
        with self.assertRaises(PermissionError):
            server.claims_for_access_token(
                "did:peer:someone-else",
                {"request_id": "request-2", "access_token": tokens["access_token"]},
            )

    def test_refresh_rotates_once_and_replay_revokes_grant(self) -> None:
        initial = self.issue()
        renewed = server.rotate_refresh_token(
            "did:peer:rp-pairwise",
            {"request_id": "request-1", "refresh_token": initial["refresh_token"]},
        )
        self.assertNotEqual(renewed["access_token"], initial["access_token"])
        self.assertNotEqual(renewed["refresh_token"], initial["refresh_token"])
        self.assertEqual(renewed["refresh_expires_at"], initial["refresh_expires_at"])
        self.assertEqual(renewed["request_id"], "request-1")
        self.assertNotIn("claims_token", renewed)
        with self.assertRaises(PermissionError):
            server.claims_for_access_token(
                "did:peer:rp-pairwise",
                {"request_id": "request-2", "access_token": initial["access_token"]},
            )
        with self.assertRaisesRegex(PermissionError, "replay"):
            server.rotate_refresh_token(
                "did:peer:rp-pairwise",
                {"request_id": "request-3", "refresh_token": initial["refresh_token"]},
            )
        with self.assertRaises(PermissionError):
            server.claims_for_access_token(
                "did:peer:rp-pairwise",
                {"request_id": "request-4", "access_token": renewed["access_token"]},
            )
        self.assertTrue(server.load_json(self.grants_file, [])[0]["revoked"])

    def test_previous_grant_is_retired_after_new_delivery_ack(self) -> None:
        previous = self.issue()
        replacement = self.issue()
        server.claims_for_access_token(
            "did:peer:rp-pairwise",
            {"request_id": "before-ack", "access_token": previous["access_token"]},
        )
        server.revoke_previous_grants(
            "user:alice", "did:peer:rp-pairwise", replacement["grant_id"]
        )
        with self.assertRaises(PermissionError):
            server.claims_for_access_token(
                "did:peer:rp-pairwise",
                {"request_id": "after-ack", "access_token": previous["access_token"]},
            )
        server.claims_for_access_token(
            "did:peer:rp-pairwise",
            {"request_id": "current", "access_token": replacement["access_token"]},
        )

    def test_token_requests_require_matching_authcrypt_sender(self) -> None:
        unpacked = {
            "message": {"from": "did:peer:rp-pairwise"},
            "metadata": asdict(
                Metadata(
                    encrypted=True,
                    authenticated=True,
                    non_repudiation=False,
                    anonymous_sender=False,
                    encrypted_from="did:peer:rp-pairwise#key-0",
                )
            ),
        }
        self.assertEqual(server.authcrypt_sender_did(unpacked), "did:peer:rp-pairwise")
        unpacked["metadata"]["encrypted_from"] = "did:peer:attacker#key-0"
        with self.assertRaises(PermissionError):
            server.authcrypt_sender_did(unpacked)
        unpacked["metadata"]["encrypted_from"] = "did:peer:rp-pairwise#key-0"
        unpacked["metadata"]["authenticated"] = False
        with self.assertRaises(PermissionError):
            server.authcrypt_sender_did(unpacked)
        unpacked["metadata"] = {}
        with self.assertRaises(PermissionError):
            server.authcrypt_sender_did(unpacked)


if __name__ == "__main__":
    unittest.main()
