import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import credential_risc0
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


class CredentialRisc0Tests(unittest.TestCase):
    def issue_credential(self, directory: str) -> dict:
        return credential_risc0.issue_registration_credential(
            "did:peer:test-idp",
            "test-request",
            Path(directory) / "registration-key.json",
        )

    def test_context_digest_is_domain_separated_and_nonce_bound(self) -> None:
        first = credential_risc0.request_context_digest("nonce-a")
        second = credential_risc0.request_context_digest("nonce-b")
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, second)

    def test_issued_credential_has_a_valid_p256_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            credential = self.issue_credential(directory)

        public_key_bytes = bytes.fromhex(credential["idp_public_key"])
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(public_key_bytes[:32], "big"),
            int.from_bytes(public_key_bytes[32:], "big"),
            ec.SECP256R1(),
        ).public_key()
        signature = utils.encode_dss_signature(
            int(credential["signature_r"]), int(credential["signature_s"])
        )
        public_key.verify(
            signature,
            bytes.fromhex(credential["credential_secret"]),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        self.assertEqual(
            credential["signature_scheme"], credential_risc0.SIGNATURE_SCHEME
        )

    def test_proof_envelope_contains_no_credential_witness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            credential = self.issue_credential(directory)
            nonce = "test-nonce"
            context = credential_risc0.request_context_digest(nonce)
            public_key = credential_risc0.fixed_hex(
                credential["idp_public_key"], 64, "idp_public_key"
            )
            cli_response = {
                "receipt_base64": "test-receipt",
                "method_id": "test-method",
                "journal": {
                    "protocol_version": 2,
                    "idp_public_key": public_key,
                    "context_digest": context,
                },
            }
            with patch.object(credential_risc0, "run_cli", return_value=cli_response):
                proof = credential_risc0.create_registration_proof(credential, nonce)

        serialized = str(proof)
        self.assertNotIn(credential["credential_secret"], serialized)
        self.assertNotIn(credential["signature_r"], serialized)
        self.assertNotIn(credential["signature_s"], serialized)

    def test_verifier_rejects_a_different_nonce_before_cli(self) -> None:
        proof = {
            "format": credential_risc0.PROOF_FORMAT,
            "proof_method": credential_risc0.PROOF_METHOD,
            "program_id": credential_risc0.PROGRAM_ID,
            "nonce": "nonce-a",
            "context_digest": credential_risc0.request_context_digest("nonce-a"),
            "proof": {
                "type": "risc0-zkvm-receipt",
                "method_id": "test-method",
                "receipt_base64": "test-receipt",
            },
        }
        with patch.object(credential_risc0, "run_cli") as run_cli:
            result = credential_risc0.verify_registration_proof(
                proof,
                expected_nonce="nonce-b",
                expected_public_key="11" * 64,
            )
        self.assertFalse(result["accepted"])
        run_cli.assert_not_called()


if __name__ == "__main__":
    unittest.main()
