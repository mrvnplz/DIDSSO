import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import credential_stark as stark


class CredentialStarkTests(unittest.TestCase):
    def test_proof_envelope_contains_only_verifier_inputs(self) -> None:
        credential = {
            "format": stark.CREDENTIAL_FORMAT,
            "stark_program_id": stark.PROGRAM_ID,
            "signature_scheme": stark.SIGNATURE_SCHEME,
            "credential_secret": "1",
            "signature_r": "2",
            "signature_s": "3",
            "idp_public_key": "4",
            "executable_fingerprint": "trusted-program",
        }
        with (
            patch.object(
                stark,
                "_build_fixed_executable",
                return_value=Path("program"),
            ),
            patch.object(
                stark,
                "_program_fingerprint",
                return_value="trusted-program",
            ),
            patch.object(
                stark,
                "_execute_proof",
                return_value={"claim": "proof"},
            ),
        ):
            proof = stark.create_registration_proof(credential, "nonce")

        self.assertEqual(proof["format"], stark.PROOF_FORMAT)
        self.assertEqual(proof["proof"]["type"], stark.PROOF_TYPE)
        self.assertEqual(set(proof["proof"]), {"type", "proof"})
        self.assertNotIn("prover_output", proof)

    def test_verifier_rejects_wrong_format_before_running_stwo(self) -> None:
        with patch.object(stark, "verify_stwo_proof_file") as verify_file:
            result = stark.verify_registration_proof(
                {"format": "wrong"},
                expected_nonce="nonce",
                expected_public_key="key",
                expected_program_fingerprint="fingerprint",
            )

        self.assertFalse(result["accepted"])
        verify_file.assert_not_called()

    def test_verifier_uses_local_channel_and_removes_temporary_proof(self) -> None:
        nonce = "nonce"
        proof = {
            "format": stark.PROOF_FORMAT,
            "program_id": stark.PROGRAM_ID,
            "nonce": nonce,
            "proof": {
                "type": stark.PROOF_TYPE,
                "proof": {"claim": "proof"},
                "channel_hash": "untrusted",
            },
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def verify_file(path: Path) -> dict:
                self.assertTrue(path.is_file())
                return {"accepted": True, "stdout": "", "stderr": ""}

            with patch.object(stark, "ROOT_DIR", root), patch.object(
                stark, "_public_program_fingerprint", return_value="fingerprint"
            ), patch.object(
                stark,
                "_proof_output",
                return_value=stark.small_felt_from_text(f"nonce:{nonce}"),
            ), patch.object(stark, "verify_stwo_proof_file", side_effect=verify_file):
                result = stark.verify_registration_proof(
                    proof,
                    expected_nonce=nonce,
                    expected_public_key="key",
                    expected_program_fingerprint="fingerprint",
                )

            self.assertTrue(result["accepted"])
            self.assertEqual(result["stwo"]["channel_hash"], stark.STWO_CHANNEL_HASH)
            self.assertEqual(list((root / "verified-proof-artifacts").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
