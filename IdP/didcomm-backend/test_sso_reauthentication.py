"""Independent checks for password-gated pairwise DID replacement."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import server


class SsoReauthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        server.SSO_AUTHENTICATIONS.clear()
        self.addCleanup(server.SSO_AUTHENTICATIONS.clear)
        self.request = {
            "responseType": "code",
            "nonce": "nonce",
            "state": "state",
            "scopes": [],
            "replacePairwiseDid": True,
        }
        self.user = {
            "subject": "user:alice",
            "email": "alice@example.test",
        }

    def test_existing_session_cannot_authorize_replacement(self) -> None:
        with self.assertRaisesRegex(PermissionError, "password reauthentication"):
            server.authenticate_sso_session(self.request, self.user["subject"])

    def test_existing_session_still_supports_normal_authorization(self) -> None:
        request = {**self.request, "replacePairwiseDid": False}
        with patch.object(server, "find_user_by_subject", return_value=self.user):
            authentication = server.authenticate_sso_session(
                request,
                self.user["subject"],
            )

        stored = server.SSO_AUTHENTICATIONS[authentication["authenticationId"]]
        self.assertEqual(stored["authentication_method"], "session")
        self.assertFalse(stored["replace_pairwise_did"])

        with patch.object(server, "did_named", return_value="did:peer:idp"), patch.object(
            server, "store_oidc_code"
        ) as store_code:
            result = server.issue_sso_code(
                {
                    "authenticationId": authentication["authenticationId"],
                    "consent": True,
                }
            )

        self.assertEqual(result["replaceId"], "")
        self.assertEqual(store_code.call_args.args[0]["replace_id"], "")

    def test_password_authentication_can_issue_replacement_code(self) -> None:
        password_request = {
            **self.request,
            "email": self.user["email"],
            "password": "correct horse battery staple",
        }
        with patch.object(server, "find_user_by_email", return_value=self.user), patch.object(
            server, "verify_user_password", return_value=True
        ):
            authentication = server.authenticate_sso(password_request)

        stored = server.SSO_AUTHENTICATIONS[authentication["authenticationId"]]
        self.assertEqual(stored["authentication_method"], "password")
        self.assertTrue(stored["replace_pairwise_did"])

        with patch.object(server, "did_named", return_value="did:peer:idp"), patch.object(
            server, "store_oidc_code"
        ) as store_code:
            result = server.issue_sso_code(
                {
                    "authenticationId": authentication["authenticationId"],
                    "consent": True,
                }
            )

        self.assertTrue(result["replaceId"].startswith("replace-"))
        self.assertEqual(store_code.call_args.args[0]["replace_id"], result["replaceId"])

    def test_code_issuance_rejects_non_password_replacement_context(self) -> None:
        server.SSO_AUTHENTICATIONS["auth-session"] = {
            "expires_at": datetime.now(timezone.utc).timestamp() + 60,
            "user_subject": self.user["subject"],
            "claims": {},
            "scopes": [],
            "nonce": "nonce",
            "state": "state",
            "replace_pairwise_did": True,
            "authentication_method": "session",
        }

        with self.assertRaisesRegex(PermissionError, "password reauthentication"):
            server.issue_sso_code(
                {"authenticationId": "auth-session", "consent": True}
            )

    def test_replacement_flag_must_be_a_json_boolean(self) -> None:
        request = {
            **self.request,
            "email": self.user["email"],
            "password": "correct horse battery staple",
            "replacePairwiseDid": "false",
        }
        with patch.object(server, "find_user_by_email", return_value=self.user), patch.object(
            server, "verify_user_password", return_value=True
        ):
            with self.assertRaisesRegex(ValueError, "must be a boolean"):
                server.authenticate_sso(request)

        self.assertEqual(server.SSO_AUTHENTICATIONS, {})


if __name__ == "__main__":
    unittest.main()
