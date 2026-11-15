"""Independent checks of participant storage paths using synthetic temporary data."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


PROJECT_DIR = Path(__file__).resolve().parents[1]


class RuntimeDataLayoutTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "Git is required to check runtime-data exclusions")
    def test_all_component_data_directories_are_excluded_from_git(self) -> None:
        for relative in (
            "IdP/data/users.json",
            "IdP/data/registration_signing_key_risc0_p256.json",
            "RP/data/authorization_config.json",
            "RP/data/user_accounts.json",
            "firefox-extension/data/wallet.json",
            "firefox-extension/data/nested/future-runtime-state.json",
        ):
            with self.subTest(path=relative):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", "--", relative],
                    cwd=PROJECT_DIR,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_backend(self, directory: str, code: str, *, data_dir: Path | None) -> None:
        environment = os.environ.copy()
        environment.pop("DIDSSO_DATA_DIR", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        if data_dir is not None:
            environment["DIDSSO_DATA_DIR"] = str(data_dir)
        backend_dir = PROJECT_DIR / directory
        script = f"import sys\nsys.path.insert(0, {str(backend_dir)!r})\n{code}"
        with tempfile.TemporaryDirectory(prefix="didsso-storage-caller-") as caller:
            result = subprocess.run(
                [sys.executable, "-B", "-c", script],
                cwd=caller,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wallet_defaults_are_component_local_and_independent_of_cwd(self) -> None:
        for component, directory, module in (
            ("IdP", "IdP/didcomm-backend", "did_peer_service"),
            ("RP", "RP/didcomm-backend", "did_peer_service"),
            ("firefox-extension", "firefox-extension/backend", "did_peer_4_service"),
        ):
            with self.subTest(component=component):
                expected = PROJECT_DIR / component / "data" / "wallet.json"
                self.run_backend(
                    directory,
                    f"import {module} as peer\n"
                    f"from pathlib import Path\n"
                    f"assert peer.WALLET_FILE == Path({str(expected)!r})\n",
                    data_dir=None,
                )

    def test_custom_idp_directory_is_shared_by_wallet_and_protocol_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="didsso-idp-storage-") as temporary:
            self.run_backend(
                "IdP/didcomm-backend",
                """
import server
import did_peer_service as peer
assert peer.DATA_DIR == server.DATA_DIR
for name in (
    'PENDING_FILE', 'REGISTERED_FILE', 'USERS_FILE', 'OIDC_CODES_FILE',
    'USER_DID_LINKS_FILE', 'TOKEN_GRANTS_FILE',
    'STWO_REGISTRATION_SIGNING_KEY_FILE', 'RISC0_REGISTRATION_SIGNING_KEY_FILE',
):
    assert getattr(server, name).parent == server.DATA_DIR, name
server.save_json(server.USERS_FILE, [{'subject': 'test-user', 'email': 'fixture@example.test'}])
assert server.find_user_by_subject('test-user')['email'] == 'fixture@example.test'
peer.create_and_store_did('fixture-idp')
assert peer.WALLET_FILE.parent == server.DATA_DIR
assert len(peer.load_wallet()['dids']) == 1
""",
                data_dir=Path(temporary) / "data",
            )

    def test_custom_rp_directory_contains_flat_configuration_and_all_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="didsso-rp-storage-") as temporary:
            self.run_backend(
                "RP/didcomm-backend",
                """
import server
import did_peer_service as peer
assert peer.DATA_DIR == server.DATA_DIR
for name in (
    'REGISTRATIONS_FILE', 'SSO_SESSIONS_FILE', 'USER_ACCOUNTS_FILE',
    'TOKEN_GRANTS_FILE', 'AUTHORIZATION_CONFIG_FILE',
):
    assert getattr(server, name).parent == server.DATA_DIR, name
assert server.authorization_config() == {'scopes': ['profile', 'email']}
server.update_authorization_config({'scopes': ['email']})
assert server.authorization_config() == {'scopes': ['email']}
assert not (server.DATA_DIR / 'data').exists()
peer.create_and_store_did('fixture-rp')
assert len(peer.load_wallet()['dids']) == 1
""",
                data_dir=Path(temporary) / "data",
            )

    def test_existing_docker_scope_configuration_is_moved_without_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="didsso-legacy-scope-") as temporary:
            self.run_backend(
                "RP/didcomm-backend",
                r"""
import server
legacy = server.DATA_DIR / 'data' / 'authorization_config.json'
legacy.parent.mkdir()
original = b'{"scopes": ["email"]}\n'
legacy.write_bytes(original)
assert server.authorization_config() == {'scopes': ['email']}
assert not legacy.exists()
assert server.AUTHORIZATION_CONFIG_FILE.read_bytes() == original
assert server.authorization_config() == {'scopes': ['email']}
""",
                data_dir=Path(temporary) / "data",
            )

    def test_flat_scope_configuration_is_never_overwritten_by_legacy_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="didsso-scope-priority-") as temporary:
            self.run_backend(
                "RP/didcomm-backend",
                """
import server
legacy = server.DATA_DIR / 'data' / 'authorization_config.json'
legacy.parent.mkdir()
legacy.write_text('{"scopes": ["profile"]}', encoding='utf-8')
server.AUTHORIZATION_CONFIG_FILE.write_text('{"scopes": ["email"]}', encoding='utf-8')
before = server.AUTHORIZATION_CONFIG_FILE.read_bytes()
assert server.authorization_config() == {'scopes': ['email']}
assert server.AUTHORIZATION_CONFIG_FILE.read_bytes() == before
""",
                data_dir=Path(temporary) / "data",
            )


if __name__ == "__main__":
    unittest.main()
