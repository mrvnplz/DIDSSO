"""Independent reset checks using only synthetic, temporary prototype data.

The project reset script is copied before every test. It is never invoked against
the real project or any of its wallets, containers, or browser profiles.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_SOURCE = Path(__file__).resolve().parents[1] / "reset-state.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
IDP_ARRAYS = (
    "sso_token_grants.json", "sessions.json", "users.json",
    "sso_user_did_links.json", "oidc_codes.json", "registered_rps.json",
    "pending_rp_requests.json",
)
RP_ARRAYS = (
    "idp_registrations.json", "token_grants.json", "user_accounts.json",
    "sso_sessions.json",
)
WALLET_OBJECTS = ("selected_did.json", "sso_auth_request.json", "sso_result.json")


@unittest.skipUnless(POWERSHELL, "PowerShell is required to test reset-state.ps1")
class ResetStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="didsso-reset-test-")
        self.addCleanup(self.temp.cleanup)
        self.sandbox = Path(self.temp.name)
        self.project = self.sandbox / "prototype"
        self.caller = self.sandbox / "unrelated-caller"
        self.caller.mkdir()
        for directory in ("IdP/didcomm-backend", "RP/didcomm-backend", "firefox-extension/backend"):
            (self.project / directory).mkdir(parents=True)
        self.script = self.project / "reset-state.ps1"
        shutil.copy2(SCRIPT_SOURCE, self.script)
        self.write(self.project / "firefox-extension/manifest.json", {"name": "fixture"})
        (self.project / "firefox-extension/backend/server.py").write_text(
            "# synthetic source file, not a running backend\n", encoding="utf-8"
        )
        self.default_roots = (
            self.project / "IdP/data", self.project / "RP/data",
            self.project / "firefox-extension/data",
        )

    @staticmethod
    def write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    @staticmethod
    def expected_targets(roots: tuple[Path, Path, Path]) -> dict[Path, object]:
        idp, rp, wallet = roots
        targets = {idp / name: [] for name in IDP_ARRAYS}
        targets.update({rp / name: [] for name in RP_ARRAYS})
        targets.update({root / "wallet.json": {"dids": []} for root in roots})
        targets.update({wallet / name: {} for name in WALLET_OBJECTS})
        return targets

    def seed(self, roots=None, *, include_user_wallet=True) -> dict[Path, object]:
        roots = roots or self.default_roots
        targets = self.expected_targets(roots)
        for path, empty_value in targets.items():
            if not include_user_wallet and path.parent == roots[2]:
                continue
            if empty_value == []:
                value = [{"old": "state"}]
            elif path.name == "wallet.json":
                value = {"dids": [{"did": "did:peer:old-fixture"}]}
            else:
                value = {"old": "state"}
            self.write(path, value)
        return targets

    def snapshot(self) -> dict[str, bytes | None]:
        return {
            str(path.relative_to(self.sandbox)): None if path.is_dir() else path.read_bytes()
            for path in self.sandbox.rglob("*")
        }

    def invoke(self, *arguments: str, inherited_data_dir: Path | None = None, succeeds=True):
        environment = os.environ.copy()
        environment.pop("DIDSSO_DATA_DIR", None)
        if inherited_data_dir is not None:
            environment["DIDSSO_DATA_DIR"] = str(inherited_data_dir)
        result = subprocess.run(
            [
                POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(self.script), *arguments,
            ],
            cwd=self.caller,
            env=environment,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
        )
        output = result.stdout + result.stderr
        if succeeds:
            self.assertEqual(result.returncode, 0, output)
        else:
            self.assertNotEqual(result.returncode, 0, output)
        return result

    def assert_reset(self, targets: dict[Path, object]) -> None:
        self.assertEqual(len(targets), 17)
        for path, expected in targets.items():
            with self.subTest(path=path.relative_to(self.sandbox)):
                self.assertEqual(json.loads(path.read_text(encoding="utf-8-sig")), expected)
                self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertFalse(list(self.sandbox.rglob("*.tmp")))

    def custom_roots(self):
        roots = tuple(self.sandbox / "external-host-data" / actor for actor in ("idp", "rp", "wallet"))
        for root in roots:
            root.mkdir(parents=True)
        arguments = [
            "-IdpDataDir", str(roots[0]), "-RpDataDir", str(roots[1]),
            "-WalletDataDir", str(roots[2]),
        ]
        return roots, arguments

    def test_default_reset_empties_actual_wallets_and_all_relationship_state(self) -> None:
        targets = self.seed()
        preserved = (
            self.project / "IdP/data/registration_signing_key.json",
            self.project / "IdP/data/registration_signing_key_risc0_p256.json",
            self.project / "RP/data/authorization_config.json",
            self.project / "IdP/didcomm-backend/wallet.json",
            self.project / "RP/didcomm-backend/wallet.json",
        )
        for path in preserved:
            self.write(path, {"preserve": True})
        unchanged = {
            path: path.read_bytes()
            for path in (*preserved, self.script, self.project / "firefox-extension/backend/server.py")
        }
        self.invoke()
        self.assert_reset(targets)
        for path, content in unchanged.items():
            self.assertEqual(path.read_bytes(), content)

    def test_validate_only_preserves_all_existing_files(self) -> None:
        self.seed()
        before = self.snapshot()
        self.invoke("-ValidateOnly")
        self.assertEqual(self.snapshot(), before)

    def test_whatif_preserves_all_existing_files(self) -> None:
        self.seed()
        before = self.snapshot()
        self.invoke("-WhatIf")
        self.assertEqual(self.snapshot(), before)

    def test_missing_generated_wallet_directory_is_created_only_for_real_reset(self) -> None:
        targets = self.seed(include_user_wallet=False)
        self.assertFalse(self.default_roots[2].exists())
        before = self.snapshot()
        self.invoke("-ValidateOnly")
        self.assertEqual(self.snapshot(), before)
        self.invoke("-WhatIf")
        self.assertEqual(self.snapshot(), before)
        self.invoke()
        self.assert_reset(targets)

    def test_explicit_custom_roots_reset_only_the_chosen_host_data(self) -> None:
        self.seed()
        roots, arguments = self.custom_roots()
        targets = self.seed(roots)
        project_before = {
            path: path.read_bytes() for path in self.project.rglob("*") if path.is_file()
        }
        self.invoke(*arguments)
        self.assert_reset(targets)
        for path, content in project_before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_ambiguous_inherited_data_directory_is_rejected_without_writes(self) -> None:
        self.seed()
        inherited = self.sandbox / "inherited-data"
        self.write(inherited / "wallet.json", {"dids": [{"preserve": True}]})
        before = self.snapshot()
        self.invoke(inherited_data_dir=inherited, succeeds=False)
        self.assertEqual(self.snapshot(), before)

    def test_all_explicit_roots_override_inherited_ambiguous_directory(self) -> None:
        roots, arguments = self.custom_roots()
        targets = self.seed(roots)
        inherited = self.sandbox / "inherited-data"
        self.write(inherited / "wallet.json", {"preserve": True})
        old_bytes = (inherited / "wallet.json").read_bytes()
        self.invoke(*arguments, inherited_data_dir=inherited)
        self.assert_reset(targets)
        self.assertEqual((inherited / "wallet.json").read_bytes(), old_bytes)

    def test_partial_explicit_roots_do_not_hide_ambiguous_inherited_directory(self) -> None:
        self.seed()
        inherited = self.sandbox / "inherited-data"
        self.write(inherited / "wallet.json", {"preserve": True})
        before = self.snapshot()
        self.invoke(
            "-IdpDataDir", str(self.default_roots[0]),
            inherited_data_dir=inherited, succeeds=False,
        )
        self.assertEqual(self.snapshot(), before)

    def test_colliding_or_nested_participant_data_roots_are_rejected(self) -> None:
        self.seed()
        roots, arguments = self.custom_roots()
        for wallet_root in (roots[0], roots[0] / "nested-wallet"):
            with self.subTest(wallet_root=wallet_root):
                wallet_root.mkdir(parents=True, exist_ok=True)
                before = self.snapshot()
                self.invoke(*arguments[:-1], str(wallet_root), succeeds=False)
                self.assertEqual(self.snapshot(), before)

    def test_invalid_later_target_fails_before_any_earlier_state_is_reset(self) -> None:
        self.seed(include_user_wallet=False)
        invalid_target = self.default_roots[2] / "sso_result.json"
        invalid_target.mkdir(parents=True)
        before = self.snapshot()
        self.invoke(succeeds=False)
        self.assertEqual(self.snapshot(), before)

    def test_project_ancestor_drive_and_home_roots_are_rejected_read_only(self) -> None:
        self.seed()
        roots, _ = self.custom_roots()
        for invalid_root in (
            self.project, self.project.parent, Path(self.project.anchor), Path.home(),
        ):
            with self.subTest(invalid_root=invalid_root):
                before = self.snapshot()
                # ValidateOnly is mandatory here so even a broken safety check
                # could never write outside this test's temporary directory.
                self.invoke(
                    "-ValidateOnly", "-IdpDataDir", str(invalid_root),
                    "-RpDataDir", str(roots[1]), "-WalletDataDir", str(roots[2]),
                    succeeds=False,
                )
                self.assertEqual(self.snapshot(), before)

    def test_relative_custom_roots_are_resolved_from_the_script_project(self) -> None:
        self.seed()
        roots = tuple(self.project / "custom-data" / actor for actor in ("idp", "rp", "wallet"))
        targets = self.seed(roots)
        original_default = {
            path: path.read_bytes() for path in self.expected_targets(self.default_roots)
        }
        self.invoke(
            "-IdpDataDir", "custom-data/idp", "-RpDataDir", "custom-data/rp",
            "-WalletDataDir", "custom-data/wallet",
        )
        self.assert_reset(targets)
        for path, content in original_default.items():
            self.assertEqual(path.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
