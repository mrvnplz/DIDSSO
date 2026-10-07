from __future__ import annotations

import atexit
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import threading
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT_DIR = Path(__file__).resolve().parent
PROOF_METHOD = "risc0"
SIGNATURE_SCHEME = "ecdsa-p256-sha256-prehashed"
CREDENTIAL_FORMAT = "did-sso-registration-credential-risc0-p256-v2"
PROOF_FORMAT = "did-sso-registration-risc0-p256-proof-v2"
PROGRAM_ID = "did-sso-registration-risc0-p256-ecdsa-v2"
CONTEXT_DOMAIN = b"did-sso:registration:risc0:v1\x00"
DEFAULT_CLI = ROOT_DIR / "risc0_wsl.cmd"
MAX_RECEIPT_BASE64_LENGTH = 128 * 1024 * 1024
_VERIFY_PROCESS: subprocess.Popen[str] | None = None
_VERIFY_PROCESS_LOCK = threading.RLock()
_VERIFY_PROCESS_STATE_LOCK = threading.Lock()
_VERIFY_SERVICE_SHUTDOWN = threading.Event()


def configured_cli() -> str:
    configured = os.environ.get("RISC0_CREDENTIAL_CLI", "").strip()
    return configured or str(DEFAULT_CLI)


def resolve_cli() -> str:
    command = configured_cli()
    path = Path(command)
    if path.parent != Path(".") and path.exists():
        return str(path)
    resolved = shutil.which(command)
    if resolved:
        return resolved
    raise RuntimeError(
        f"RISC Zero credential CLI not found: {command}. Set RISC0_CREDENTIAL_CLI."
    )


def run_cli(command: str, payload: dict) -> dict:
    if command == "verify":
        return run_persistent_verify(payload)
    completed = subprocess.run(
        [resolve_cli(), command],
        input=json.dumps(payload, separators=(",", ":")),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        cwd=str(ROOT_DIR),
    )
    if completed.returncode != 0:
        details = completed.stderr.strip() or completed.stdout.strip()
        lines = [line for line in details.splitlines() if line.strip()]
        raise RuntimeError(
            f"RISC Zero {command} failed with exit code {completed.returncode}: "
            + "\n".join(lines[-30:])
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"RISC Zero {command} returned invalid JSON: {completed.stdout[-1000:]}"
        ) from error


def start_verifier_service() -> None:
    global _VERIFY_PROCESS
    if _VERIFY_SERVICE_SHUTDOWN.is_set():
        raise RuntimeError("Persistent RISC Zero verifier is shutting down")

    with _VERIFY_PROCESS_LOCK:
        with _VERIFY_PROCESS_STATE_LOCK:
            current_process = _VERIFY_PROCESS
        if current_process is not None and current_process.poll() is None:
            return
        if _VERIFY_SERVICE_SHUTDOWN.is_set():
            raise RuntimeError("Persistent RISC Zero verifier is shutting down")

        process_group_options: dict[str, object] = {}
        if os.name == "nt":
            process_group_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            process_group_options["start_new_session"] = True
        process = subprocess.Popen(
            [resolve_cli(), "verify-server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(ROOT_DIR),
            **process_group_options,
        )
        with _VERIFY_PROCESS_STATE_LOCK:
            _VERIFY_PROCESS = process
        ready_line = process.stdout.readline() if process.stdout else ""
        try:
            ready = json.loads(ready_line)
        except json.JSONDecodeError as error:
            stop_verifier_service()
            raise RuntimeError(
                f"Persistent RISC Zero verifier returned invalid startup data: {ready_line[-500:]}"
            ) from error
        if ready.get("ready") is not True:
            stop_verifier_service()
            raise RuntimeError("Persistent RISC Zero verifier did not become ready")
        if _VERIFY_SERVICE_SHUTDOWN.is_set():
            stop_verifier_service()
            raise RuntimeError("Persistent RISC Zero verifier was stopped during startup")


def _force_stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    if os.name == "nt":
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            if completed.returncode != 0 and process.poll() is None:
                process.kill()
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
        return

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()


def stop_verifier_service(permanent: bool = False) -> None:
    global _VERIFY_PROCESS
    if permanent:
        _VERIFY_SERVICE_SHUTDOWN.set()

    # Do not acquire _VERIFY_PROCESS_LOCK here. A request thread deliberately
    # holds it while waiting for a verifier response. Shutdown must be able to
    # close the pipes and terminate that process so the waiting thread unblocks.
    with _VERIFY_PROCESS_STATE_LOCK:
        process = _VERIFY_PROCESS
        _VERIFY_PROCESS = None
    if process is None:
        return

    if process.stdin:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
        return
    except subprocess.TimeoutExpired:
        _force_stop_process_tree(process)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_persistent_verify(payload: dict) -> dict:
    with _VERIFY_PROCESS_LOCK:
        start_verifier_service()
        process = _VERIFY_PROCESS
        if process is None or process.stdin is None or process.stdout is None:
            raise RuntimeError("Persistent RISC Zero verifier has no usable pipes")
        try:
            process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            process.stdin.flush()
            response_line = process.stdout.readline()
        except (BrokenPipeError, OSError) as error:
            stop_verifier_service()
            raise RuntimeError("Persistent RISC Zero verifier connection failed") from error
        if not response_line:
            exit_code = process.poll()
            stop_verifier_service()
            raise RuntimeError(
                f"Persistent RISC Zero verifier stopped unexpectedly (exit code {exit_code})"
            )
        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Persistent RISC Zero verifier returned invalid JSON: {response_line[-1000:]}"
            ) from error
        if response.get("ok") is not True:
            raise RuntimeError(
                f"RISC Zero verify failed: {response.get('error', 'unknown verifier error')}"
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("Persistent RISC Zero verifier returned no result object")
        return result


atexit.register(stop_verifier_service, True)


def int_to_hex_32(value: int, label: str) -> str:
    if not 0 <= value < 2**256:
        raise ValueError(f"{label} does not fit into 256 bits")
    return value.to_bytes(32, "big").hex()


def fixed_hex(value: str, byte_length: int, label: str) -> str:
    value = str(value).removeprefix("0x").lower()
    if len(value) != byte_length * 2:
        raise ValueError(f"{label} must contain exactly {byte_length} bytes")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} is not valid hexadecimal text") from error
    return value


def _public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    numbers = private_key.public_key().public_numbers()
    return int_to_hex_32(numbers.x, "public_key.x") + int_to_hex_32(
        numbers.y, "public_key.y"
    )


def load_or_create_p256_signing_key(signing_key_path: Path) -> dict:
    if signing_key_path.exists():
        key = json.loads(signing_key_path.read_text(encoding="utf-8"))
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_value = private_key.private_numbers().private_value
        key = {
            "scheme": SIGNATURE_SCHEME,
            "private_key": int_to_hex_32(private_value, "private_key"),
            "public_key": _public_key_hex(private_key),
        }

    if key.get("scheme") != SIGNATURE_SCHEME:
        raise ValueError("Unsupported RISC Zero registration signing key scheme")
    private_value = int(fixed_hex(key["private_key"], 32, "private_key"), 16)
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    expected_public_key = _public_key_hex(private_key)
    if fixed_hex(key["public_key"], 64, "public_key") != expected_public_key:
        raise ValueError("Stored P-256 public key does not match its private key")
    key["public_key"] = expected_public_key

    signing_key_path.parent.mkdir(parents=True, exist_ok=True)
    signing_key_path.write_text(json.dumps(key, indent=2), encoding="utf-8")
    try:
        signing_key_path.chmod(0o600)
    except OSError:
        pass
    return key


def sign_registration_secret(
    credential_secret: bytes, signing_key_path: Path
) -> tuple[dict, int, int]:
    if len(credential_secret) != 32:
        raise ValueError("credential_secret must be a 32-byte SHA-256-sized value")
    key = load_or_create_p256_signing_key(signing_key_path)
    private_key = ec.derive_private_key(int(key["private_key"], 16), ec.SECP256R1())
    der_signature = private_key.sign(
        credential_secret,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    signature_r, signature_s = utils.decode_dss_signature(der_signature)
    return key, signature_r, signature_s


def request_context_digest(nonce: str) -> str:
    nonce = str(nonce).strip()
    if not nonce:
        raise ValueError("A non-empty authorization nonce is required")
    return hashlib.sha256(CONTEXT_DOMAIN + nonce.encode("utf-8")).hexdigest()


def issue_registration_credential(
    idp_master_did: str,
    request_id: str,
    signing_key_path: Path,
) -> dict:
    secret = secrets.token_bytes(32)
    key, signature_r, signature_s = sign_registration_secret(secret, signing_key_path)
    return {
        "format": CREDENTIAL_FORMAT,
        "proof_method": PROOF_METHOD,
        "risc0_program_id": PROGRAM_ID,
        "issuer": idp_master_did,
        "subject_hint": "rp-registration",
        "credential_secret": secret.hex(),
        "idp_public_key": key["public_key"],
        "signature_r": str(signature_r),
        "signature_s": str(signature_s),
        "signature_scheme": SIGNATURE_SCHEME,
        "request_id": request_id,
    }


def registration_verifier_config(signing_key_path: Path) -> dict:
    key = load_or_create_p256_signing_key(signing_key_path)
    return {
        "proof_method": PROOF_METHOD,
        "idp_public_key": key["public_key"],
    }


def ensure_supported_credential(credential: dict) -> None:
    if credential.get("format") != CREDENTIAL_FORMAT:
        raise ValueError("Register this RP again to obtain a RISC Zero credential")
    if credential.get("proof_method") != PROOF_METHOD:
        raise ValueError("Credential belongs to a different proof backend")
    if credential.get("signature_scheme") != SIGNATURE_SCHEME:
        raise ValueError("Unsupported credential signature scheme")
    if credential.get("risc0_program_id") != PROGRAM_ID:
        raise ValueError("Unsupported RISC Zero credential program")


def create_registration_proof(
    credential: dict,
    nonce: str | None = None,
) -> dict:
    ensure_supported_credential(credential)
    nonce_value = nonce or str(uuid.uuid4())
    context_digest = request_context_digest(nonce_value)
    expected_public_key = fixed_hex(
        credential["idp_public_key"], 64, "idp_public_key"
    )
    response = run_cli(
        "prove",
        {
            "credential_secret": fixed_hex(
                credential["credential_secret"], 32, "credential_secret"
            ),
            "signature_r": int_to_hex_32(int(credential["signature_r"]), "signature_r"),
            "signature_s": int_to_hex_32(int(credential["signature_s"]), "signature_s"),
            "idp_public_key": expected_public_key,
            "context_digest": context_digest,
        },
    )
    journal = response.get("journal", {})
    if journal.get("idp_public_key") != expected_public_key:
        raise RuntimeError("RISC Zero prover returned an unexpected IdP public key")
    if journal.get("context_digest") != context_digest:
        raise RuntimeError("RISC Zero prover returned an unexpected request context")

    return {
        "format": PROOF_FORMAT,
        "proof_method": PROOF_METHOD,
        "program_id": PROGRAM_ID,
        "nonce": nonce_value,
        "context_digest": context_digest,
        "proof": {
            "type": "risc0-zkvm-receipt",
            "method_id": response["method_id"],
            "receipt_base64": response["receipt_base64"],
        },
    }


def verify_registration_proof(
    proof: dict,
    *,
    expected_nonce: str,
    expected_public_key: str,
    expected_program_fingerprint: str = "",
) -> dict:
    del expected_program_fingerprint
    if proof.get("format") != PROOF_FORMAT:
        return {"accepted": False, "error": "Unsupported RISC Zero proof format"}
    if proof.get("proof_method") != PROOF_METHOD or proof.get("program_id") != PROGRAM_ID:
        return {"accepted": False, "error": "Proof belongs to a different backend or program"}
    if proof.get("nonce") != expected_nonce:
        return {"accepted": False, "error": "Proof nonce does not match the authorization code"}

    expected_context_digest = request_context_digest(expected_nonce)
    if proof.get("context_digest") != expected_context_digest:
        return {"accepted": False, "error": "Proof context does not match this request"}
    proof_body = proof.get("proof", {})
    receipt_base64 = proof_body.get("receipt_base64", "")
    if proof_body.get("type") != "risc0-zkvm-receipt" or not receipt_base64:
        return {"accepted": False, "error": "Missing RISC Zero receipt"}
    if len(receipt_base64) > MAX_RECEIPT_BASE64_LENGTH:
        return {"accepted": False, "error": "RISC Zero receipt exceeds the size limit"}

    expected_public_key_hex = fixed_hex(expected_public_key, 64, "idp_public_key")
    try:
        verification = run_cli(
            "verify",
            {
                "receipt_base64": receipt_base64,
                "expected_idp_public_key": expected_public_key_hex,
                "expected_context_digest": expected_context_digest,
            },
        )
    except (KeyError, RuntimeError, TypeError, ValueError) as error:
        return {"accepted": False, "error": str(error)}

    if verification.get("accepted") is not True:
        return {"accepted": False, "error": "RISC Zero verifier rejected the receipt"}
    if proof_body.get("method_id") != verification.get("method_id"):
        return {"accepted": False, "error": "Receipt method ID does not match the proof envelope"}
    journal = verification.get("journal", {})
    if journal.get("idp_public_key") != expected_public_key_hex:
        return {"accepted": False, "error": "Journal is bound to a different IdP key"}
    if journal.get("context_digest") != expected_context_digest:
        return {"accepted": False, "error": "Journal is bound to a different request"}

    return {
        "accepted": True,
        "program_id": PROGRAM_ID,
        "proof_method": PROOF_METHOD,
        "idp_public_key": expected_public_key,
        "risc0": {
            "method_id": verification["method_id"],
            "journal": journal,
        },
    }
