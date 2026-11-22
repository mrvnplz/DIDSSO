from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import uuid
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_SCARB = ROOT_DIR / "scarb_wsl.cmd"
DEFAULT_CAIRO_EXECUTE = ROOT_DIR / "cairo_execute_wsl.cmd"
DEFAULT_RUN_AND_PROVE = ROOT_DIR / "run_and_prove_wsl.cmd"
DEFAULT_VERIFY = ROOT_DIR / "verify_wsl.cmd"


def configured_stwo_tool(env_name: str, wrapper: Path, fallback: str) -> str:
    configured = os.environ.get(env_name, "")
    native_windows_opt_in = os.environ.get("STWO_ALLOW_NATIVE_WINDOWS") == "1"
    if (
        os.name == "nt"
        and configured.lower().endswith(".exe")
        and wrapper.exists()
        and not native_windows_opt_in
    ):
        return str(wrapper)
    if configured:
        return configured
    return str(wrapper if wrapper.exists() else fallback)


STWO_RUN_AND_PROVE = configured_stwo_tool(
    "STWO_RUN_AND_PROVE", DEFAULT_RUN_AND_PROVE, "run_and_prove"
)
STWO_VERIFY = configured_stwo_tool("STWO_VERIFY", DEFAULT_VERIFY, "verify")
STWO_SCARB = os.environ.get(
    "STWO_SCARB",
    str(DEFAULT_SCARB if DEFAULT_SCARB.exists() else "scarb"),
)
STWO_CAIRO_EXECUTE = os.environ.get(
    "STWO_CAIRO_EXECUTE",
    str(DEFAULT_CAIRO_EXECUTE if DEFAULT_CAIRO_EXECUTE.exists() else "cairo-execute"),
)
STWO_CHANNEL_HASH = os.environ.get("STWO_CHANNEL_HASH", "blake2s")
STWO_PARAMS_JSON = os.environ.get("STWO_PARAMS_JSON", "")

FIELD_PRIME = 2**251 + 17 * 2**192 + 1
CURVE_ORDER = int("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f", 16)
GENERATOR = (
    int("01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca", 16),
    int("05668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f", 16),
)
SMALL_VALUE_BOUND = 2**20
PROGRAM_ID = "registration-credential-stwo-cairo-v3"
CREDENTIAL_FORMAT = "did-sso-registration-credential-v3"
PROOF_FORMAT = "did-sso-registration-stark-proof-v3"
PROOF_TYPE = "stwo-cairo-stark-proof"
SIGNATURE_SCHEME = "stark-curve-ecdsa"


def small_felt_from_text(text: str) -> int:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % SMALL_VALUE_BOUND


def _point_add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD_PRIME == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + 1) * pow(2 * y1, -1, FIELD_PRIME)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD_PRIME)
    slope %= FIELD_PRIME
    x3 = (slope * slope - x1 - x2) % FIELD_PRIME
    return x3, (slope * (x1 - x3) - y1) % FIELD_PRIME


def _scalar_multiply(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _sign(message: int, private_key: int) -> tuple[int, int]:
    while True:
        nonce = secrets.randbelow(CURVE_ORDER - 1) + 1
        point = _scalar_multiply(nonce, GENERATOR)
        if point is None:
            continue
        signature_r = point[0]
        if not 1 <= signature_r < CURVE_ORDER:
            continue
        signature_s = (
            pow(nonce, -1, CURVE_ORDER)
            * (message + signature_r * private_key)
        ) % CURVE_ORDER
        if signature_s:
            return signature_r, signature_s


def run_command(args: list[str | Path], cwd: Path = ROOT_DIR) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [str(arg) for arg in args],
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if completed.returncode != 0:
        output = completed.stderr.strip() or completed.stdout.strip()
        lines = [line for line in output.splitlines() if line.strip()]
        raise RuntimeError(
            f"command failed with exit code {completed.returncode}\n"
            + "\n".join(lines[-25:])
        )
    return completed


def resolve_executable(command: str, label: str, env_name: str) -> str:
    path = Path(command)
    if path.parent != Path(".") and path.exists():
        return str(path)
    resolved = shutil.which(command)
    if resolved:
        return resolved
    raise RuntimeError(f"{label} not found: {command}. Set {env_name}.")


def write_stwo_params(output_dir: Path, artifact_id: str) -> Path:
    if STWO_PARAMS_JSON.strip():
        return Path(STWO_PARAMS_JSON)
    params_path = output_dir / f"{artifact_id}-stwo-params.json"
    params_path.write_text(
        json.dumps(
            {
                "channel_hash": STWO_CHANNEL_HASH,
                "channel_salt": 0,
                "pcs_config": {
                    "pow_bits": 16,
                    "fri_config": {
                        "log_last_layer_degree_bound": 0,
                        "log_blowup_factor": 1,
                        "n_queries": 32,
                        "fold_step": 1,
                    },
                    "lifting_log_size": None,
                },
                "preprocessed_trace": "canonical_without_pedersen",
                "store_polynomials_coefficients": False,
                "include_all_preprocessed_columns": False,
                "opt_n_id_to_big_components": None,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return params_path


def _render_fixed_project(public_key: int) -> Path:
    project_dir = ROOT_DIR / "registration-proof-program-v3" / str(public_key)
    source_dir = project_dir / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "Scarb.toml").write_text(
        """[package]
name = "did_sso_registration_proof"
version = "0.1.0"
edition = "2024_07"

[[target.executable]]

[cairo]
enable-gas = false
allow-warnings = false

[dependencies]
cairo_execute = "2.18.0"
""",
        encoding="utf-8",
    )
    (project_dir / "cairo_project.toml").write_text(
        """[crate_roots]
"did_sso_registration_proof" = "src"

[config.global]
edition = "2024_07"
version = "0.1.0"
cfg_set = [["target", "lib"]]
""",
        encoding="utf-8",
    )
    (source_dir / "lib.cairo").write_text(
        f"""use core::ecdsa::check_ecdsa_signature;

const IDP_PUBLIC_KEY: felt252 = {public_key};
#[executable]
fn main(
    credential_secret: u128,
    signature_r: felt252,
    signature_s: felt252,
    nonce: u32,
) -> felt252 {{
    let secret: felt252 = credential_secret.into();
    assert(
        check_ecdsa_signature(
            secret,
            IDP_PUBLIC_KEY,
            signature_r,
            signature_s,
        ),
        'invalid credential',
    );

    let nonce_value: felt252 = nonce.into();
    nonce_value
}}
""",
        encoding="utf-8",
    )
    return project_dir


def _build_fixed_executable(public_key: int) -> Path:
    project_dir = _render_fixed_project(public_key)
    executable_path = project_dir / "did_sso_registration_proof.executable.json"
    if executable_path.exists():
        return executable_path

    scarb = resolve_executable(STWO_SCARB, "Scarb", "STWO_SCARB")
    cairo_execute = resolve_executable(
        STWO_CAIRO_EXECUTE, "cairo-execute", "STWO_CAIRO_EXECUTE"
    )
    version = run_command([scarb, "--version"], cwd=project_dir)
    version_output = (version.stdout + version.stderr).strip()
    if "scarb 2.18." not in version_output:
        raise RuntimeError(f"Scarb 2.18.x is required, got: {version_output}")

    run_command(
        [
            cairo_execute,
            project_dir,
            "--executable",
            "did_sso_registration_proof::main",
            "--build-only",
            "--output-path",
            executable_path,
            "--allow-warnings",
        ],
        cwd=project_dir,
    )
    if not executable_path.exists():
        raise RuntimeError("cairo-execute did not produce the fixed executable")
    return executable_path


def _program_fingerprint(executable_path: Path) -> str:
    executable = json.loads(executable_path.read_text(encoding="utf-8"))
    bytecode = [str(value).lower() for value in executable["program"]["bytecode"]]
    return hashlib.sha256(
        json.dumps(bytecode, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _public_program_fingerprint(proof_json: dict) -> str:
    entries = proof_json["claim"]["public_data"]["public_memory"]["program"]
    memory: dict[int, list[int]] = {}
    for address, limbs in entries:
        address = int(address)
        normalized_limbs = [int(limb) for limb in limbs]
        if address in memory and memory[address] != normalized_limbs:
            raise ValueError("Conflicting public program memory")
        memory[address] = normalized_limbs
    canonical = sorted(memory.items())
    return hashlib.sha256(
        json.dumps(canonical, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _execute_proof(
    program_path: Path,
    arguments: list[int],
) -> dict:
    output_dir = ROOT_DIR / "proof-artifacts"
    output_dir.mkdir(exist_ok=True)
    artifact_id = str(uuid.uuid4())
    proof_path = output_dir / f"{artifact_id}-stwo-proof.json"
    arguments_path = output_dir / f"{artifact_id}-arguments.json"
    arguments_path.write_text(
        json.dumps([hex(value) for value in arguments]),
        encoding="utf-8",
    )
    params_path = write_stwo_params(output_dir, artifact_id)
    run_and_prove = resolve_executable(
        STWO_RUN_AND_PROVE, "stwo-cairo run_and_prove", "STWO_RUN_AND_PROVE"
    )
    generated_params = not STWO_PARAMS_JSON.strip()
    try:
        run_command(
            [
                run_and_prove,
                "--program",
                program_path,
                "--program_type",
                "executable",
                "--program_arguments_file",
                arguments_path,
                "--proof_path",
                proof_path,
                "--params_json",
                params_path,
            ]
        )
        return json.loads(proof_path.read_text(encoding="utf-8"))
    finally:
        arguments_path.unlink(missing_ok=True)
        proof_path.unlink(missing_ok=True)
        if generated_params:
            params_path.unlink(missing_ok=True)


def load_or_create_raw_signing_key(signing_key_path: Path) -> dict:
    if signing_key_path.exists():
        key = json.loads(signing_key_path.read_text(encoding="utf-8"))
    else:
        private_key = secrets.randbelow(CURVE_ORDER - 1) + 1
        public_point = _scalar_multiply(private_key, GENERATOR)
        if public_point is None:
            raise RuntimeError("Failed to derive registration signing key")
        key = {
            "scheme": SIGNATURE_SCHEME,
            "private_key": str(private_key),
            "public_key": str(public_point[0]),
        }

    if key.get("scheme") != SIGNATURE_SCHEME:
        raise ValueError("Unsupported registration signing key scheme")
    signing_key_path.parent.mkdir(parents=True, exist_ok=True)
    signing_key_path.write_text(json.dumps(key, indent=2), encoding="utf-8")
    return key


def load_or_create_signing_key(signing_key_path: Path) -> dict:
    key = load_or_create_raw_signing_key(signing_key_path)

    executable_path = _build_fixed_executable(int(key["public_key"]))
    key["executable_fingerprint"] = _program_fingerprint(executable_path)
    if key.get("program_id") != PROGRAM_ID:
        signature_r, signature_s = _sign(1, int(key["private_key"]))
        reference_proof = _execute_proof(
            executable_path,
            [1, signature_r, signature_s, 0],
        )
        key["public_program_fingerprint"] = _public_program_fingerprint(reference_proof)
        key["program_id"] = PROGRAM_ID
    signing_key_path.parent.mkdir(parents=True, exist_ok=True)
    signing_key_path.write_text(json.dumps(key, indent=2), encoding="utf-8")
    return key


def registration_verifier_config(signing_key_path: Path) -> dict:
    key = load_or_create_signing_key(signing_key_path)
    return {
        "idp_public_key": key["public_key"],
        "program_fingerprint": key["public_program_fingerprint"],
    }


def issue_registration_credential(
    idp_master_did: str,
    request_id: str,
    signing_key_path: Path,
) -> dict:
    key = load_or_create_signing_key(signing_key_path)
    secret = secrets.randbits(128)
    signature_r, signature_s = _sign(secret, int(key["private_key"]))
    return {
        "format": CREDENTIAL_FORMAT,
        "stark_program_id": PROGRAM_ID,
        "issuer": idp_master_did,
        "subject_hint": "rp-registration",
        "credential_secret": str(secret),
        "idp_public_key": key["public_key"],
        "signature_r": str(signature_r),
        "signature_s": str(signature_s),
        "signature_scheme": SIGNATURE_SCHEME,
        "executable_fingerprint": key["executable_fingerprint"],
        "program_fingerprint": key["public_program_fingerprint"],
        "request_id": request_id,
    }


def _ensure_supported_credential(credential: dict) -> None:
    if credential.get("format") != CREDENTIAL_FORMAT:
        raise ValueError("Register this RP again to obtain a v3 credential")
    if credential.get("signature_scheme") != SIGNATURE_SCHEME:
        raise ValueError("Unsupported credential signature scheme")
    if credential.get("stark_program_id") != PROGRAM_ID:
        raise ValueError("Unsupported STARK program")


def create_registration_proof(
    credential: dict,
    nonce: str | None = None,
) -> dict:
    _ensure_supported_credential(credential)
    nonce_value = nonce or str(uuid.uuid4())
    nonce_felt = small_felt_from_text(f"nonce:{nonce_value}")
    public_key = int(credential["idp_public_key"])
    program_path = _build_fixed_executable(public_key)
    if _program_fingerprint(program_path) != credential["executable_fingerprint"]:
        raise ValueError("Credential is bound to a different proof program")

    proof_json = _execute_proof(
        program_path,
        [
            int(credential["credential_secret"]),
            int(credential["signature_r"]),
            int(credential["signature_s"]),
            nonce_felt,
        ],
    )
    return {
        "format": PROOF_FORMAT,
        "program_id": PROGRAM_ID,
        "nonce": nonce_value,
        "proof": {
            "type": PROOF_TYPE,
            "proof": proof_json,
        },
    }


def verify_stwo_proof_file(proof_path: Path) -> dict:
    verifier = resolve_executable(STWO_VERIFY, "stwo-cairo verify", "STWO_VERIFY")
    completed = run_command(
        [
            verifier,
            "--proof_path",
            proof_path,
            "--channel_hash",
            STWO_CHANNEL_HASH,
        ]
    )
    return {"accepted": True, "stdout": completed.stdout, "stderr": completed.stderr}


def _felt_from_limbs(limbs: list[int]) -> int:
    return sum(int(limb) << (31 * index) for index, limb in enumerate(limbs))


def _proof_output(proof_json: dict) -> int:
    entries = proof_json["claim"]["public_data"]["public_memory"]["output"]
    if len(entries) != 1:
        raise ValueError("Unexpected number of public outputs")
    return _felt_from_limbs(entries[0][1])


def verify_registration_proof(
    proof: dict,
    *,
    expected_nonce: str,
    expected_public_key: str,
    expected_program_fingerprint: str,
) -> dict:
    if proof.get("format") != PROOF_FORMAT:
        return {"accepted": False, "error": "Unsupported STARK proof format"}
    if proof.get("program_id") != PROGRAM_ID:
        return {"accepted": False, "error": "Unsupported STARK program"}
    if proof.get("nonce") != expected_nonce:
        return {"accepted": False, "error": "Proof nonce does not match the authorization code"}

    proof_body = proof.get("proof", {})
    proof_json = proof_body.get("proof")
    if proof_body.get("type") != PROOF_TYPE or not proof_json:
        return {"accepted": False, "error": "Missing stwo-cairo proof JSON"}

    try:
        if _public_program_fingerprint(proof_json) != expected_program_fingerprint:
            return {"accepted": False, "error": "Proof used an untrusted Cairo program"}
        if _proof_output(proof_json) != small_felt_from_text(f"nonce:{expected_nonce}"):
            return {"accepted": False, "error": "Proof output is not bound to this request"}
    except (KeyError, TypeError, ValueError) as error:
        return {"accepted": False, "error": f"Invalid public proof data: {error}"}

    output_dir = ROOT_DIR / "verified-proof-artifacts"
    output_dir.mkdir(exist_ok=True)
    proof_path = output_dir / f"{uuid.uuid4()}-stwo-proof.json"
    try:
        proof_path.write_text(json.dumps(proof_json, indent=2), encoding="utf-8")
        verification = verify_stwo_proof_file(proof_path)
    finally:
        proof_path.unlink(missing_ok=True)
    return {
        "accepted": verification["accepted"],
        "program_id": PROGRAM_ID,
        "idp_public_key": expected_public_key,
        "stwo": {
            "channel_hash": STWO_CHANNEL_HASH,
            "stdout": verification["stdout"],
            "stderr": verification["stderr"],
        },
    }
