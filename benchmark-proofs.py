from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROOT_DIR = Path(__file__).resolve().parent
ZK_STARK_DIR = ROOT_DIR / "zk-stark"
ZK_RISC0_DIR = ROOT_DIR / "zk-risc0"


def configure_backends() -> None:
    os.environ.setdefault(
        "STWO_RUN_AND_PROVE", str(ZK_STARK_DIR / "run_and_prove_wsl.cmd")
    )
    os.environ.setdefault("STWO_VERIFY", str(ZK_STARK_DIR / "verify_wsl.cmd"))
    os.environ.setdefault("STWO_SCARB", str(ZK_STARK_DIR / "scarb_wsl.cmd"))
    os.environ.setdefault(
        "STWO_CAIRO_EXECUTE", str(ZK_STARK_DIR / "cairo_execute_wsl.cmd")
    )
    os.environ.setdefault("STWO_CHANNEL_HASH", "blake2s")
    os.environ.setdefault("STWO_ALLOW_NATIVE_WINDOWS", "0")
    os.environ.setdefault(
        "RISC0_CREDENTIAL_CLI", str(ZK_RISC0_DIR / "risc0_wsl.cmd")
    )

    for path in (ROOT_DIR, ZK_STARK_DIR, ZK_RISC0_DIR):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def timed(function: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    result = function()
    return result, time.perf_counter() - started


def proof_size_bytes(proof: dict) -> int:
    return len(json.dumps(proof, separators=(",", ":")).encode("utf-8"))


def statistics_for(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }


def summarize(name: str, setup_seconds: float, runs: list[dict]) -> dict:
    prove_values = [run["prove_seconds"] for run in runs]
    verify_values = [run["verify_seconds"] for run in runs]
    size_values = [run["proof_size_bytes"] for run in runs]
    return {
        "backend": name,
        "setup_or_credential_seconds": setup_seconds,
        "runs": runs,
        "prove_seconds": statistics_for(prove_values),
        "verify_seconds": statistics_for(verify_values),
        "proof_size_bytes": {
            "mean": statistics.fmean(size_values),
            "minimum": min(size_values),
            "maximum": max(size_values),
        },
    }


def benchmark_risc0(run_count: int) -> dict:
    import credential_risc0 as backend

    with tempfile.TemporaryDirectory(prefix="didsso-risc0-benchmark-") as temporary:
        key_path = Path(temporary) / "registration-key.json"
        credential, credential_seconds = timed(
            lambda: backend.issue_registration_credential(
                "did:peer:benchmark-idp", "benchmark-risc0", key_path
            )
        )
        _, verifier_start_seconds = timed(backend.start_verifier_service)
        runs: list[dict] = []
        try:
            for index in range(1, run_count + 1):
                nonce = f"benchmark-risc0-{uuid.uuid4()}"
                proof, prove_seconds = timed(
                    lambda: backend.create_registration_proof(credential, nonce)
                )
                verification, verify_seconds = timed(
                    lambda: backend.verify_registration_proof(
                        proof,
                        expected_nonce=nonce,
                        expected_public_key=credential["idp_public_key"],
                    )
                )
                if verification.get("accepted") is not True:
                    raise RuntimeError(f"RISC Zero rejected run {index}: {verification}")
                runs.append(
                    {
                        "run": index,
                        "prove_seconds": prove_seconds,
                        "verify_seconds": verify_seconds,
                        "proof_size_bytes": proof_size_bytes(proof),
                    }
                )
        finally:
            backend.stop_verifier_service()

    result = summarize("risc0", credential_seconds, runs)
    result["verifier_start_seconds"] = verifier_start_seconds
    return result


def benchmark_stwo(run_count: int) -> dict:
    import credential_stark as backend

    generated_program_dir: Path | None = None
    with tempfile.TemporaryDirectory(prefix="didsso-stwo-benchmark-") as temporary:
        key_path = Path(temporary) / "registration-key.json"
        started = time.perf_counter()
        raw_key = backend.load_or_create_raw_signing_key(key_path)
        generated_program_dir = (
            ZK_STARK_DIR
            / "registration-proof-program-v3"
            / str(raw_key["public_key"])
        )
        if generated_program_dir.exists():
            raise RuntimeError(
                f"Refusing to reuse or remove existing STWO program: {generated_program_dir}"
            )

        try:
            credential = backend.issue_registration_credential(
                "did:peer:benchmark-idp", "benchmark-stwo", key_path
            )
            credential_seconds = time.perf_counter() - started
            runs: list[dict] = []
            for index in range(1, run_count + 1):
                nonce = f"benchmark-stwo-{uuid.uuid4()}"
                proof, prove_seconds = timed(
                    lambda: backend.create_registration_proof(credential, nonce)
                )
                verification, verify_seconds = timed(
                    lambda: backend.verify_registration_proof(
                        proof,
                        expected_nonce=nonce,
                        expected_public_key=credential["idp_public_key"],
                        expected_program_fingerprint=credential[
                            "program_fingerprint"
                        ],
                    )
                )
                if verification.get("accepted") is not True:
                    raise RuntimeError(f"STWO rejected run {index}: {verification}")
                runs.append(
                    {
                        "run": index,
                        "prove_seconds": prove_seconds,
                        "verify_seconds": verify_seconds,
                        "proof_size_bytes": proof_size_bytes(proof),
                    }
                )
        finally:
            if generated_program_dir is not None and generated_program_dir.exists():
                shutil.rmtree(generated_program_dir)

    return summarize("stwo", credential_seconds, runs)


def print_backend(result: dict) -> None:
    print(f"\n{result['backend'].upper()}")
    print(
        "  Setup/Credential: "
        f"{result['setup_or_credential_seconds']:.3f} s"
    )
    if "verifier_start_seconds" in result:
        print(f"  Verifier-Start:   {result['verifier_start_seconds']:.3f} s")
    for run in result["runs"]:
        print(
            f"  Run {run['run']:>2}: prove {run['prove_seconds']:.3f} s, "
            f"verify {run['verify_seconds']:.3f} s, "
            f"size {run['proof_size_bytes'] / 1024:.1f} KiB"
        )
    print(
        f"  Prove mean/median:  {result['prove_seconds']['mean']:.3f} / "
        f"{result['prove_seconds']['median']:.3f} s"
    )
    print(
        f"  Verify mean/median: {result['verify_seconds']['mean']:.3f} / "
        f"{result['verify_seconds']['median']:.3f} s"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark the DIDSSO STWO and RISC Zero proof backends."
    )
    parser.add_argument(
        "--backend", choices=("all", "stwo", "risc0"), default="all"
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.runs < 1:
        parser.error("--runs must be at least 1")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    configure_backends()
    selected = (
        ("stwo", "risc0") if arguments.backend == "all" else (arguments.backend,)
    )
    report: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version,
        "requested_runs": arguments.runs,
        "results": [],
        "errors": [],
    }

    benchmarks = {"stwo": benchmark_stwo, "risc0": benchmark_risc0}
    for backend_name in selected:
        print(f"\nBenchmarking {backend_name.upper()} ({arguments.runs} runs) ...")
        try:
            result = benchmarks[backend_name](arguments.runs)
            report["results"].append(result)
            print_backend(result)
        except KeyboardInterrupt:
            raise
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            report["errors"].append({"backend": backend_name, "error": message})
            print(f"  FAILED: {message}", file=sys.stderr)

    output_path = arguments.output
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = ROOT_DIR / "benchmark-results" / f"proofs-{timestamp}.json"
    elif not output_path.is_absolute():
        output_path = ROOT_DIR / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport: {output_path}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
