from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import platform
import statistics
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


EVALUATION_DIR = Path(__file__).resolve().parent
ROOT_DIR = EVALUATION_DIR.parent
ZK_RISC0_DIR = ROOT_DIR / "zk-risc0"


def configure_backend() -> None:
    os.environ.setdefault(
        "RISC0_CREDENTIAL_CLI", str(ZK_RISC0_DIR / "risc0_wsl.cmd")
    )

    for path in (ROOT_DIR, ZK_RISC0_DIR):
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)


def timed(function: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    result = function()
    return result, time.perf_counter() - started


def proof_sizes(proof: dict) -> tuple[int, int]:
    try:
        receipt_base64 = proof["proof"]["receipt_base64"]
    except (KeyError, TypeError) as error:
        raise ValueError("RISC Zero proof has no receipt") from error
    if not isinstance(receipt_base64, str) or not receipt_base64:
        raise ValueError("RISC Zero proof has no receipt")
    try:
        receipt = base64.b64decode(receipt_base64, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("RISC Zero proof contains invalid receipt Base64") from error

    serialized_envelope = json.dumps(
        proof,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return len(receipt), len(serialized_envelope)


def statistics_for(values: list[float | int]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "sample_standard_deviation": statistics.stdev(values)
        if len(values) > 1
        else None,
        "minimum": min(values),
        "maximum": max(values),
    }


def summarize(
    name: str,
    setup_seconds: float,
    warmup_runs: int,
    runs: list[dict],
) -> dict:
    prove_values = [run["prove_seconds"] for run in runs]
    verify_values = [run["verify_seconds"] for run in runs]
    receipt_size_values = [run["receipt_size_bytes"] for run in runs]
    envelope_size_values = [run["proof_envelope_size_bytes"] for run in runs]
    return {
        "backend": name,
        "excluded_setup_or_credential_seconds": setup_seconds,
        "unmeasured_warmup_runs": warmup_runs,
        "runs": runs,
        "prove_seconds": statistics_for(prove_values),
        "verify_seconds": statistics_for(verify_values),
        "receipt_size_bytes": statistics_for(receipt_size_values),
        "proof_envelope_size_bytes": statistics_for(envelope_size_values),
    }


def benchmark_risc0(
    run_count: int,
    warmup_count: int,
    progress: Callable[[dict], None] | None = None,
) -> dict:
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
            for _ in range(warmup_count):
                nonce = f"benchmark-risc0-warmup-{uuid.uuid4()}"
                proof = backend.create_registration_proof(credential, nonce)
                verification = backend.verify_registration_proof(
                    proof,
                    expected_nonce=nonce,
                    expected_public_key=credential["idp_public_key"],
                )
                if verification.get("accepted") is not True:
                    raise RuntimeError(f"RISC Zero rejected a warm-up run: {verification}")
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
                receipt_size_bytes, proof_envelope_size_bytes = proof_sizes(proof)
                runs.append(
                    {
                        "run": index,
                        "prove_seconds": prove_seconds,
                        "verify_seconds": verify_seconds,
                        "receipt_size_bytes": receipt_size_bytes,
                        "proof_envelope_size_bytes": proof_envelope_size_bytes,
                    }
                )
                if progress is not None:
                    partial = summarize(
                        "risc0", credential_seconds, warmup_count, runs
                    )
                    partial["excluded_verifier_start_seconds"] = (
                        verifier_start_seconds
                    )
                    progress(partial)
        finally:
            backend.stop_verifier_service()

    result = summarize("risc0", credential_seconds, warmup_count, runs)
    result["excluded_verifier_start_seconds"] = verifier_start_seconds
    return result


def print_backend(result: dict) -> None:
    print(f"\n{result['backend'].upper()}")
    print(
        "  Setup/Credential: "
        f"{result['excluded_setup_or_credential_seconds']:.3f} s (excluded)"
    )
    if "excluded_verifier_start_seconds" in result:
        print(
            "  Verifier-Start:   "
            f"{result['excluded_verifier_start_seconds']:.3f} s (excluded)"
        )
    print(f"  Warm-up runs:    {result['unmeasured_warmup_runs']} (excluded)")
    for run in result["runs"]:
        print(
            f"  Run {run['run']:>2}: prove {run['prove_seconds']:.3f} s, "
            f"verify {run['verify_seconds']:.3f} s, "
            f"receipt {run['receipt_size_bytes'] / 1024:.1f} KiB, "
            f"envelope {run['proof_envelope_size_bytes'] / 1024:.1f} KiB"
        )
    print(
        f"  Prove mean/median:  {result['prove_seconds']['mean']:.3f} / "
        f"{result['prove_seconds']['median']:.3f} s"
    )
    print(
        f"  Verify mean/median: {result['verify_seconds']['mean']:.3f} / "
        f"{result['verify_seconds']['median']:.3f} s"
    )
    prove_sd = result["prove_seconds"]["sample_standard_deviation"]
    verify_sd = result["verify_seconds"]["sample_standard_deviation"]
    if prove_sd is not None and verify_sd is not None:
        print(f"  Prove/verify SD:    {prove_sd:.3f} / {verify_sd:.3f} s")
    print(
        "  Receipt size mean/median:  "
        f"{result['receipt_size_bytes']['mean'] / 1024:.1f} / "
        f"{result['receipt_size_bytes']['median'] / 1024:.1f} KiB"
    )
    print(
        "  Envelope size mean/median: "
        f"{result['proof_envelope_size_bytes']['mean'] / 1024:.1f} / "
        f"{result['proof_envelope_size_bytes']['median'] / 1024:.1f} KiB"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark the RISC Zero proof backend used by DIDSSO."
    )
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmup-runs", type=int, default=1)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.runs < 1:
        parser.error("--runs must be at least 1")
    if arguments.warmup_runs < 0:
        parser.error("--warmup-runs must not be negative")
    return arguments


def resolved_output_path(arguments: argparse.Namespace) -> Path:
    if arguments.output is None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return ROOT_DIR / "benchmark-results" / f"proofs-{timestamp}.json"
    return (
        arguments.output
        if arguments.output.is_absolute()
        else ROOT_DIR / arguments.output
    )


def save_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    arguments = parse_arguments()
    configure_backend()
    report: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version,
        "proof_backend": "risc0",
        "requested_runs": arguments.runs,
        "unmeasured_warmup_runs": arguments.warmup_runs,
        "standard_deviation": "sample standard deviation",
        "status": "running",
        "completed_at": None,
        "results": [],
        "errors": [],
    }
    output_path = resolved_output_path(arguments)
    save_report(output_path, report)

    def persist_result(result: dict) -> None:
        report["results"] = [result]
        save_report(output_path, report)

    exit_code = 0
    print(f"\nBenchmarking RISC0 ({arguments.runs} runs) ...")
    try:
        result = benchmark_risc0(
            arguments.runs,
            arguments.warmup_runs,
            progress=persist_result,
        )
        persist_result(result)
        print_backend(result)
    except KeyboardInterrupt:
        report["errors"].append(
            {"backend": "risc0", "error": "KeyboardInterrupt: cancelled"}
        )
        report["status"] = "cancelled"
        exit_code = 130
    except Exception as error:
        message = f"{type(error).__name__}: {error}"
        report["errors"].append({"backend": "risc0", "error": message})
        print(f"  FAILED: {message}", file=sys.stderr)
        exit_code = 1

    if report["status"] == "running":
        report["status"] = "failed" if report["errors"] else "completed"
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    save_report(output_path, report)
    print(f"\nReport: {output_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
