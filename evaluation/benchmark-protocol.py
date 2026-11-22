from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import platform
import ssl
import statistics
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen


EVALUATION_DIR = Path(__file__).resolve().parent
ROOT_DIR = EVALUATION_DIR.parent
EXTENSION_DIR = ROOT_DIR / "firefox-extension"
RESULT_FIELDS = (
    "scenario",
    "run",
    "session_id",
    "proof_backend",
    "navigation_source",
    "token_mode",
    "end_to_end_seconds",
    "proof_generation_seconds",
    "proof_verification_seconds",
    "token_issuance_seconds",
    "token_claims_round_trip_seconds",
    "result_delivery_seconds",
    "wallet_result_validation_latency_seconds",
    "extension_poll_delay_seconds",
    "extension_detection_latency_seconds",
    "browser_processing_seconds",
    "unattributed_seconds",
    "started_at_epoch_ms",
    "rp_logged_in_at_epoch_ms",
    "wallet_result_validated_at_epoch_ms",
    "extension_result_detected_at_epoch_ms",
    "navigation_at_epoch_ms",
    "claims_displayed_at_epoch_ms",
)
SUMMARY_METRICS = tuple(
    field for field in RESULT_FIELDS if field.endswith("_seconds")
)


class EvaluationError(RuntimeError):
    pass


def json_request(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method=method)
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as error:
        response_body = error.read().decode("utf-8", errors="replace")
        raise EvaluationError(
            f"HTTP {error.code} from {url}: {response_body[:300]}"
        ) from error
    except URLError as error:
        raise EvaluationError(f"Could not reach {url}: {error.reason}") from error

    try:
        value = json.loads(raw) if raw else {}
    except json.JSONDecodeError as error:
        raise EvaluationError(f"Invalid JSON from {url}") from error
    if not isinstance(value, dict):
        raise EvaluationError(f"Expected a JSON object from {url}")
    return value


def endpoint(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def statistics_for(values: list[float]) -> dict[str, float | int | None]:
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


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    summaries: dict[str, Any] = {}
    scenarios = sorted({str(result["scenario"]) for result in results})
    for scenario in scenarios:
        scenario_results = [
            result for result in results if result.get("scenario") == scenario
        ]
        metrics: dict[str, Any] = {}
        for metric in SUMMARY_METRICS:
            values = [
                float(result[metric])
                for result in scenario_results
                if isinstance(result.get(metric), (int, float))
            ]
            if values:
                metrics[metric] = statistics_for(values)
        navigation_sources: dict[str, int] = {}
        token_modes: dict[str, int] = {}
        for result in scenario_results:
            source = str(result.get("navigation_source") or "unknown")
            navigation_sources[source] = navigation_sources.get(source, 0) + 1
            mode = str(result.get("token_mode") or "")
            if mode:
                token_modes[mode] = token_modes.get(mode, 0) + 1
        summaries[scenario] = {
            "completed_runs": len(scenario_results),
            "metrics": metrics,
            "navigation_sources": navigation_sources,
            "token_modes": token_modes,
        }
    return summaries


class ReportWriter:
    def __init__(self, output_path: Path, report: dict[str, Any]) -> None:
        self.output_path = output_path
        self.raw_csv_path = output_path.with_name(f"{output_path.stem}-raw.csv")
        self.summary_csv_path = output_path.with_name(
            f"{output_path.stem}-summary.csv"
        )
        self.report = report

    def save(self) -> None:
        self.report["summaries"] = summarize(self.report["results"])
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output_path.with_suffix(f"{self.output_path.suffix}.tmp")
        temporary.write_text(json.dumps(self.report, indent=2), encoding="utf-8")
        temporary.replace(self.output_path)
        self._write_raw_csv()
        self._write_summary_csv()

    def _write_raw_csv(self) -> None:
        with self.raw_csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS)
            writer.writeheader()
            for result in self.report["results"]:
                writer.writerow({field: result.get(field, "") for field in RESULT_FIELDS})

    def _write_summary_csv(self) -> None:
        fields = (
            "scenario",
            "metric",
            "count",
            "mean",
            "median",
            "sample_standard_deviation",
            "minimum",
            "maximum",
        )
        with self.summary_csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for scenario, summary in self.report.get("summaries", {}).items():
                for metric, values in summary.get("metrics", {}).items():
                    writer.writerow(
                        {"scenario": scenario, "metric": metric, **values}
                    )


def build_extension_archive(destination: Path) -> None:
    included = [
        EXTENSION_DIR / "manifest.json",
        EXTENSION_DIR / "background.js",
        *sorted((EXTENSION_DIR / "frontend").rglob("*")),
    ]
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in included:
            if path.is_file():
                archive.write(path, path.relative_to(EXTENSION_DIR).as_posix())


def create_driver(arguments: argparse.Namespace, addon_path: Path):
    try:
        import selenium
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service
    except ImportError as error:
        raise EvaluationError(
            "Selenium is not installed. Run .\\evaluation\\setup-evaluation.ps1 first."
        ) from error

    options = Options()
    options.accept_insecure_certs = True
    if arguments.firefox_binary:
        options.binary_location = str(arguments.firefox_binary)
    if arguments.headless:
        options.add_argument("-headless")
    for preference, value in {
        "browser.cache.disk.enable": False,
        "browser.cache.memory.enable": False,
        "browser.cache.offline.enable": False,
        "network.http.use-cache": False,
        "browser.shell.checkDefaultBrowser": False,
        "app.update.auto": False,
    }.items():
        options.set_preference(preference, value)

    service = (
        Service(executable_path=str(arguments.geckodriver))
        if arguments.geckodriver
        else Service()
    )
    driver = webdriver.Firefox(options=options, service=service)
    driver.set_page_load_timeout(arguments.timeout)
    driver.install_addon(str(addon_path), temporary=True)
    capabilities = dict(driver.capabilities)
    capabilities["seleniumVersion"] = selenium.__version__
    return driver, capabilities


def wait_for(
    driver,
    condition: Callable[[Any], Any],
    timeout: float,
    message: str,
):
    from selenium.webdriver.support.ui import WebDriverWait

    return WebDriverWait(
        driver,
        timeout,
        poll_frequency=0.05,
        ignored_exceptions=(Exception,),
    ).until(condition, message=message)


def element_ready(driver, selector: str) -> bool:
    return bool(
        driver.execute_script(
            """
            const element = document.querySelector(arguments[0]);
            if (!element) return false;
            const style = window.getComputedStyle(element);
            return !element.disabled
                && style.display !== "none"
                && style.visibility !== "hidden"
                && element.getClientRects().length > 0;
            """,
            selector,
        )
    )


def browser_click_timestamp(driver, selector: str) -> float:
    value = driver.execute_script(
        """
        const element = document.querySelector(arguments[0]);
        if (!element || element.disabled) {
            throw new Error(`Element is not ready: ${arguments[0]}`);
        }
        const timestamp = performance.timeOrigin + performance.now();
        element.click();
        return timestamp;
        """,
        selector,
    )
    return float(value)


def authenticate_idp(
    driver,
    *,
    idp_url: str,
    email: str,
    password: str,
    timeout: float,
) -> None:
    from selenium.webdriver.common.by import By

    driver.get(endpoint(idp_url, "/login"))
    if urlparse(driver.current_url).path == "/user":
        return
    wait_for(
        driver,
        lambda current: current.find_elements(By.ID, "email"),
        timeout,
        "IdP login form was not displayed",
    )
    driver.find_element(By.ID, "email").send_keys(email)
    driver.find_element(By.ID, "password").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "form button[type='submit']").click()
    wait_for(
        driver,
        lambda current: urlparse(current.current_url).path == "/user",
        timeout,
        "IdP login failed; verify the benchmark account credentials",
    )


def wait_for_consent(
    driver,
    *,
    email: str,
    password: str,
    timeout: float,
) -> None:
    from selenium.webdriver.common.by import By

    wait_for(
        driver,
        lambda current: urlparse(current.current_url).path == "/sso",
        timeout,
        "The browser did not reach the IdP consent page",
    )
    if parse_qs(urlparse(driver.current_url).query).get(
        "replacement_required", [""]
    )[0] == "1":
        raise EvaluationError(
            "The SSO benchmark reached the pairwise-DID replacement flow; "
            "reset the wallet binding before measuring the regular SSO flow"
        )

    state = wait_for(
        driver,
        lambda current: (
            "consent"
            if element_ready(current, "#accept")
            else "authentication"
            if element_ready(current, "#authentication-form button")
            else False
        ),
        timeout,
        "Neither IdP authentication nor consent became available",
    )
    if state == "authentication":
        email_input = driver.find_element(By.ID, "email")
        password_input = driver.find_element(By.ID, "password")
        email_input.clear()
        email_input.send_keys(email)
        password_input.send_keys(password)
        driver.find_element(
            By.CSS_SELECTOR, "#authentication-form button[type='submit']"
        ).click()

    wait_for(
        driver,
        lambda current: element_ready(current, "#accept"),
        timeout,
        "The IdP consent button did not become available",
    )


def wait_for_account_page(driver, timeout: float) -> dict[str, Any]:
    wait_for(
        driver,
        lambda current: urlparse(current.current_url).path == "/user"
        and bool(
            current.execute_script(
                "return document.documentElement.dataset.didssoClaimsDisplayedAtMs || '';"
            )
        ),
        timeout,
        "The authenticated RP page did not display the account claims",
    )
    values = driver.execute_script(
        """
        return {
            claimsDisplayedAtMs:
                document.documentElement.dataset.didssoClaimsDisplayedAtMs || "",
            navigationAtMs:
                document.documentElement.dataset.didssoNavigationAtMs || "",
            navigationSource:
                document.documentElement.dataset.didssoNavigationSource || "unknown"
        };
        """
    )
    session_id = parse_qs(urlparse(driver.current_url).query).get("session_id", [""])[0]
    if not session_id:
        raise EvaluationError("Authenticated RP page has no session_id")
    try:
        claims_displayed_at = float(values["claimsDisplayedAtMs"])
        navigation_at = float(values["navigationAtMs"])
    except (KeyError, TypeError, ValueError) as error:
        raise EvaluationError("RP page did not expose valid browser timestamps") from error
    return {
        "session_id": session_id,
        "claims_displayed_at_epoch_ms": claims_displayed_at,
        "navigation_at_epoch_ms": navigation_at,
        "navigation_source": str(values.get("navigationSource") or "unknown"),
    }


def component_events(base_url: str, session_id: str) -> dict[str, Any]:
    query = urlencode({"session_id": session_id})
    response = json_request(endpoint(base_url, f"/evaluation/measurements?{query}"))
    events = response.get("events", {})
    if not isinstance(events, dict):
        raise EvaluationError(f"Invalid evaluation events from {base_url}")
    return events


def event_timestamp(events: dict[str, Any], name: str) -> float | None:
    value = events.get(name, {}).get("timestamp_epoch_ms")
    return float(value) if isinstance(value, (int, float)) else None


def event_duration(events: dict[str, Any], name: str) -> float | None:
    value = events.get(name, {}).get("duration_seconds")
    return float(value) if isinstance(value, (int, float)) else None


def wait_for_wallet_events(
    base_url: str,
    session_id: str,
    timeout: float = 5,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    events: dict[str, Any] = {}
    while time.monotonic() < deadline:
        events = component_events(base_url, session_id)
        if "extension_result_detected" in events:
            return events
        time.sleep(0.05)
    raise EvaluationError(
        f"Firefox extension did not record the result for session {session_id}"
    )


def assemble_sso_result(
    *,
    run: int,
    started_at_ms: float,
    page: dict[str, Any],
    rp_events: dict[str, Any],
    idp_events: dict[str, Any],
    wallet_events: dict[str, Any],
    proof_backend: str,
) -> dict[str, Any]:
    logged_in = event_timestamp(rp_events, "rp_logged_in")
    wallet_validated = event_timestamp(wallet_events, "wallet_result_validated")
    extension_detected = event_timestamp(
        wallet_events, "extension_result_detected"
    )
    navigation_at = float(page["navigation_at_epoch_ms"])
    displayed_at = float(page["claims_displayed_at_epoch_ms"])
    proof_generation = event_duration(rp_events, "proof_generation")
    proof_verification = event_duration(idp_events, "proof_verification")
    token_issuance = event_duration(idp_events, "token_issuance")

    required = {
        "rp_logged_in": logged_in,
        "wallet_result_validated": wallet_validated,
        "extension_result_detected": extension_detected,
        "proof_generation": proof_generation,
        "proof_verification": proof_verification,
        "token_issuance": token_issuance,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise EvaluationError(
            f"Missing SSO measurements for {page['session_id']}: {', '.join(missing)}"
        )

    end_to_end = (displayed_at - started_at_ms) / 1000
    result_delivery = (navigation_at - logged_in) / 1000
    browser_processing = (displayed_at - navigation_at) / 1000
    unattributed = (
        end_to_end
        - float(proof_generation)
        - float(proof_verification)
        - float(token_issuance)
        - result_delivery
        - browser_processing
    )
    return {
        "scenario": "privacy_enhanced_sso",
        "run": run,
        "session_id": page["session_id"],
        "proof_backend": proof_backend,
        "navigation_source": page["navigation_source"],
        "token_mode": "initial_grant",
        "end_to_end_seconds": end_to_end,
        "proof_generation_seconds": proof_generation,
        "proof_verification_seconds": proof_verification,
        "token_issuance_seconds": token_issuance,
        "token_claims_round_trip_seconds": None,
        "result_delivery_seconds": result_delivery,
        "wallet_result_validation_latency_seconds": (wallet_validated - logged_in)
        / 1000,
        "extension_poll_delay_seconds": (extension_detected - wallet_validated)
        / 1000,
        "extension_detection_latency_seconds": (extension_detected - logged_in)
        / 1000,
        "browser_processing_seconds": browser_processing,
        "unattributed_seconds": unattributed,
        "started_at_epoch_ms": started_at_ms,
        "rp_logged_in_at_epoch_ms": logged_in,
        "wallet_result_validated_at_epoch_ms": wallet_validated,
        "extension_result_detected_at_epoch_ms": extension_detected,
        "navigation_at_epoch_ms": navigation_at,
        "claims_displayed_at_epoch_ms": displayed_at,
    }


def assemble_direct_result(
    *,
    scenario: str,
    expected_mode: str,
    run: int,
    started_at_ms: float,
    page: dict[str, Any],
    rp_events: dict[str, Any],
    proof_backend: str,
) -> dict[str, Any]:
    logged_in = event_timestamp(rp_events, "rp_logged_in")
    token_event = rp_events.get("token_claims_round_trip", {})
    token_round_trip = event_duration(rp_events, "token_claims_round_trip")
    token_mode = str(token_event.get("details", {}).get("mode", ""))
    if token_mode != expected_mode:
        raise EvaluationError(
            f"Expected token mode {expected_mode}, observed {token_mode or 'none'}"
        )
    if logged_in is None or token_round_trip is None:
        raise EvaluationError(
            f"Missing direct-login measurements for {page['session_id']}"
        )

    navigation_at = float(page["navigation_at_epoch_ms"])
    displayed_at = float(page["claims_displayed_at_epoch_ms"])
    return {
        "scenario": scenario,
        "run": run,
        "session_id": page["session_id"],
        "proof_backend": proof_backend,
        "navigation_source": page["navigation_source"],
        "token_mode": token_mode,
        "end_to_end_seconds": (displayed_at - started_at_ms) / 1000,
        "proof_generation_seconds": None,
        "proof_verification_seconds": None,
        "token_issuance_seconds": None,
        "token_claims_round_trip_seconds": token_round_trip,
        "result_delivery_seconds": (navigation_at - logged_in) / 1000,
        "wallet_result_validation_latency_seconds": None,
        "extension_poll_delay_seconds": None,
        "extension_detection_latency_seconds": None,
        "browser_processing_seconds": (displayed_at - navigation_at) / 1000,
        "unattributed_seconds": None,
        "started_at_epoch_ms": started_at_ms,
        "rp_logged_in_at_epoch_ms": logged_in,
        "wallet_result_validated_at_epoch_ms": None,
        "extension_result_detected_at_epoch_ms": None,
        "navigation_at_epoch_ms": navigation_at,
        "claims_displayed_at_epoch_ms": displayed_at,
    }


class ProtocolBenchmark:
    def __init__(
        self,
        arguments: argparse.Namespace,
        driver,
        proof_backend: str,
    ) -> None:
        self.arguments = arguments
        self.driver = driver
        self.proof_backend = proof_backend

    def run_sso(self, run: int) -> dict[str, Any]:
        from selenium.webdriver.common.by import By

        start_button = "#sso-start-button"
        self.driver.get(self.arguments.rp_url)
        wait_for(
            self.driver,
            lambda current: element_ready(current, start_button),
            self.arguments.timeout,
            "RP Privacy-Enhanced SSO button was not available",
        )
        self.driver.find_element(By.CSS_SELECTOR, start_button).click()
        wait_for_consent(
            self.driver,
            email=self.arguments.email,
            password=self.arguments.password,
            timeout=self.arguments.timeout,
        )
        time.sleep(0.2)
        started_at_ms = browser_click_timestamp(self.driver, "#accept")
        page = wait_for_account_page(self.driver, self.arguments.timeout)
        rp_events = component_events(self.arguments.rp_backend_url, page["session_id"])
        idp_events = component_events(self.arguments.idp_backend_url, page["session_id"])
        wallet_events = wait_for_wallet_events(
            self.arguments.wallet_backend_url, page["session_id"]
        )
        return assemble_sso_result(
            run=run,
            started_at_ms=started_at_ms,
            page=page,
            rp_events=rp_events,
            idp_events=idp_events,
            wallet_events=wallet_events,
            proof_backend=self.proof_backend,
        )

    def run_direct(
        self,
        *,
        run: int,
        scenario: str,
        expected_mode: str,
    ) -> dict[str, Any]:
        if expected_mode == "refresh":
            expired = json_request(
                endpoint(
                    self.arguments.rp_backend_url,
                    "/evaluation/expire-access-tokens",
                ),
                method="POST",
                payload={},
            )
            if int(expired.get("expired_grant_count", 0)) < 1:
                raise EvaluationError("No active Access Token was available to expire")

        self.driver.get(self.arguments.rp_url)
        wait_for(
            self.driver,
            lambda current: element_ready(current, "#did-login-button"),
            self.arguments.timeout,
            "RP DID Login button was not available",
        )
        started_at_ms = browser_click_timestamp(self.driver, "#did-login-button")
        page = wait_for_account_page(self.driver, self.arguments.timeout)
        rp_events = component_events(self.arguments.rp_backend_url, page["session_id"])
        return assemble_direct_result(
            scenario=scenario,
            expected_mode=expected_mode,
            run=run,
            started_at_ms=started_at_ms,
            page=page,
            rp_events=rp_events,
            proof_backend=self.proof_backend,
        )


def ensure_evaluation_endpoints(arguments: argparse.Namespace) -> None:
    for component, base_url in (
        ("RP", arguments.rp_backend_url),
        ("IdP", arguments.idp_backend_url),
        ("wallet", arguments.wallet_backend_url),
    ):
        try:
            response = json_request(
                endpoint(base_url, "/evaluation/measurements?session_id=preflight")
            )
        except EvaluationError as error:
            raise EvaluationError(
                f"{component} evaluation endpoint is unavailable. Start its backend "
                f"with .\\start.ps1 -Evaluation. Details: {error}"
            ) from error
        if response.get("enabled") is not True:
            raise EvaluationError(f"{component} evaluation mode is not enabled")


def required_proof_backend(arguments: argparse.Namespace) -> str:
    rp_configuration = json_request(
        endpoint(
            arguments.rp_backend_url,
            "/evaluation/measurements?session_id=preflight",
        )
    )
    idp_configuration = json_request(
        endpoint(
            arguments.idp_backend_url,
            "/evaluation/measurements?session_id=preflight",
        )
    )
    rp_backend = str(rp_configuration.get("proof_backend", "")).strip().lower()
    idp_backend = str(idp_configuration.get("proof_backend", "")).strip().lower()
    if not rp_backend or rp_backend != idp_backend:
        raise EvaluationError(
            "RP and IdP must run the same proof backend; "
            f"observed RP={rp_backend or 'unknown'}, IdP={idp_backend or 'unknown'}"
        )
    if rp_backend != "risc0":
        raise EvaluationError(
            "The quantitative evaluation requires the RISC Zero proof backend; "
            f"observed {rp_backend.upper()}"
        )

    try:
        accepted_count = int(
            rp_configuration.get("accepted_registration_count", 0)
        )
    except (TypeError, ValueError) as error:
        raise EvaluationError(
            "The RP returned an invalid accepted-registration count"
        ) from error
    if accepted_count < 1:
        raise EvaluationError(
            f"The RP has no accepted IdP credential for {rp_backend.upper()}"
        )
    return rp_backend


def usable_grant_count(arguments: argparse.Namespace) -> int:
    state = json_request(
        endpoint(arguments.rp_backend_url, "/evaluation/token-state")
    )
    return int(state.get("usable_grant_count", 0))


def require_single_usable_grant(arguments: argparse.Namespace) -> None:
    count = usable_grant_count(arguments)
    if count != 1:
        raise EvaluationError(
            "Direct-login measurements require exactly one usable RP token grant; "
            f"observed {count}. Reset the prototype state and complete one SSO flow."
        )


def access_tokens_valid_for(
    arguments: argparse.Namespace,
    minimum_remaining_seconds: float,
) -> bool:
    state = json_request(
        endpoint(arguments.rp_backend_url, "/evaluation/token-state")
    )
    grants = state.get("grants", [])
    if not isinstance(grants, list) or not grants:
        return False
    now = datetime.now(timezone.utc)
    for grant in grants:
        try:
            expiry = datetime.fromisoformat(str(grant["access_expires_at"]))
        except (KeyError, TypeError, ValueError):
            return False
        if expiry.tzinfo is None:
            return False
        if (expiry - now).total_seconds() <= minimum_remaining_seconds:
            return False
    return True


def print_run(result: dict[str, Any]) -> None:
    suffix = ""
    if result.get("token_mode"):
        suffix += f", token={result['token_mode']}"
    if result.get("navigation_source"):
        suffix += f", navigation={result['navigation_source']}"
    print(
        f"  Run {result['run']:>3}: {result['end_to_end_seconds']:.3f} s{suffix}",
        flush=True,
    )


def run_series(
    *,
    name: str,
    runs: int,
    warmup_runs: int,
    operation: Callable[[int], dict[str, Any]],
    report: dict[str, Any],
    writer: ReportWriter,
    preparation_already_performed: bool = False,
) -> None:
    print(f"\n{name}: {runs} measured runs", flush=True)
    warmups_remaining = max(0, warmup_runs - int(preparation_already_performed))
    for index in range(1, warmups_remaining + 1):
        print(f"  Warm-up {index}/{warmups_remaining} ...", flush=True)
        operation(0)
    for index in range(1, runs + 1):
        result = operation(index)
        report["results"].append(result)
        writer.save()
        print_run(result)


def resolve_scenarios(value: str) -> tuple[str, ...]:
    if value == "all":
        return ("sso", "direct-access", "direct-refresh")
    return (value,)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure the browser-observed DIDSSO protocol flows described in the "
            "thesis methodology."
        )
    )
    parser.add_argument(
        "--scenario",
        choices=("all", "sso", "direct-access", "direct-refresh"),
        default="all",
    )
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmup-runs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--rp-url", default="http://127.0.0.1:3002")
    parser.add_argument("--idp-url", default="https://127.0.0.1:3001")
    parser.add_argument("--rp-backend-url", default="http://127.0.0.1:8771")
    parser.add_argument("--idp-backend-url", default="http://127.0.0.1:8770")
    parser.add_argument("--wallet-backend-url", default="http://127.0.0.1:8765")
    parser.add_argument("--email", default=os.environ.get("DIDSSO_BENCH_EMAIL", ""))
    parser.add_argument(
        "--password", default=os.environ.get("DIDSSO_BENCH_PASSWORD", "")
    )
    parser.add_argument("--firefox-binary", type=Path)
    parser.add_argument("--geckodriver", type=Path)
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.runs < 1:
        parser.error("--runs must be at least 1")
    if arguments.warmup_runs < 0:
        parser.error("--warmup-runs must not be negative")
    if arguments.timeout <= 0:
        parser.error("--timeout must be positive")
    return arguments


def output_path(arguments: argparse.Namespace) -> Path:
    if arguments.output:
        return (
            arguments.output
            if arguments.output.is_absolute()
            else ROOT_DIR / arguments.output
        )
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return ROOT_DIR / "benchmark-results" / f"protocol-{timestamp}.json"


def main() -> int:
    arguments = parse_arguments()
    if not arguments.email:
        arguments.email = input("IdP benchmark account email: ").strip()
    if not arguments.password:
        arguments.password = getpass.getpass("IdP benchmark account password: ")
    if not arguments.email or not arguments.password:
        raise EvaluationError("IdP benchmark credentials are required")

    scenarios = resolve_scenarios(arguments.scenario)
    report: dict[str, Any] = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "status": "running",
        "platform": platform.platform(),
        "python": sys.version,
        "requested_runs_per_scenario": arguments.runs,
        "unmeasured_warmup_runs_per_scenario": arguments.warmup_runs,
        "headless": arguments.headless,
        "scenarios": list(scenarios),
        "clock_method": {
            "browser_boundaries": "performance.timeOrigin + performance.now()",
            "component_durations": "time.perf_counter_ns()",
            "cross_process_events": "time.time_ns() / browser epoch milliseconds",
        },
        "standard_deviation": "sample standard deviation",
        "unmeasured_maintenance_refreshes": 0,
        "results": [],
        "summaries": {},
        "errors": [],
    }
    writer = ReportWriter(output_path(arguments), report)
    writer.save()

    driver = None
    exit_code = 0
    try:
        ensure_evaluation_endpoints(arguments)
        proof_backend = required_proof_backend(arguments)
        report["proof_backend"] = proof_backend
        for base_url in (
            arguments.rp_backend_url,
            arguments.idp_backend_url,
            arguments.wallet_backend_url,
        ):
            json_request(
                endpoint(base_url, "/evaluation/measurements/clear"),
                method="POST",
                payload={},
            )

        with tempfile.TemporaryDirectory(prefix="didsso-evaluation-addon-") as temp:
            addon_path = Path(temp) / "didsso-evaluation.xpi"
            build_extension_archive(addon_path)
            driver, capabilities = create_driver(arguments, addon_path)
            report["browser"] = {
                "browser_name": capabilities.get("browserName"),
                "browser_version": capabilities.get("browserVersion"),
                "platform_name": capabilities.get("platformName"),
                "geckodriver_version": capabilities.get("moz:geckodriverVersion"),
                "selenium_version": capabilities.get("seleniumVersion"),
            }
            writer.save()

            authenticate_idp(
                driver,
                idp_url=arguments.idp_url,
                email=arguments.email,
                password=arguments.password,
                timeout=arguments.timeout,
            )
            benchmark = ProtocolBenchmark(arguments, driver, proof_backend)

            preparation_sso = False
            initial_grant_count = usable_grant_count(arguments)
            if (
                {"direct-access", "direct-refresh"}.intersection(scenarios)
                and initial_grant_count > 1
            ):
                require_single_usable_grant(arguments)
            if initial_grant_count == 0:
                print(
                    "\nPreparing the persistent RP account and token grant "
                    "(not measured) ...",
                    flush=True,
                )
                benchmark.run_sso(0)
                preparation_sso = True

            if "sso" in scenarios:
                run_series(
                    name="Privacy-enhanced SSO",
                    runs=arguments.runs,
                    warmup_runs=arguments.warmup_runs,
                    operation=benchmark.run_sso,
                    report=report,
                    writer=writer,
                    preparation_already_performed=preparation_sso,
                )

            if "direct-access" in scenarios:
                require_single_usable_grant(arguments)

                def measured_access_login(run: int) -> dict[str, Any]:
                    if not access_tokens_valid_for(arguments, 60):
                        print(
                            "  Renewing the Access Token outside the measurement ...",
                            flush=True,
                        )
                        benchmark.run_direct(
                            run=0,
                            scenario="unmeasured_access_renewal",
                            expected_mode="refresh",
                        )
                        report["unmeasured_maintenance_refreshes"] += 1
                    return benchmark.run_direct(
                        run=run,
                        scenario="direct_login_access_token",
                        expected_mode="access",
                    )

                run_series(
                    name="Direct DID login with valid Access Token",
                    runs=arguments.runs,
                    warmup_runs=arguments.warmup_runs,
                    operation=measured_access_login,
                    report=report,
                    writer=writer,
                )

            if "direct-refresh" in scenarios:
                require_single_usable_grant(arguments)
                run_series(
                    name="Direct DID login with Refresh Token",
                    runs=arguments.runs,
                    warmup_runs=arguments.warmup_runs,
                    operation=lambda run: benchmark.run_direct(
                        run=run,
                        scenario="direct_login_refresh_token",
                        expected_mode="refresh",
                    ),
                    report=report,
                    writer=writer,
                )
    except KeyboardInterrupt:
        report["errors"].append({"type": "KeyboardInterrupt", "message": "Cancelled"})
        report["status"] = "cancelled"
        exit_code = 130
    except Exception as error:
        report["errors"].append(
            {"type": type(error).__name__, "message": str(error)}
        )
        report["status"] = "failed"
        print(f"\nFAILED: {type(error).__name__}: {error}", file=sys.stderr)
        exit_code = 1
    else:
        report["status"] = "completed"
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception as error:
                report["errors"].append(
                    {
                        "type": type(error).__name__,
                        "message": f"Firefox teardown failed: {error}",
                    }
                )
                if report["status"] == "completed":
                    report["status"] = "completed_with_teardown_error"
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        writer.save()
        print(f"\nJSON report:    {writer.output_path}")
        print(f"Raw CSV:        {writer.raw_csv_path}")
        print(f"Summary CSV:    {writer.summary_csv_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
