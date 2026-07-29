from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

from did_peer_4_service import (
    create_did_peer_4_record,
    find_record,
    load_wallet,
    public_record,
    save_wallet,
)
from json_storage import load_json, save_json


BACKEND_DIR = Path(__file__).resolve().parent
DATA_STORAGE_DIR = BACKEND_DIR.parent / "data"
SELECTED_DID_FILE = DATA_STORAGE_DIR / "selected_did.json"
PREPARED_RP_ORIGINS: dict[str, str] = {}
PREPARED_RP_ORIGINS_LOCK = Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_data_storage() -> None:
    DATA_STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def selected_did_record() -> dict:
    selected = load_json(SELECTED_DID_FILE, {})
    did = selected.get("did", "")
    if not did:
        raise ValueError("No DID selected in the plugin")

    return public_record(find_record(did))


def store_selected_did(did: str) -> dict:
    if not did:
        save_json(SELECTED_DID_FILE, {})
        return {"status": "cleared"}

    record = public_record(find_record(did))
    save_json(
        SELECTED_DID_FILE,
        {
            "did": record["did"],
            "shortDid": record["shortDid"],
            "name": record["name"],
            "selectedAt": utc_now(),
        },
    )
    return {"status": "selected", "selectedDid": record}


def same_binding_value(left: str, right: str) -> bool:
    return bool(left and right and left == right)


def normalize_rp_origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("A valid HTTP RP origin is required")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("A valid HTTP RP origin is required") from error

    hostname = parsed.hostname.lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"

    port_part = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{hostname}{port_part}"


def public_rp_binding(record: dict) -> dict | None:
    binding = record.get("rpBinding")
    if not binding:
        return None

    return {
        **binding,
        "pairwiseDid": record["did"],
    }


def service_origin_for_record(record: dict) -> str:
    binding = record.get("rpBinding")
    if binding and binding.get("rpOrigin"):
        return str(binding["rpOrigin"])

    return str(
        record.get("serviceOrigin")
        or record.get("pendingRpOrigin")
        or ""
    )


def record_for_service(wallet: dict, service_origin: str) -> dict | None:
    bound_record = next(
        (
            record
            for record in reversed(wallet["dids"])
            if binding_matches_rp(record.get("rpBinding", {}), service_origin)
        ),
        None,
    )
    if bound_record is not None:
        return bound_record

    return next(
        (
            record
            for record in reversed(wallet["dids"])
            if service_origin_for_record(record) == service_origin
        ),
        None,
    )


def create_managed_did(service_origin: str) -> dict:
    record = create_did_peer_4_record(automatic_did_name(service_origin))
    record["managedByPlugin"] = True
    record["serviceOrigin"] = service_origin
    return record


def binding_matches_rp(binding: dict, rp_origin: str) -> bool:
    return same_binding_value(binding.get("rpOrigin", ""), rp_origin)


def ensure_pairwise_did_can_bind(
    pairwise_did: str,
    rp_origin: str,
) -> None:
    rp_origin = normalize_rp_origin(rp_origin)
    record = find_record(pairwise_did)
    binding = public_rp_binding(record)
    if binding and not binding_matches_rp(binding, rp_origin):
        raise ValueError("This pairwise DID is already bound to another RP")

    pending_rp_origin = record.get("pendingRpOrigin", "")
    if pending_rp_origin and pending_rp_origin != rp_origin:
        raise ValueError("This pairwise DID is already prepared for another RP")


def remember_prepared_did(pairwise_did: str, rp_origin: str) -> None:
    with PREPARED_RP_ORIGINS_LOCK:
        PREPARED_RP_ORIGINS[pairwise_did] = rp_origin


def validate_prepared_did(pairwise_did: str, rp_origin: str) -> None:
    with PREPARED_RP_ORIGINS_LOCK:
        prepared_rp_origin = PREPARED_RP_ORIGINS.get(pairwise_did, "")

    if prepared_rp_origin != rp_origin:
        raise ValueError(
            "SSO challenge does not match the RP origin observed by the plugin"
        )


def forget_prepared_did(pairwise_did: str) -> None:
    with PREPARED_RP_ORIGINS_LOCK:
        PREPARED_RP_ORIGINS.pop(pairwise_did, None)


def bind_pairwise_did_to_rp(
    pairwise_did: str,
    rp_master_did: str,
    rp_origin: str,
    source: str,
) -> dict:
    rp_origin = normalize_rp_origin(rp_origin)
    wallet = load_wallet()
    record = next(
        (
            record
            for record in wallet["dids"]
            if record["did"] == pairwise_did
        ),
        None,
    )
    if record is None:
        raise ValueError("Unknown DID")

    pending_rp_origin = record.get("pendingRpOrigin", "")
    if pending_rp_origin and pending_rp_origin != rp_origin:
        raise ValueError("This pairwise DID was prepared for another RP")

    binding = record.get("rpBinding")
    if binding:
        if not binding_matches_rp(binding, rp_origin):
            raise ValueError("This pairwise DID is already bound to another RP")

        binding.update(
            {
                "rpMasterDid": rp_master_did or binding.get("rpMasterDid", ""),
                "rpOrigin": rp_origin or binding.get("rpOrigin", ""),
                "updatedAt": utc_now(),
                "lastSource": source,
            }
        )
    else:
        now = utc_now()
        record["rpBinding"] = {
            "rpMasterDid": rp_master_did,
            "rpOrigin": rp_origin,
            "createdAt": now,
            "updatedAt": now,
            "lastSource": source,
        }

    if record.get("managedByPlugin"):
        record["serviceOrigin"] = rp_origin
    record.pop("pendingRpOrigin", None)
    save_wallet(wallet)
    return public_rp_binding(record)


def binding_for_pairwise_did(pairwise_did: str) -> dict | None:
    return public_rp_binding(find_record(pairwise_did))


def automatic_did_name(rp_origin: str) -> str:
    parsed = urlparse(rp_origin)
    return f"Pairwise {parsed.netloc}"


def select_did_for_service(service_origin: str) -> dict:
    service_origin = normalize_rp_origin(service_origin)
    selected = load_json(SELECTED_DID_FILE, {})
    selected_did = selected.get("did", "")
    wallet = load_wallet()
    if not selected_did:
        service_record = record_for_service(wallet, service_origin)
        status = "selected"
        if service_record is None:
            service_record = create_managed_did(service_origin)
            wallet["dids"].append(service_record)
            save_wallet(wallet)
            status = "created"

        selected = store_selected_did(service_record["did"])
        remember_prepared_did(service_record["did"], service_origin)
        return {
            "status": status,
            "serviceOrigin": service_origin,
            "selectedDid": selected["selectedDid"],
        }

    current_record = next(
        (
            record
            for record in wallet["dids"]
            if record["did"] == selected_did
            or record["shortDid"] == selected_did
        ),
        None,
    )
    if current_record is None:
        raise ValueError("Unknown selected DID")

    current_service_origin = service_origin_for_record(current_record)
    if not current_service_origin:
        return {
            "status": "unassigned-selection",
            "serviceOrigin": service_origin,
            "selectedDid": public_record(current_record),
        }
    if current_service_origin == service_origin:
        remember_prepared_did(current_record["did"], service_origin)
        return {
            "status": "selected",
            "serviceOrigin": service_origin,
            "selectedDid": public_record(current_record),
        }

    service_record = record_for_service(wallet, service_origin)
    status = "switched"
    if service_record is None:
        service_record = create_managed_did(service_origin)
        wallet["dids"].append(service_record)
        save_wallet(wallet)
        status = "created"

    selected = store_selected_did(service_record["did"])
    remember_prepared_did(service_record["did"], service_origin)
    return {
        "status": status,
        "serviceOrigin": service_origin,
        "selectedDid": selected["selectedDid"],
    }


def prepare_did_for_rp(
    rp_origin: str,
    automatic: bool,
    selected_did: str = "",
) -> dict:
    rp_origin = normalize_rp_origin(rp_origin)
    wallet = load_wallet()

    if automatic:
        record = record_for_service(wallet, rp_origin)
        status = "bound" if record and record.get("rpBinding") else "prepared"

        if record is None:
            record = create_managed_did(rp_origin)
            wallet["dids"].append(record)
            status = "created"

        wallet_changed = False
        if record.get("managedByPlugin") and not record.get("serviceOrigin"):
            record["serviceOrigin"] = rp_origin
            wallet_changed = True
        if not record.get("rpBinding") and record.get("pendingRpOrigin") != rp_origin:
            record["pendingRpOrigin"] = rp_origin
            wallet_changed = True
        if status == "created" or wallet_changed:
            save_wallet(wallet)
    else:
        if not selected_did:
            selected_did = selected_did_record()["did"]

        record = next(
            (
                record
                for record in wallet["dids"]
                if record["did"] == selected_did
                or record["shortDid"] == selected_did
            ),
            None,
        )
        if record is None:
            raise ValueError("Unknown DID")

        binding = public_rp_binding(record)
        if binding and not binding_matches_rp(binding, rp_origin):
            raise ValueError("The manually selected DID is bound to another RP")

        pending_rp_origin = record.get("pendingRpOrigin", "")
        if not binding and pending_rp_origin != rp_origin:
            record["pendingRpOrigin"] = rp_origin
            save_wallet(wallet)
        status = "manual"

    selected = store_selected_did(record["did"])
    remember_prepared_did(record["did"], rp_origin)
    return {
        "status": status,
        "mode": "automatic" if automatic else "manual",
        "rpOrigin": rp_origin,
        "selectedDid": selected["selectedDid"],
    }
