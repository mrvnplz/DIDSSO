from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from did_peer_4_service import (
    find_record,
    load_wallet,
    public_record,
    save_wallet,
)
from json_storage import load_json, save_json


BACKEND_DIR = Path(__file__).resolve().parent
DATA_STORAGE_DIR = BACKEND_DIR.parent / "data"
SELECTED_DID_FILE = DATA_STORAGE_DIR / "selected_did.json"


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


def public_rp_binding(record: dict) -> dict | None:
    binding = record.get("rpBinding")
    if not binding:
        return None

    return {
        **binding,
        "pairwiseDid": record["did"],
    }


def binding_matches_rp(binding: dict, rp_origin: str) -> bool:
    return same_binding_value(binding.get("rpOrigin", ""), rp_origin)


def ensure_pairwise_did_can_bind(
    pairwise_did: str,
    rp_origin: str,
) -> None:
    binding = public_rp_binding(find_record(pairwise_did))
    if binding and not binding_matches_rp(binding, rp_origin):
        raise ValueError("This pairwise DID is already bound to another RP")


def bind_pairwise_did_to_rp(
    pairwise_did: str,
    rp_master_did: str,
    rp_origin: str,
    source: str,
) -> dict:
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

    save_wallet(wallet)
    return public_rp_binding(record)


def binding_for_rp(rp_origin: str) -> dict | None:
    for record in reversed(load_wallet()["dids"]):
        binding = public_rp_binding(record)
        if binding and binding_matches_rp(binding, rp_origin):
            return binding

    return None


def binding_for_pairwise_did(pairwise_did: str) -> dict | None:
    return public_rp_binding(find_record(pairwise_did))


def select_bound_did_for_rp(rp_origin: str) -> dict:
    binding = binding_for_rp(rp_origin)
    if not binding:
        return {"status": "not-bound"}

    selected = load_json(SELECTED_DID_FILE, {})
    selected_did = selected.get("did", "")
    if selected_did:
        selected_binding = binding_for_pairwise_did(selected_did)
        if selected_binding is None and selected_did != binding["pairwiseDid"]:
            return {
                "status": "kept-unbound-selection",
                "binding": binding,
                "selectedDid": public_record(find_record(selected_did)),
            }

    selected = store_selected_did(binding["pairwiseDid"])
    return {
        "status": "selected",
        "binding": binding,
        "selectedDid": selected["selectedDid"],
    }
