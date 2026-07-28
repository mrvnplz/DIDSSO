from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from did_peer_4_service import find_record, public_record
from json_storage import load_json, save_json


BACKEND_DIR = Path(__file__).resolve().parent
DATA_STORAGE_DIR = BACKEND_DIR.parent / "data"
SELECTED_DID_FILE = DATA_STORAGE_DIR / "selected_did.json"
RP_BINDINGS_FILE = BACKEND_DIR / "rp_bindings.json"


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


def load_rp_bindings() -> dict:
    bindings = load_json(RP_BINDINGS_FILE, {"bindings": []})
    if isinstance(bindings, list):
        return {"bindings": bindings}

    bindings.setdefault("bindings", [])
    return bindings


def save_rp_bindings(bindings: dict) -> None:
    save_json(RP_BINDINGS_FILE, bindings)


def same_binding_value(left: str, right: str) -> bool:
    return bool(left and right and left == right)


def bind_pairwise_did_to_rp(
    pairwise_did: str,
    rp_master_did: str,
    rp_origin: str,
    source: str,
) -> dict:
    record = public_record(find_record(pairwise_did))
    bindings = load_rp_bindings()

    for binding in bindings["bindings"]:
        same_pairwise_did = binding.get("pairwiseDid") == record["did"]
        same_rp = (
            same_binding_value(binding.get("rpMasterDid", ""), rp_master_did)
            or same_binding_value(binding.get("rpOrigin", ""), rp_origin)
        )

        if same_pairwise_did and not same_rp:
            raise ValueError("This pairwise DID is already bound to another RP")
        if same_pairwise_did and same_rp:
            binding.update(
                {
                    "rpMasterDid": rp_master_did or binding.get("rpMasterDid", ""),
                    "rpOrigin": rp_origin or binding.get("rpOrigin", ""),
                    "pairwiseDid": record["did"],
                    "pairwiseShortDid": record["shortDid"],
                    "updatedAt": utc_now(),
                    "lastSource": source,
                }
            )
            save_rp_bindings(bindings)
            return binding

    binding = {
        "rpMasterDid": rp_master_did,
        "rpOrigin": rp_origin,
        "pairwiseDid": record["did"],
        "pairwiseShortDid": record["shortDid"],
        "createdAt": utc_now(),
        "updatedAt": utc_now(),
        "lastSource": source,
    }
    bindings["bindings"].append(binding)
    save_rp_bindings(bindings)
    return binding


def binding_for_rp(rp_master_did: str = "", rp_origin: str = "") -> dict | None:
    for binding in reversed(load_rp_bindings()["bindings"]):
        if same_binding_value(binding.get("rpMasterDid", ""), rp_master_did):
            return binding
        if same_binding_value(binding.get("rpOrigin", ""), rp_origin):
            return binding

    return None


def binding_for_pairwise_did(pairwise_did: str) -> dict | None:
    record = public_record(find_record(pairwise_did))
    for binding in load_rp_bindings()["bindings"]:
        if binding.get("pairwiseDid") == record["did"]:
            return binding

    return None


def select_bound_did_for_rp(rp_master_did: str = "", rp_origin: str = "") -> dict:
    binding = binding_for_rp(rp_master_did, rp_origin)
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
