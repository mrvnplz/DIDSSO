from __future__ import annotations

import base58
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from did_peer_4 import encode, resolve_short
from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services
from json_storage import load_json, save_json


DATA_DIR = Path(
    os.environ.get(
        "DIDSSO_DATA_DIR", Path(__file__).resolve().parent.parent / "data"
    )
).resolve()
WALLET_FILE = DATA_DIR / "wallet.json"
DIDCOMM_SERVICE_ENDPOINT = os.environ.get(
    "DIDSSO_DIDCOMM_ENDPOINT", "http://127.0.0.1:8765/didcomm/inbox"
)


def base58btc_encode(data: bytes) -> str:
    return "z" + base58.b58encode(data).decode("ascii")


def raw_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def raw_private_key_base58btc(private_key) -> str:
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base58btc_encode(private_bytes)


def multikey_x25519(public_key: bytes) -> str:
    return base58btc_encode(b"\xec\x01" + public_key)

# Load wallet data.
def load_wallet() -> dict:
    return load_json(WALLET_FILE, {"dids": []})

# Save wallet entries as JSON, creating the file if it does not exist.
def save_wallet(wallet: dict) -> None:
    save_json(WALLET_FILE, wallet)

# Create a public version of the selected wallet record.
def public_record(record: dict) -> dict:
    public = {
        "name": record["name"],
        "did": record["did"],
        "shortDid": record["shortDid"],
        "inputDocument": record["inputDocument"],
        "resolvedDocument": record["resolvedDocument"],
        "createdAt": record["createdAt"],
    }
    if record.get("rpBinding"):
        public["rpBinding"] = dict(record["rpBinding"])

    return public

# Return all wallet records as public records.
def list_public_records() -> list[dict]:
    return [public_record(record) for record in load_wallet()["dids"]]

# Extract the short-form DID from the long-form DID.
def short_form_did(did: str) -> str:
    return did[: did.rfind(":")]

# Create a Peer DID.
def create_did_peer_4_record(name: str) -> dict:
    agreement_key = x25519.X25519PrivateKey.generate()

    agreement_multikey = multikey_x25519(raw_public_key(agreement_key.public_key()))

    keys = [
        KeySpec(
            multikey=agreement_multikey,
            relationships=["keyAgreement"],
        ),
    ]
    service = {
        "id": "#didcomm-0",
        "type": "DIDCommMessaging",
        "serviceEndpoint": {
            "uri": DIDCOMM_SERVICE_ENDPOINT,
            "accept": ["didcomm/v2"],
        },
    }

    input_document = input_doc_from_keys_and_services(keys, [service])
    did = encode(input_document)

    return {
        "name": name,
        "did": did,
        "shortDid": short_form_did(did),
        "inputDocument": input_document,
        "resolvedDocument": resolve_short(did),
        "keys": {
            "agreementPublicMultikey": agreement_multikey,
            "agreementPrivateRawBase58btc": raw_private_key_base58btc(agreement_key),
        },
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }

# Create a named DID, store it in the wallet, and return its public record.
def create_and_store_did(name: str) -> dict:
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("A DID name is required")

    wallet = load_wallet()
    record = create_did_peer_4_record(clean_name)
    wallet["dids"].append(record)
    save_wallet(wallet)
    return public_record(record) 


def find_record(did: str) -> dict:
    for record in load_wallet()["dids"]:
        if record["did"] == did or record["shortDid"] == did:
            return record

    raise ValueError("Unknown DID")
