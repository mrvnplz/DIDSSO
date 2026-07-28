from __future__ import annotations

import base58
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from did_peer_4 import encode, resolve_short
from did_peer_4.input_doc import KeySpec, input_doc_from_keys_and_services
from json_storage import load_json, save_json


WALLET_FILE = Path(__file__).resolve().parent.parent / "data" / "wallet.json"
DIDCOMM_SERVICE_ENDPOINT = "http://127.0.0.1:8765/didcomm/inbox"


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


def multikey_ed25519(public_key: bytes) -> str:
    return base58btc_encode(b"\xed\x01" + public_key)


def multikey_x25519(public_key: bytes) -> str:
    return base58btc_encode(b"\xec\x01" + public_key)

# lädt daten aus wallet
def load_wallet() -> dict:
    return load_json(WALLET_FILE, {"dids": []})

# speichert die wallet einträge in json. Falls kein wallet file existiert wird eins erstellt
def save_wallet(wallet: dict) -> None:
    save_json(WALLET_FILE, wallet)

# erstellt öffentliche version des ausgewählten wallet eintrags
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

# returns all records form wallet as public records
def list_public_records() -> list[dict]:
    return [public_record(record) for record in load_wallet()["dids"]]

# extrahiert short form aus der long form
def short_form_did(did: str) -> str:
    return did[: did.rfind(":")]

# creates a peer did
def create_did_peer_4_record(name: str) -> dict:
    signing_key = ed25519.Ed25519PrivateKey.generate()
    agreement_key = x25519.X25519PrivateKey.generate()

    signing_multikey = multikey_ed25519(raw_public_key(signing_key.public_key()))
    agreement_multikey = multikey_x25519(raw_public_key(agreement_key.public_key()))

    keys = [
        KeySpec(
            multikey=signing_multikey,
            relationships=[
                "authentication",
                "assertionMethod",
                "capabilityInvocation",
                "capabilityDelegation",
            ],
        ),
        KeySpec(
            multikey=agreement_multikey,
            relationships=["keyAgreement"],
        ),
    ]
    service = {
        "id": "#didcomm-0",
        "type": "DIDCommMessaging",
        "serviceEndpoint": DIDCOMM_SERVICE_ENDPOINT,
        "accept": ["didcomm/v2"],
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
            "signingPublicMultikey": signing_multikey,
            "agreementPublicMultikey": agreement_multikey,
            "signingPrivateRawBase58btc": raw_private_key_base58btc(signing_key),
            "agreementPrivateRawBase58btc": raw_private_key_base58btc(agreement_key),
        },
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }

# erstellt DID mit entsprechendem namen, speichert in wallet und gibt public_record zurück
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
