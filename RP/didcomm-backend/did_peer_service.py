from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from did_peer_4 import encode, resolve_short
from did_peer_4.input_doc import Multikey, input_doc_from_keys_and_services


DATA_DIR = Path(
    os.environ.get("DIDSSO_DATA_DIR", Path(__file__).resolve().parent.parent)
).resolve()
WALLET_FILE = DATA_DIR / "wallet.json"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DIDCOMM_SERVICE_ENDPOINT = os.environ.get(
    "DIDSSO_DIDCOMM_ENDPOINT", "http://127.0.0.1:8771/didcomm/inbox"
)


def base58btc_encode(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""

    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    return "z" + ("1" * leading_zeroes) + (encoded or "1")


def base58btc_decode(value: str) -> bytes:
    if not value.startswith("z"):
        raise ValueError("Expected base58btc value with z prefix")

    raw = value[1:]
    number = 0

    for character in raw:
        number = number * 58 + BASE58_ALPHABET.index(character)

    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(raw) - len(raw.lstrip("1"))
    return (b"\0" * leading_zeroes) + decoded


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


def decode_multikey_public_key(multikey: str, expected_prefix: bytes) -> bytes:
    decoded = base58btc_decode(multikey)

    if not decoded.startswith(expected_prefix):
        raise ValueError("Unexpected multikey prefix")

    return decoded[len(expected_prefix) :]


def load_wallet() -> dict:
    if not WALLET_FILE.exists():
        return {"dids": []}

    wallet_text = WALLET_FILE.read_text(encoding="utf-8-sig").strip()
    if not wallet_text:
        return {"dids": []}

    return json.loads(wallet_text)


def save_wallet(wallet: dict) -> None:
    WALLET_FILE.parent.mkdir(parents=True, exist_ok=True)
    WALLET_FILE.write_text(json.dumps(wallet, indent=2), encoding="utf-8")


def didcomm_service_endpoint(record: dict) -> str:
    service_endpoint = record["inputDocument"]["service"][0]["serviceEndpoint"]
    if isinstance(service_endpoint, dict):
        return str(service_endpoint.get("uri", ""))
    return str(service_endpoint)


def public_record(record: dict) -> dict:
    public = {
        "name": record["name"],
        "did": record["did"],
        "shortDid": record["shortDid"],
        "inputDocument": record["inputDocument"],
        "resolvedDocument": record["resolvedDocument"],
        "createdAt": record["createdAt"],
    }
    if record.get("idpBinding"):
        public["idpBinding"] = record["idpBinding"]
    return public


def list_public_records() -> list[dict]:
    return [public_record(record) for record in load_wallet()["dids"]]


def short_form_did(did: str) -> str:
    parts = did.split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else did


def create_did_peer_4_record(name: str) -> dict:
    agreement_key = x25519.X25519PrivateKey.generate()

    agreement_multikey = multikey_x25519(raw_public_key(agreement_key.public_key()))

    keys = [
        Multikey(
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


def create_and_store_did(name: str) -> dict:
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("A DID name is required")

    wallet = load_wallet()
    record = create_did_peer_4_record(clean_name)
    wallet["dids"].append(record)
    save_wallet(wallet)
    return public_record(record)


def ensure_idp_pairwise_did(idp_master_did: str) -> str:
    clean_idp_did = idp_master_did.strip()
    if not clean_idp_did:
        raise ValueError("An IdP master DID is required")

    wallet = load_wallet()
    for record in wallet["dids"]:
        binding = record.get("idpBinding", {})
        if (
            binding.get("idpMasterDid") == clean_idp_did
            and didcomm_service_endpoint(record) == DIDCOMM_SERVICE_ENDPOINT
        ):
            return record["did"]

    pairwise_count = sum(1 for record in wallet["dids"] if record.get("idpBinding"))
    record = create_did_peer_4_record(f"rp-pairwise-idp-{pairwise_count + 1}")
    record["idpBinding"] = {
        "idpMasterDid": clean_idp_did,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    wallet["dids"].append(record)
    save_wallet(wallet)
    return record["did"]


def find_record(did: str) -> dict:
    for record in load_wallet()["dids"]:
        if record["did"] == did or record["shortDid"] == did:
            return record

    raise ValueError("Unknown DID")
