import json

import pytest

import backend.did_peer_4_service as service


def test_base58btc_encode_adds_multibase_prefix():
    # Verifies that raw bytes are encoded as base58btc with the required "z" prefix.
    encoded = service.base58btc_encode(b"hello")

    assert encoded.startswith("z")
    assert encoded == "zCn8eVZg"


def test_multikey_helpers_add_expected_prefixes():
    # Verifies that Ed25519 and X25519 public keys get the correct multicodec prefixes.
    public_key = bytes(range(32))

    signing_multikey = service.multikey_ed25519(public_key)
    agreement_multikey = service.multikey_x25519(public_key)

    assert service.base58.b58decode(signing_multikey[1:]).startswith(b"\xed\x01")
    assert service.base58.b58decode(agreement_multikey[1:]).startswith(b"\xec\x01")


def test_create_did_peer_4_record_contains_didcomm_keys_and_service():
    # Verifies that a generated DID record contains DIDComm-compatible keys and service data.
    record = service.create_did_peer_4_record("Alice")

    assert record["name"] == "Alice"
    assert record["did"].startswith("did:peer:4")
    assert record["shortDid"].startswith("did:peer:4")
    assert ":" not in record["shortDid"][10:]
    assert record["keys"]["signingPublicMultikey"].startswith("z")
    assert record["keys"]["agreementPublicMultikey"].startswith("z")

    input_document = record["inputDocument"]
    assert input_document["authentication"] == ["#key-0"]
    assert input_document["keyAgreement"] == ["#key-1"]
    assert input_document["service"][0]["type"] == "DIDCommMessaging"
    assert input_document["service"][0]["accept"] == ["didcomm/v2"]


def test_create_and_store_did_writes_public_record(tmp_path, monkeypatch):
    # Verifies that storing a DID writes the full wallet entry while returning only public data.
    wallet_file = tmp_path / "wallet.json"
    monkeypatch.setattr(service, "WALLET_FILE", wallet_file)

    public_record = service.create_and_store_did(" Alice ")

    assert public_record["name"] == "Alice"
    assert "keys" not in public_record

    stored_wallet = json.loads(wallet_file.read_text(encoding="utf-8"))
    assert len(stored_wallet["dids"]) == 1
    assert stored_wallet["dids"][0]["keys"]["agreementPrivateRawBase58btc"].startswith("z")


def test_find_record_accepts_long_and_short_did(tmp_path, monkeypatch):
    # Verifies that wallet lookup works with both the long and short DID forms.
    wallet_file = tmp_path / "wallet.json"
    monkeypatch.setattr(service, "WALLET_FILE", wallet_file)

    service.create_and_store_did("Alice")
    record = service.load_wallet()["dids"][0]

    assert service.find_record(record["did"]) == record
    assert service.find_record(record["shortDid"]) == record


def test_create_and_store_did_rejects_empty_name():
    # Verifies that blank DID names are rejected before writing to the wallet.
    with pytest.raises(ValueError, match="DID name is required"):
        service.create_and_store_did("   ")
