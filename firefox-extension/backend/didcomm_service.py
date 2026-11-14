from __future__ import annotations

import base64
import asyncio
from dataclasses import asdict
import json
import base58

from didcomm import (
    DIDCommService,
    DIDDoc,
    DIDResolverInMemory,
    Message,
    PackEncryptedConfig,
    ResolversConfig,
    Secret,
    SecretsResolverInMemory,
    VerificationMaterial,
    VerificationMaterialFormat,
    VerificationMethod,
    VerificationMethodType,
    pack_encrypted,
    unpack,
)

from did_peer_4 import resolve as resolve_peer_4

from did_peer_4_service import (
    find_record,
    load_wallet,
)


X25519_PUBLIC_PREFIX = b"\xec\x01"


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base58btc_decode(value: str) -> bytes:
    if not value.startswith("z"):
        raise ValueError("Expected a base58btc multibase value")

    return base58.b58decode(value[1:])


def decode_multikey_public_key(multikey: str, expected_prefix: bytes) -> bytes:
    decoded = base58btc_decode(multikey)
    if not decoded.startswith(expected_prefix):
        raise ValueError("Unexpected multikey type")

    return decoded[len(expected_prefix):]


def key_id(did: str, fragment: str) -> str:
    return f"{did}#{fragment}"

# Ensure a long-form DID is provided.
def require_long_form_did(did: str) -> str:
    peer_4_prefix = "did:peer:4"
    encoded_parts = did.removeprefix(peer_4_prefix).split(":", maxsplit=1)
    if not did.startswith(peer_4_prefix) or len(encoded_parts) != 2 or not all(encoded_parts):
        raise ValueError("DIDComm requires a long-form did:peer:4 DID")

    return did


# Convert a public Multikey to a JWK.
def public_jwk(public_multikey: str) -> dict:
    public_key = decode_multikey_public_key(public_multikey, X25519_PUBLIC_PREFIX)

    return {
        "kty": "OKP",
        "crv": "X25519",
        "x": base64url_encode(public_key),
    }


# Build a DIDComm DIDDoc with JWK keys from a resolved Peer DID Document.
def didcomm_did_doc(did: str, document: dict) -> DIDDoc:
    methods = {
        method["id"]: method
        for method in document.get("verificationMethod", [])
        if isinstance(method, dict)
    }

    def method_id(value: str | dict) -> str:
        return value["id"] if isinstance(value, dict) else value

    def full_kid(kid: str) -> str:
        return f"{did}{kid}" if kid.startswith("#") else kid

    agreement_ref = method_id(document["keyAgreement"][0])
    agreement_kid = full_kid(agreement_ref)
    agreement_method = methods.get(agreement_ref, document["keyAgreement"][0])

    return DIDDoc(
        id=did,
        verificationMethod=[
            VerificationMethod(
                id=agreement_kid,
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did,
                publicKeyJwk=public_jwk(agreement_method["publicKeyMultibase"]),
            ),
        ],
        keyAgreement=[agreement_kid],
        service=[
            DIDCommService(
                id=key_id(did, "didcomm-0"),
                type="DIDCommMessaging",
                serviceEndpoint="didcomm:transport/queue",
                recipientKeys=[agreement_kid],
                accept=["didcomm/v2"],
            )
        ],
    )


# Build a DIDComm secret in JWK format from a public and private key.
def jwk_secret(
    kid: str,
    public_multikey: str,
    private_raw_base58btc: str,
) -> Secret:
    jwk = public_jwk(public_multikey)
    private_key = base58btc_decode(private_raw_base58btc)
    jwk["kid"] = kid
    jwk["d"] = base64url_encode(private_key)

    return Secret(
        kid=kid,
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json.dumps(jwk),
        ),
    )


# Create the X25519 key-agreement secret for a wallet record.
def didcomm_secrets(record: dict, did: str) -> list[Secret]:
    keys = record["keys"]

    return [
        jwk_secret(
            key_id(did, "key-0"),
            keys["agreementPublicMultikey"],
            keys["agreementPrivateRawBase58btc"],
        ),
    ]
 
# Build DIDComm resolvers from the local wallet; extra_dids supplies external
# long-form DIDs whose public DID Documents are also resolved for communication.
def build_resolvers_config(extra_dids: list[str] | None = None) -> ResolversConfig:
    did_docs = []
    secrets = []

    for record in load_wallet()["dids"]:
        did = record["did"]
        did_docs.append(didcomm_did_doc(did, record["resolvedDocument"]))
        secrets.extend(didcomm_secrets(record, did))

    for did in extra_dids or []:
        require_long_form_did(did)
        if did and all(document.id != did for document in did_docs):
            did_docs.append(didcomm_did_doc(did, resolve_peer_4(did)))

    return ResolversConfig(
        secrets_resolver=SecretsResolverInMemory(secrets),
        did_resolver=DIDResolverInMemory(did_docs),
    )


# Pack and encrypt a DIDComm message between two long-form DIDs.
def pack_encrypted_message(
    sender_did: str,
    recipient_did: str,
    body: dict,
    message_type: str = "https://didcomm.org/basicmessage/2.0/message",
    message_id: str | None = None,
    thread_id: str | None = None,
) -> dict:
    require_long_form_did(sender_did)
    require_long_form_did(recipient_did)
    find_record(sender_did)
    resolvers_config = build_resolvers_config([recipient_did])
    message = Message(
        type=message_type,
        frm=sender_did,
        to=[recipient_did],
        body=body,
        id=message_id,
        thid=thread_id,
    )
    result = asyncio.run(
        pack_encrypted(
            resolvers_config=resolvers_config,
            message=message,
            frm=sender_did,
            to=recipient_did,
            pack_config=PackEncryptedConfig(forward=False),
        )
    )

    return {
        "packedMessage": result.packed_msg,
        "to": recipient_did,
        "from": sender_did,
        "encrypted": True,
    }


# Decrypt a DIDComm message and return its content and metadata.
def unpack_message(packed_message: dict | str, sender_did: str = "") -> dict:
    if sender_did:
        require_long_form_did(sender_did)

    resolvers_config = build_resolvers_config([sender_did] if sender_did else [])
    result = asyncio.run(
        unpack(
            resolvers_config=resolvers_config,
            packed_msg=packed_message,
        )
    )

    return {
        "message": result.message.as_dict() if hasattr(result.message, "as_dict") else result.message,
        "metadata": json.loads(json.dumps(asdict(result.metadata), default=str)),
    }


def message_thread_id(message: dict) -> str:
    message_id = str(message.get("id", "")).strip()
    thread_id = str(message.get("thid") or message_id).strip()
    if not message_id or not thread_id:
        raise ValueError("DIDComm message has no message or thread ID")
    return thread_id
