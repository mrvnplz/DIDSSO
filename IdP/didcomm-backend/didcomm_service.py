from __future__ import annotations

import base64
import asyncio
from dataclasses import asdict
import json
from typing import Any

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

from did_peer_service import (
    base58btc_decode,
    decode_multikey_public_key,
    find_record,
    load_wallet,
)


X25519_PUBLIC_PREFIX = b"\xec\x01"


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def did_aliases(record: dict) -> list[str]:
    aliases = [record["did"], record["shortDid"]]
    resolved_id = record.get("resolvedDocument", {}).get("id")

    if resolved_id:
        aliases.append(resolved_id)

    return list(dict.fromkeys(aliases))


def key_id(did: str, fragment: str) -> str:
    return f"{did}#{fragment}"


def public_jwk(public_multikey: str) -> dict:
    public_key = decode_multikey_public_key(public_multikey, X25519_PUBLIC_PREFIX)

    return {
        "kty": "OKP",
        "crv": "X25519",
        "x": base64url_encode(public_key),
    }


def didcomm_did_doc_from_multikeys(
    did: str,
    agreement_multikey: str,
    agreement_kid: str | None = None,
) -> DIDDoc:
    agreement_kid = agreement_kid or key_id(did, "key-0")

    return DIDDoc(
        id=did,
        verificationMethod=[
            VerificationMethod(
                id=agreement_kid,
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did,
                publicKeyJwk=public_jwk(agreement_multikey),
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


def didcomm_did_doc(record: dict, did: str) -> DIDDoc:
    return didcomm_did_doc_from_multikeys(
        did,
        record["keys"]["agreementPublicMultikey"],
    )


def didcomm_did_doc_from_resolved_document(did: str, document: dict) -> DIDDoc:
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
    agreement_method = methods.get(agreement_ref, document["keyAgreement"][0])

    return didcomm_did_doc_from_multikeys(
        did,
        agreement_method["publicKeyMultibase"],
        full_kid(agreement_ref),
    )


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


def didcomm_secrets(record: dict, did: str) -> list[Secret]:
    keys = record["keys"]

    return [
        jwk_secret(
            key_id(did, "key-0"),
            keys["agreementPublicMultikey"],
            keys["agreementPrivateRawBase58btc"],
        ),
    ]


def build_resolvers_config(extra_dids: list[str] | None = None) -> ResolversConfig:
    did_docs = []
    secrets = []

    for record in load_wallet()["dids"]:
        for did in did_aliases(record):
            did_docs.append(didcomm_did_doc(record, did))
            secrets.extend(didcomm_secrets(record, did))

    for did in extra_dids or []:
        if did and all(document.id != did for document in did_docs):
            did_docs.append(didcomm_did_doc_from_resolved_document(did, resolve_peer_4(did)))

    return ResolversConfig(
        secrets_resolver=SecretsResolverInMemory(secrets),
        did_resolver=DIDResolverInMemory(did_docs),
    )


def json_ready(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def pack_encrypted_message(
    sender_did: str,
    recipient_did: str,
    body: dict,
    message_type: str,
    message_id: str | None = None,
    thread_id: str | None = None,
) -> dict | str:
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

    return result.packed_msg


def unpack_message(packed_message: dict | str, sender_did: str = "") -> dict:
    resolvers_config = build_resolvers_config([sender_did] if sender_did else [])
    result = asyncio.run(
        unpack(
            resolvers_config=resolvers_config,
            packed_msg=packed_message,
        )
    )

    return {
        "message": result.message.as_dict() if hasattr(result.message, "as_dict") else result.message,
        "metadata": json_ready(asdict(result.metadata)),
    }


def message_thread_id(message: dict) -> str:
    message_id = str(message.get("id", "")).strip()
    thread_id = str(message.get("thid") or message_id).strip()
    if not message_id or not thread_id:
        raise ValueError("DIDComm message has no message or thread ID")
    return thread_id
