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


ED25519_PUBLIC_PREFIX = b"\xed\x01"
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

# stellt sicher, dass die long-form vorhanden ist
def require_long_form_did(did: str) -> str:
    peer_4_prefix = "did:peer:4"
    encoded_parts = did.removeprefix(peer_4_prefix).split(":", maxsplit=1)
    if not did.startswith(peer_4_prefix) or len(encoded_parts) != 2 or not all(encoded_parts):
        raise ValueError("DIDComm requires a long-form did:peer:4 DID")

    return did


# konvertiert public multikey zu JWK
def public_jwk(key_type: str, public_multikey: str) -> dict:
    if key_type == "Ed25519":
        public_key = decode_multikey_public_key(public_multikey, ED25519_PUBLIC_PREFIX)
    elif key_type == "X25519":
        public_key = decode_multikey_public_key(public_multikey, X25519_PUBLIC_PREFIX)
    else:
        raise ValueError(f"Unsupported DIDComm key type: {key_type}")

    return {
        "kty": "OKP",
        "crv": key_type,
        "x": base64url_encode(public_key),
    }


# Erstellt aus einem aufgeloesten Peer-DID-Dokument ein DIDComm-DIDDoc mit JWK-Schluesseln.
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

    signing_ref = method_id(document["authentication"][0])
    agreement_ref = method_id(document["keyAgreement"][0])
    signing_kid = full_kid(signing_ref)
    agreement_kid = full_kid(agreement_ref)
    signing_method = methods.get(signing_ref, document["authentication"][0])
    agreement_method = methods.get(agreement_ref, document["keyAgreement"][0])

    return DIDDoc(
        id=did,
        verificationMethod=[
            VerificationMethod(
                id=signing_kid,
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did,
                publicKeyJwk=public_jwk("Ed25519", signing_method["publicKeyMultibase"]),
            ),
            VerificationMethod(
                id=agreement_kid,
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller=did,
                publicKeyJwk=public_jwk("X25519", agreement_method["publicKeyMultibase"]),
            ),
        ],
        authentication=[signing_kid],
        assertionMethod=[signing_kid],
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


# Erstellt aus einem oeffentlichen und privaten Schluessel ein DIDComm-Secret im JWK-Format.
def jwk_secret(
    kid: str,
    key_type: str,
    public_multikey: str,
    private_raw_base58btc: str,
) -> Secret:
    jwk = public_jwk(key_type, public_multikey)
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


# Erstellt die Signatur- und Schluesselaustausch-Secrets eines Wallet-Eintrags fuer DIDComm.
def didcomm_secrets(record: dict, did: str) -> list[Secret]:
    keys = record["keys"]

    return [
        jwk_secret(
            key_id(did, "key-0"),
            "Ed25519",
            keys["signingPublicMultikey"],
            keys["signingPrivateRawBase58btc"],
        ),
        jwk_secret(
            key_id(did, "key-1"),
            "X25519",
            keys["agreementPublicMultikey"],
            keys["agreementPrivateRawBase58btc"],
        ),
    ]
 
# Erstellt die DIDComm-Resolver aus der lokalen Wallet; extra_dids sind externe Long-Form-DIDs,
# deren oeffentliche DID-Dokumente zusaetzlich fuer die Kommunikation aufgeloest werden.
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


# Erstellt und verschluesselt eine DIDComm-Nachricht zwischen zwei Long-Form-DIDs.
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


# Entschluesselt eine DIDComm-Nachricht und gibt ihren Inhalt sowie Metadaten zurueck.
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
