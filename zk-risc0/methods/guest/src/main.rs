use credential_risc0_types::{GuestInput, PublicJournal, PROTOCOL_VERSION};
use risc0_crypto::{
    BigInt,
    curves::secp256r1::{self, Affine, Fq, Fr},
    ecdsa::Signature,
};
use risc0_zkvm::guest::env;

fn main() {
    let input: GuestInput = env::read();

    let signature_r = Fr::from_bigint(BigInt::<8>::from_be_bytes(&input.signature_r))
        .expect("signature r is not a canonical P-256 scalar");
    let signature_s = Fr::from_bigint(BigInt::<8>::from_be_bytes(&input.signature_s))
        .expect("signature s is not a canonical P-256 scalar");
    let signature = Signature::<secp256r1::Config, 8>::new(signature_r, signature_s)
        .expect("P-256 signature components must be non-zero");

    let public_key_x = Fq::from_bigint(BigInt::<8>::from_be_bytes(&input.idp_public_key_x))
        .expect("public-key x-coordinate is not canonical");
    let public_key_y = Fq::from_bigint(BigInt::<8>::from_be_bytes(&input.idp_public_key_y))
        .expect("public-key y-coordinate is not canonical");
    let public_key = Affine::new_in_subgroup(public_key_x, public_key_y)
        .expect("IdP public key is not a valid P-256 point");

    assert!(
        signature.verify(&public_key, &input.credential_secret),
        "credential signature verification failed"
    );

    env::commit(&PublicJournal {
        protocol_version: PROTOCOL_VERSION,
        idp_public_key_x: input.idp_public_key_x,
        idp_public_key_y: input.idp_public_key_y,
        context_digest: input.context_digest,
    });
}
