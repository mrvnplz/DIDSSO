use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 2;

/// All fields are private zkVM inputs. The verifier only sees the journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuestInput {
    pub credential_secret: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
    pub idp_public_key_x: [u8; 32],
    pub idp_public_key_y: [u8; 32],
    pub context_digest: [u8; 32],
}

/// The complete public statement proven by the receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicJournal {
    pub protocol_version: u32,
    pub idp_public_key_x: [u8; 32],
    pub idp_public_key_y: [u8; 32],
    pub context_digest: [u8; 32],
}
