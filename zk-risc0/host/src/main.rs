use std::env;
use std::io::{self, BufRead, BufWriter, Read, Write};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use credential_risc0_types::{GuestInput, PublicJournal, PROTOCOL_VERSION};
use methods::{METHOD_ELF, METHOD_ID};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Deserialize)]
struct ProveRequest {
    credential_secret: String,
    signature_r: String,
    signature_s: String,
    idp_public_key: String,
    context_digest: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    receipt_base64: String,
    expected_idp_public_key: String,
    expected_context_digest: String,
}

#[derive(Serialize)]
struct JournalJson {
    protocol_version: u32,
    idp_public_key: String,
    context_digest: String,
}

#[derive(Serialize)]
struct ProveResponse {
    receipt_base64: String,
    method_id: String,
    journal: JournalJson,
}

#[derive(Serialize)]
struct VerifyResponse {
    accepted: bool,
    method_id: String,
    journal: JournalJson,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    let command = env::args()
        .nth(1)
        .context("usage: host <prove|verify|verify-server|method-id>")?;
    match command.as_str() {
        "prove" => prove(),
        "verify" => verify(),
        "verify-server" => verify_server(),
        "method-id" => {
            println!("{}", method_id());
            Ok(())
        }
        _ => bail!(
            "unsupported command {command:?}; expected prove, verify, verify-server, or method-id"
        ),
    }
}

fn prove() -> Result<()> {
    let request: ProveRequest = read_stdin_json()?;
    let (idp_public_key_x, idp_public_key_y) =
        parse_public_key(&request.idp_public_key, "idp_public_key")?;
    let guest_input = GuestInput {
        credential_secret: parse_hex_32(&request.credential_secret, "credential_secret")?,
        signature_r: parse_hex_32(&request.signature_r, "signature_r")?,
        signature_s: parse_hex_32(&request.signature_s, "signature_s")?,
        idp_public_key_x,
        idp_public_key_y,
        context_digest: parse_hex_32(&request.context_digest, "context_digest")?,
    };

    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .context("failed to serialize private guest input")?
        .build()
        .context("failed to construct the zkVM executor environment")?;
    let receipt = default_prover()
        .prove(env, METHOD_ELF)
        .context("RISC Zero proving failed")?
        .receipt;

    // The RP only packages the receipt. The IdP is the single security-relevant verifier.
    let journal = decode_and_validate_journal(
        &receipt,
        &guest_input.idp_public_key_x,
        &guest_input.idp_public_key_y,
        &guest_input.context_digest,
    )?;
    let receipt_bytes = bincode::serialize(&receipt).context("failed to serialize receipt")?;
    write_stdout_json(&ProveResponse {
        receipt_base64: BASE64_STANDARD.encode(receipt_bytes),
        method_id: method_id(),
        journal: journal_json(&journal),
    })
}

fn verify() -> Result<()> {
    let request: VerifyRequest = read_stdin_json()?;
    write_stdout_json(&verify_request(request)?)
}

fn verify_request(request: VerifyRequest) -> Result<VerifyResponse> {
    let (expected_idp_public_key_x, expected_idp_public_key_y) =
        parse_public_key(&request.expected_idp_public_key, "expected_idp_public_key")?;
    let expected_context_digest =
        parse_hex_32(&request.expected_context_digest, "expected_context_digest")?;
    let receipt_bytes = BASE64_STANDARD
        .decode(request.receipt_base64.as_bytes())
        .context("receipt_base64 is not valid Base64")?;
    let receipt: Receipt =
        bincode::deserialize(&receipt_bytes).context("invalid RISC Zero receipt encoding")?;

    receipt
        .verify(METHOD_ID)
        .context("RISC Zero receipt verification failed")?;
    let journal = decode_and_validate_journal(
        &receipt,
        &expected_idp_public_key_x,
        &expected_idp_public_key_y,
        &expected_context_digest,
    )?;
    Ok(VerifyResponse {
        accepted: true,
        method_id: method_id(),
        journal: journal_json(&journal),
    })
}

fn verify_server() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = BufWriter::new(io::stdout().lock());

    serde_json::to_writer(&mut stdout, &serde_json::json!({ "ready": true }))
        .context("failed to serialize verifier ready message")?;
    writeln!(stdout)?;
    stdout.flush()?;

    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) if !line.trim().is_empty() => {
                match serde_json::from_str::<VerifyRequest>(&line)
                    .context("invalid persistent verify request")
                    .and_then(verify_request)
                {
                    Ok(result) => serde_json::json!({ "ok": true, "result": result }),
                    Err(error) => {
                        serde_json::json!({ "ok": false, "error": format!("{error:#}") })
                    }
                }
            }
            Ok(_) => continue,
            Err(error) => serde_json::json!({
                "ok": false,
                "error": format!("failed to read persistent verify request: {error}")
            }),
        };
        serde_json::to_writer(&mut stdout, &response)
            .context("failed to serialize persistent verify response")?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}

fn decode_and_validate_journal(
    receipt: &Receipt,
    expected_idp_public_key_x: &[u8; 32],
    expected_idp_public_key_y: &[u8; 32],
    expected_context_digest: &[u8; 32],
) -> Result<PublicJournal> {
    let journal: PublicJournal = receipt
        .journal
        .decode()
        .context("receipt journal has an unexpected format")?;
    ensure!(
        journal.protocol_version == PROTOCOL_VERSION,
        "unexpected credential proof protocol version"
    );
    ensure!(
        &journal.idp_public_key_x == expected_idp_public_key_x
            && &journal.idp_public_key_y == expected_idp_public_key_y,
        "receipt is bound to a different IdP public key"
    );
    ensure!(
        &journal.context_digest == expected_context_digest,
        "receipt is bound to a different request context"
    );
    Ok(journal)
}

fn journal_json(journal: &PublicJournal) -> JournalJson {
    JournalJson {
        protocol_version: journal.protocol_version,
        idp_public_key: format!(
            "{}{}",
            encode_hex(&journal.idp_public_key_x),
            encode_hex(&journal.idp_public_key_y)
        ),
        context_digest: encode_hex(&journal.context_digest),
    }
}

fn method_id() -> String {
    Digest::from(METHOD_ID).to_string()
}

fn read_stdin_json<T: DeserializeOwned>() -> Result<T> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read JSON from stdin")?;
    serde_json::from_str(&input).context("invalid JSON request")
}

fn write_stdout_json<T: Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(value).context("failed to serialize JSON response")?
    );
    Ok(())
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        value.len() == 64,
        "{label} must contain exactly 32 bytes as hexadecimal text"
    );
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).expect("hexadecimal text is ASCII");
        output[index] = u8::from_str_radix(pair, 16).context("invalid hexadecimal digit")?;
    }
    Ok(output)
}

fn parse_public_key(value: &str, label: &str) -> Result<([u8; 32], [u8; 32])> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        value.len() == 128,
        "{label} must contain exactly 64 bytes (x || y) as hexadecimal text"
    );
    Ok((
        parse_hex_32(&value[..64], &format!("{label}.x"))?,
        parse_hex_32(&value[64..], &format!("{label}.y"))?,
    ))
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
