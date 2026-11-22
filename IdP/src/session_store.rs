use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

pub(crate) const SESSION_TTL_SECONDS: u64 = 60 * 60;

fn sessions_file() -> PathBuf {
    std::env::var_os("DIDSSO_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"))
        .join("sessions.json")
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionRecord {
    token: String,
    user_subject: String,
    expires_at: u64,
}

pub(crate) fn create_session(user_subject: &str) -> String {
    let now = unix_timestamp();
    let mut sessions: Vec<SessionRecord> = load_sessions()
        .into_iter()
        .filter(|session| session.expires_at > now)
        .collect();

    let token = loop {
        let candidate = random_token();
        if sessions.iter().all(|session| session.token != candidate) {
            break candidate;
        }
    };
    sessions.push(SessionRecord {
        token: token.clone(),
        user_subject: user_subject.to_string(),
        expires_at: now + SESSION_TTL_SECONDS,
    });
    save_sessions(&sessions);
    token
}

pub(crate) fn user_subject_for_session(token: &str) -> Option<String> {
    active_user_subject(&load_sessions(), token, unix_timestamp())
}

pub(crate) fn revoke_session(token: &str) -> bool {
    let now = unix_timestamp();
    let mut sessions = load_sessions();
    let revoked = remove_session(&mut sessions, token, now);
    save_sessions(&sessions);
    revoked
}

fn remove_session(sessions: &mut Vec<SessionRecord>, token: &str, now: u64) -> bool {
    let session_count = sessions.len();
    let token_was_active = sessions
        .iter()
        .any(|session| session.token == token && session.expires_at > now);
    sessions.retain(|session| session.expires_at > now && session.token != token);
    token_was_active && sessions.len() < session_count
}

fn active_user_subject(sessions: &[SessionRecord], token: &str, now: u64) -> Option<String> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    sessions
        .iter()
        .find(|session| session.token == token && session.expires_at > now)
        .map(|session| session.user_subject.clone())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_sessions() -> Vec<SessionRecord> {
    let contents = fs::read_to_string(sessions_file()).unwrap_or_else(|_| "[]".to_string());
    serde_json::from_str(&contents).expect("Could not parse IdP sessions")
}

fn save_sessions(sessions: &[SessionRecord]) {
    let contents =
        serde_json::to_string_pretty(sessions).expect("Could not serialize IdP sessions");
    let path = sessions_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("Could not create IdP data directory");
    }
    fs::write(path, contents).expect("Could not persist IdP sessions");
}
