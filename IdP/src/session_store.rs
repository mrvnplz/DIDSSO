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
        .unwrap_or_default()
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
    fs::write(sessions_file(), contents).expect("Could not persist IdP sessions");
}

#[cfg(test)]
mod tests {
    use super::{SessionRecord, active_user_subject, random_token, remove_session};

    #[test]
    fn session_tokens_are_random_256_bit_hex_values() {
        let first = random_token();
        let second = random_token();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn only_known_unexpired_tokens_resolve_to_a_user() {
        let token = "a".repeat(64);
        let sessions = [SessionRecord {
            token: token.clone(),
            user_subject: "user-test".to_string(),
            expires_at: 100,
        }];

        assert_eq!(
            active_user_subject(&sessions, &token, 99),
            Some("user-test".to_string())
        );
        assert_eq!(active_user_subject(&sessions, &token, 100), None);
        assert_eq!(active_user_subject(&sessions, &"b".repeat(64), 99), None);
        assert_eq!(active_user_subject(&sessions, "user@example.com", 99), None);
    }

    #[test]
    fn logout_removes_only_the_selected_active_session() {
        let first_token = "a".repeat(64);
        let second_token = "b".repeat(64);
        let mut sessions = vec![
            SessionRecord {
                token: first_token.clone(),
                user_subject: "user-one".to_string(),
                expires_at: 200,
            },
            SessionRecord {
                token: second_token.clone(),
                user_subject: "user-two".to_string(),
                expires_at: 200,
            },
        ];

        assert!(remove_session(&mut sessions, &first_token, 100));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].token, second_token);
        assert!(!remove_session(&mut sessions, &first_token, 100));
    }
}
