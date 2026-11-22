use std::{fs, io, path::PathBuf};

use serde::{Deserialize, Serialize};

fn users_file() -> PathBuf {
    std::env::var_os("DIDSSO_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data"))
        .join("users.json")
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct User {
    pub(crate) subject: String,
    pub(crate) name: String,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) birthdate: String,
    pub(crate) password_hash: String,
}

#[derive(Debug)]
pub(crate) enum UpdateUserError {
    NotFound,
    Storage(io::Error),
}

pub(crate) fn find_user_by_email(email: &str) -> Option<User> {
    load_users().into_iter().find(|user| user.email == email)
}

pub(crate) fn find_user_by_subject(subject: &str) -> Option<User> {
    load_users()
        .into_iter()
        .find(|user| user.subject == subject)
}

pub(crate) fn update_username(subject: &str, username: &str) -> Result<(), UpdateUserError> {
    let mut users = load_users();
    if !update_username_in(&mut users, subject, username) {
        return Err(UpdateUserError::NotFound);
    }

    save_users(&users).map_err(UpdateUserError::Storage)
}

fn load_users() -> Vec<User> {
    let users_json = fs::read_to_string(users_file()).unwrap_or_else(|_| "[]".to_string());
    parse_users(&users_json)
}

pub(crate) fn save_user(user: &User) {
    let mut users = load_users();
    users.push(user.clone());
    save_users(&users).expect("Could not persist IdP users");
}

fn parse_users(users_json: &str) -> Vec<User> {
    let mut users: Vec<User> = serde_json::from_str(users_json).expect("Could not parse IdP users");
    users.retain(|user| !user.email.is_empty());
    for user in &mut users {
        if user.subject.is_empty() {
            user.subject = format!("user:{}", user.email);
        }
    }
    users
}

fn update_username_in(users: &mut [User], subject: &str, username: &str) -> bool {
    let Some(user) = users.iter_mut().find(|user| user.subject == subject) else {
        return false;
    };

    user.username = username.to_string();
    true
}

fn save_users(users: &[User]) -> io::Result<()> {
    let users_json = serde_json::to_string_pretty(users).map_err(io::Error::other)?;
    let path = users_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, users_json)
}
