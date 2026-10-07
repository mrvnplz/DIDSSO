use std::{
    collections::HashMap,
    fs,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;

use crate::{
    http_protocol::{
        HttpRequest, send_logout_redirect, send_redirect, send_redirect_with_session, send_response,
    },
    session_store::{create_session, revoke_session, user_subject_for_session},
    user_store::{
        UpdateUserError, User, find_user_by_email, find_user_by_subject, save_user, update_username,
    },
};

pub(crate) fn handle_register<T: Write>(stream: &mut T, request: &HttpRequest) {
    let form = parse_form_body(&request.body);
    let password = form.get("password").cloned().unwrap_or_default();

    let username = form.get("username").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    let email = form.get("email").cloned().unwrap_or_default();
    let birthdate = form.get("birthdate").cloned().unwrap_or_default();

    if name.is_empty()
        || username.is_empty()
        || email.is_empty()
        || birthdate.is_empty()
        || password.is_empty()
    {
        send_response(
            stream,
            "HTTP/1.1 400 BAD REQUEST",
            "text/plain",
            "Full name, preferred username, email, birthdate and password are required.",
        );
        return;
    }

    let password_hash = match hash_password(&password) {
        Some(password_hash) => password_hash,
        None => {
            send_response(
                stream,
                "HTTP/1.1 500 INTERNAL SERVER ERROR",
                "text/plain",
                "Could not hash password.",
            );
            return;
        }
    };

    let user = User {
        subject: create_user_subject(),
        name,
        username,
        email,
        birthdate,
        password_hash,
    };

    println!("Registered IdP user: {}", user.email);
    save_user(&user);

    let session_id = create_session(&user.subject);
    send_redirect_with_session(stream, "/user", &session_id);
}

pub(crate) fn handle_login<T: Write>(stream: &mut T, request: &HttpRequest) {
    let form = parse_form_body(&request.body);
    let email = form.get("email").cloned().unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();

    if email.is_empty() || password.is_empty() {
        send_response(
            stream,
            "HTTP/1.1 400 BAD REQUEST",
            "text/plain",
            "Email and password are required.",
        );
        return;
    }

    let user = match find_user_by_email(&email) {
        Some(user) => user,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "Invalid email or password.",
            );
            return;
        }
    };

    if !verify_password(&password, &user.password_hash) {
        send_response(
            stream,
            "HTTP/1.1 401 UNAUTHORIZED",
            "text/plain",
            "Invalid email or password.",
        );
        return;
    }

    let session_id = create_session(&user.subject);
    send_redirect_with_session(stream, "/user", &session_id);
}

pub(crate) fn handle_logout<T: Write>(stream: &mut T, request: &HttpRequest) {
    if let Some(session_id) = session_cookie(request) {
        revoke_session(&session_id);
    }
    send_logout_redirect(stream);
}

pub(crate) fn handle_update_user<T: Write>(stream: &mut T, request: &HttpRequest) {
    let session_id = match session_cookie(request) {
        Some(session_id) => session_id,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "No active session.",
            );
            return;
        }
    };
    let user_subject = match user_subject_for_session(&session_id) {
        Some(user_subject) => user_subject,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "Invalid or expired session.",
            );
            return;
        }
    };
    let form = parse_form_body(&request.body);
    let username = form
        .get("username")
        .map(|value| value.trim())
        .unwrap_or_default();
    if username.is_empty() {
        send_response(
            stream,
            "HTTP/1.1 400 BAD REQUEST",
            "text/plain",
            "Preferred username is required.",
        );
        return;
    }

    match update_username(&user_subject, username) {
        Ok(()) => send_redirect(stream, "/user"),
        Err(UpdateUserError::NotFound) => send_response(
            stream,
            "HTTP/1.1 404 NOT FOUND",
            "text/plain",
            "Session user was not found.",
        ),
        Err(UpdateUserError::Storage(error)) => {
            eprintln!("Could not update IdP user: {error}");
            send_response(
                stream,
                "HTTP/1.1 500 INTERNAL SERVER ERROR",
                "text/plain",
                "Could not update user profile.",
            );
        }
    }
}

fn hash_password(password: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .ok()
        .map(|password_hash| password_hash.to_string())
}

fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(parsed_hash) => parsed_hash,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub(crate) fn handle_user_page<T: Write>(stream: &mut T, request: &HttpRequest) {
    let session_id = match session_cookie(request) {
        Some(session_id) => session_id,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "No active session.",
            );
            return;
        }
    };

    let user_subject = match user_subject_for_session(&session_id) {
        Some(user_subject) => user_subject,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "Invalid or expired session.",
            );
            return;
        }
    };

    let user = match find_user_by_subject(&user_subject) {
        Some(user) => user,
        None => {
            send_response(
                stream,
                "HTTP/1.1 401 UNAUTHORIZED",
                "text/plain",
                "Session user was not found.",
            );
            return;
        }
    };

    match fs::read_to_string("web/user.html") {
        Ok(template) => {
            let contents = template
                .replace("{{name}}", &html_escape(&user.name))
                .replace("{{username}}", &html_escape(&user.username))
                .replace("{{email}}", &html_escape(&user.email))
                .replace("{{birthdate}}", &html_escape(&user.birthdate));
            send_response(stream, "HTTP/1.1 200 OK", "text/html", &contents);
        }
        Err(error) => {
            eprintln!("Could not read web/user.html: {error}");
            send_response(
                stream,
                "HTTP/1.1 500 INTERNAL SERVER ERROR",
                "text/plain",
                "Could not read user page.",
            );
        }
    }
}

pub(crate) fn session_cookie(request: &HttpRequest) -> Option<String> {
    let cookies = request.headers.get("cookie")?;

    cookies
        .split(';')
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| {
            if name == "__Host-session_id" {
                Some(value.to_string())
            } else {
                None
            }
        })
}

fn parse_form_body(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (percent_decode(key), percent_decode(value)))
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16)
        {
            decoded.push(hex);
            index += 3;
            continue;
        }

        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }

    String::from_utf8_lossy(&decoded).to_string()
}

// Stable IdP-local identifier used as the OIDC subject instead of a user DID.
fn create_user_subject() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("user-{nanos}")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
