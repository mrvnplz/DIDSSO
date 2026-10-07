use std::{
    collections::HashMap,
    fs,
    io::{self, BufReader, prelude::*},
};

use crate::session_store::SESSION_TTL_SECONDS;

#[derive(Debug)]
pub(crate) struct HttpRequest {
    pub(crate) request_line: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: String,
}

pub(crate) fn read_http_request<T: Read>(stream: &mut T) -> io::Result<HttpRequest> {
    let mut buf_reader = BufReader::new(stream);
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line)?;
    request_line = request_line.trim_end().to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line)?;
        let line = line.trim_end();

        if line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body_bytes = vec![0; content_length];

    if content_length > 0 {
        buf_reader.read_exact(&mut body_bytes)?;
    }

    Ok(HttpRequest {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body_bytes).to_string(),
    })
}

pub(crate) fn send_file<T: Write>(stream: &mut T, path: &str, content_type: &str) {
    match fs::read_to_string(path) {
        Ok(contents) => send_response(stream, "HTTP/1.1 200 OK", content_type, &contents),
        Err(error) => {
            eprintln!("Could not read {path}: {error}");
            send_response(
                stream,
                "HTTP/1.1 500 INTERNAL SERVER ERROR",
                "text/plain",
                "Could not read server file.",
            );
        }
    }
}

pub(crate) fn send_redirect_with_session<T: Write>(
    stream: &mut T,
    location: &str,
    session_id: &str,
) {
    let response = format!(
        "HTTP/1.1 303 SEE OTHER\r\nLocation: {location}\r\nSet-Cookie: __Host-session_id={session_id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_TTL_SECONDS}\r\nSet-Cookie: session_id=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-DIDSSO-Service: idp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
}

pub(crate) fn send_redirect<T: Write>(stream: &mut T, location: &str) {
    let response = format!(
        "HTTP/1.1 303 SEE OTHER\r\nLocation: {location}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-DIDSSO-Service: idp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
}

pub(crate) fn send_logout_redirect<T: Write>(stream: &mut T) {
    let response = "HTTP/1.1 303 SEE OTHER\r\nLocation: /\r\nSet-Cookie: __Host-session_id=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0\r\nSet-Cookie: session_id=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-DIDSSO-Service: idp\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(response.as_bytes()).unwrap();
}

pub(crate) fn send_response<T: Write>(
    stream: &mut T,
    status_line: &str,
    content_type: &str,
    contents: &str,
) {
    let length = contents.len();
    let response = format!(
        "{status_line}\r\nContent-Type: {content_type}; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-DIDSSO-Service: idp\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{contents}"
    );
    stream.write_all(response.as_bytes()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::{send_logout_redirect, send_redirect, send_redirect_with_session};

    #[test]
    fn login_cookie_has_secure_attributes_and_contains_only_the_token() {
        let token = "a".repeat(64);
        let mut response = Vec::new();
        send_redirect_with_session(&mut response, "/user", &token);
        let response = String::from_utf8(response).unwrap();

        assert!(response.contains(&format!("Set-Cookie: __Host-session_id={token};")));
        assert!(response.contains("HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600"));
        assert!(response.contains("Cache-Control: no-store"));
        assert!(!response.contains("user@example.com"));
    }

    #[test]
    fn logout_redirect_clears_current_and_legacy_session_cookies() {
        let mut response = Vec::new();
        send_logout_redirect(&mut response);
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 303 SEE OTHER\r\nLocation: /\r\n"));
        assert!(response.contains("Set-Cookie: __Host-session_id=;"));
        assert!(response.contains("Set-Cookie: session_id=;"));
        assert_eq!(response.matches("Max-Age=0").count(), 2);
        assert!(response.contains("Cache-Control: no-store"));
    }

    #[test]
    fn ordinary_redirect_does_not_replace_the_session_cookie() {
        let mut response = Vec::new();
        send_redirect(&mut response, "/user");
        let response = String::from_utf8(response).unwrap();

        assert!(response.starts_with("HTTP/1.1 303 SEE OTHER\r\nLocation: /user\r\n"));
        assert!(!response.contains("Set-Cookie:"));
        assert!(response.contains("Cache-Control: no-store"));
    }
}
