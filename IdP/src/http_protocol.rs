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
