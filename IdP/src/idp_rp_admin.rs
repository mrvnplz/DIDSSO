use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::http_protocol::{HttpRequest, send_response};

fn didcomm_address() -> (String, u16) {
    let host = std::env::var("DIDSSO_IDP_DIDCOMM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("DIDSSO_IDP_DIDCOMM_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8770);
    (host, port)
}

pub(crate) fn list_rp_requests<T: Write>(stream: &mut T) {
    match proxy_get("/rp-registration/pending") {
        Ok(body) => send_response(stream, "HTTP/1.1 200 OK", "application/json", &body),
        Err(error) => send_response(
            stream,
            "HTTP/1.1 502 BAD GATEWAY",
            "text/plain",
            &format!("Could not reach IdP DIDComm backend: {error}"),
        ),
    }
}

pub(crate) fn get_master_did<T: Write>(stream: &mut T) {
    match proxy_get("/master-did") {
        Ok(body) => send_response(stream, "HTTP/1.1 200 OK", "application/json", &body),
        Err(error) => send_response(
            stream,
            "HTTP/1.1 502 BAD GATEWAY",
            "text/plain",
            &format!("Could not reach IdP DIDComm backend: {error}"),
        ),
    }
}

pub(crate) fn accept_rp_request<T: Write>(stream: &mut T, request: &HttpRequest) {
    proxy_decision(stream, "/admin/rp-requests/accept", &request.body);
}

pub(crate) fn reject_rp_request<T: Write>(stream: &mut T, request: &HttpRequest) {
    proxy_decision(stream, "/admin/rp-requests/reject", &request.body);
}

fn proxy_decision<T: Write>(stream: &mut T, path: &str, body: &str) {
    match proxy_post(path, body) {
        Ok(response_body) => send_response(
            stream,
            "HTTP/1.1 200 OK",
            "application/json",
            &response_body,
        ),
        Err(error) => send_response(
            stream,
            "HTTP/1.1 502 BAD GATEWAY",
            "text/plain",
            &format!("Could not reach IdP DIDComm backend: {error}"),
        ),
    }
}

fn proxy_get(path: &str) -> std::io::Result<String> {
    let (host, port) = didcomm_address();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    send_raw_http(&host, port, request)
}

fn proxy_post(path: &str, body: &str) -> std::io::Result<String> {
    let (host, port) = didcomm_address();
    let length = body.len();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}"
    );
    send_raw_http(&host, port, request)
}

fn send_raw_http(host: &str, port: u16, request: String) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default())
}
