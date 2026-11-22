use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::{
    auth_handlers::{
        handle_login, handle_logout, handle_register, handle_update_user, handle_user_page,
        session_cookie,
    },
    http_protocol::{read_http_request, send_file, send_redirect, send_response},
    idp_rp_admin::{accept_rp_request, get_master_did, list_rp_requests, reject_rp_request},
    session_store::user_subject_for_session,
};

pub fn handle_connection<T: Read + Write>(stream: &mut T) {
    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("Could not read HTTPS request: {error}");
            return;
        }
    };
    let request_log = request
        .request_line
        .split_once('?')
        .map(|(method_and_path, _)| method_and_path)
        .unwrap_or(&request.request_line);
    println!("Request: {request_log}");

    match request.request_line.as_str() {
        "GET / HTTP/1.1" => send_file(stream, "web/home.html", "text/html"),
        "GET /register HTTP/1.1" => send_file(stream, "web/register.html", "text/html"),
        "GET /login HTTP/1.1" => {
            let has_active_session = session_cookie(&request)
                .and_then(|session_id| user_subject_for_session(&session_id))
                .is_some();
            if has_active_session {
                send_redirect(stream, "/user");
            } else {
                send_file(stream, "web/login.html", "text/html");
            }
        }
        "GET /admin HTTP/1.1" => send_file(stream, "web/admin.html", "text/html"),
        "GET /style.css HTTP/1.1" => send_file(stream, "web/style.css", "text/css"),
        "GET /master-did HTTP/1.1" => get_master_did(stream),
        "GET /admin/rp-requests HTTP/1.1" => list_rp_requests(stream),
        "GET /user HTTP/1.1" => handle_user_page(stream, &request),
        line if line.starts_with("GET /sso") => send_file(stream, "web/sso.html", "text/html"),
        "POST /register HTTP/1.1" => handle_register(stream, &request),
        "POST /login HTTP/1.1" => handle_login(stream, &request),
        "POST /logout HTTP/1.1" => handle_logout(stream, &request),
        "POST /user/update HTTP/1.1" => handle_update_user(stream, &request),
        "POST /sso/authenticate HTTP/1.1" => {
            proxy_sso_request(stream, &request, "/sso/authenticate")
        }
        "POST /sso/session-authenticate HTTP/1.1" => proxy_session_authentication(stream, &request),
        "POST /sso/issue-code HTTP/1.1" => proxy_sso_request(stream, &request, "/sso/issue-code"),
        "POST /admin/rp-requests/accept HTTP/1.1" => accept_rp_request(stream, &request),
        "POST /admin/rp-requests/reject HTTP/1.1" => reject_rp_request(stream, &request),
        _ => send_response(
            stream,
            "HTTP/1.1 404 NOT FOUND",
            "text/plain",
            "404 Not Found",
        ),
    }
}

// Proxies the browser's HTTPS request to the local IdP backend and forwards its
// complete response, including the DIDSSO authorization-code headers.
fn proxy_sso_request<T: Write>(
    stream: &mut T,
    request: &crate::http_protocol::HttpRequest,
    backend_path: &str,
) {
    proxy_sso_request_for_subject(stream, request, backend_path, None);
}

fn proxy_session_authentication<T: Write>(
    stream: &mut T,
    request: &crate::http_protocol::HttpRequest,
) {
    let user_subject =
        session_cookie(request).and_then(|session_id| user_subject_for_session(&session_id));
    let Some(user_subject) = user_subject else {
        send_response(
            stream,
            "HTTP/1.1 401 UNAUTHORIZED",
            "application/json",
            r#"{"error":"No active IdP session"}"#,
        );
        return;
    };

    proxy_sso_request_for_subject(
        stream,
        request,
        "/sso/session-authenticate",
        Some(&user_subject),
    );
}

fn proxy_sso_request_for_subject<T: Write>(
    stream: &mut T,
    request: &crate::http_protocol::HttpRequest,
    backend_path: &str,
    user_subject: Option<&str>,
) {
    let backend_host =
        std::env::var("DIDSSO_IDP_DIDCOMM_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let backend_port = std::env::var("DIDSSO_IDP_DIDCOMM_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8770);
    let mut backend = match TcpStream::connect((backend_host.as_str(), backend_port)) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("Could not connect to IdP backend: {error}");
            send_response(
                stream,
                "HTTP/1.1 502 BAD GATEWAY",
                "application/json",
                r#"{"error":"IdP backend is unavailable"}"#,
            );
            return;
        }
    };
    let user_subject_header = user_subject
        .map(|subject| format!("X-DIDSSO-User-Subject-Hex: {}\r\n", hex_encode(subject)))
        .unwrap_or_default();
    let backend_request = format!(
        "POST {backend_path} HTTP/1.1\r\nHost: {backend_host}:{backend_port}\r\nContent-Type: application/json\r\nX-DIDSSO-Internal-Proxy: https-idp\r\n{user_subject_header}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        request.body.len(),
        request.body,
    );

    if backend.write_all(backend_request.as_bytes()).is_err() {
        send_response(
            stream,
            "HTTP/1.1 502 BAD GATEWAY",
            "application/json",
            r#"{"error":"Could not send request to IdP backend"}"#,
        );
        return;
    }

    let mut response = Vec::new();
    if backend.read_to_end(&mut response).is_err() || response.is_empty() {
        send_response(
            stream,
            "HTTP/1.1 502 BAD GATEWAY",
            "application/json",
            r#"{"error":"Could not read response from IdP backend"}"#,
        );
        return;
    }

    if let Err(error) = stream.write_all(&response) {
        eprintln!("Could not forward IdP backend response: {error}");
    }
}

fn hex_encode(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
