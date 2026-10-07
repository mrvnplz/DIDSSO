use std::{
    fs,
    io::{self, prelude::*},
    net::{TcpListener, TcpStream},
};

fn main() {
    let port = std::env::var("PORT").expect("PORT muss gesetzt sein");
    let host = std::env::var("DIDSSO_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{host}:{port}");

    let listener = TcpListener::bind(&addr).expect("Server konnte nicht starten");

    println!("Server laeuft auf http://{addr}");
    println!("Stoppen mit Ctrl+C");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream) {
                    eprintln!("Request konnte nicht verarbeitet werden: {error}");
                }
            }
            Err(error) => eprintln!("Verbindung konnte nicht angenommen werden: {error}"),
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or("");
    println!("Request: {request_line}");

    let path = request_line
        .strip_prefix("GET ")
        .and_then(|request| request.split_whitespace().next())
        .and_then(|request| request.split('?').next())
        .unwrap_or("");
    let Some((file, content_type)) = static_route(path) else {
        return write_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"404 Not Found",
        );
    };

    let contents = fs::read(file)?;
    write_response(&mut stream, "200 OK", content_type, &contents)
}

fn static_route(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" => Some(("web/index.html", "text/html; charset=utf-8")),
        "/admin" => Some(("web/admin.html", "text/html; charset=utf-8")),
        "/did-sso" => Some(("web/did-sso.html", "text/html; charset=utf-8")),
        "/sso/wait" => Some(("web/sso-wait.html", "text/html; charset=utf-8")),
        "/user" => Some(("web/user.html", "text/html; charset=utf-8")),
        "/style.css" => Some(("web/style.css", "text/css; charset=utf-8")),
        _ => None,
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)
}
