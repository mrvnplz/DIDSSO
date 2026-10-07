use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use rcgen::generate_simple_self_signed;
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

fn main() {
    let port = std::env::var("PORT").unwrap();
    let host = std::env::var("DIDSSO_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{host}:{port}");

    let listener = TcpListener::bind(&addr).unwrap();
    let tls_config = Arc::new(create_tls_config());
    println!("IdP server listening on https://{addr}");

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_tls_connection(stream, tls_config.clone());
    }
}

fn create_tls_config() -> ServerConfig {
    let certified_key =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified_key.key_pair.serialize_der(),
    ));

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap()
}

fn handle_tls_connection(stream: TcpStream, tls_config: Arc<ServerConfig>) {
    let tls_connection = ServerConnection::new(tls_config).unwrap();
    let mut tls_stream = StreamOwned::new(tls_connection, stream);
    id_p::handle_connection(&mut tls_stream);
}
