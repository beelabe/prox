use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::Arc;
use std::error::Error;

use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::pki_types::ServerName;
use rustls_native_certs::load_native_certs;

mod tls_config {
    use super::*;

    pub fn build() -> Result<ClientConfig, Box<dyn Error>> {
        let mut root_store = RootCertStore::empty();
        let native_certs = load_native_certs().certs;
        for cert in native_certs {
            root_store.add(cert)?;
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(config)
    }
}

mod http_parser {
    pub fn extract_host(request: &str) -> Result<String, Box<dyn std::error::Error>> {
        let host_line = request.lines()
            .find(|line| line.to_lowercase().starts_with("host:"))
            .ok_or("Missing Host header")?;
        Ok(host_line.trim_start_matches("Host:").trim().to_string())
    }
}

mod tls_connector {
    use super::*;

    pub fn connect(host: String, config: Arc<ClientConfig>) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
        let server_name = ServerName::try_from(host.clone())?;
        let conn = ClientConnection::new(config, server_name)?;
        let tls_socket = TcpStream::connect((host.as_str(), 443))?;
        Ok(StreamOwned::new(conn, tls_socket))
    }
}

mod http_forwarder {
    use super::*;

    pub fn forward_request(stream: &mut StreamOwned<ClientConnection, TcpStream>, host: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );
        stream.write_all(request.as_bytes())?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    }
}

mod proxy_handler {
    use super::*;

    pub fn handle_client(mut client_stream: TcpStream, tls_config: Arc<ClientConfig>) -> Result<(), Box<dyn Error>> {
        let mut buffer = [0; 4096];
        let n = client_stream.read(&mut buffer)?;
        let request_str = String::from_utf8_lossy(&buffer[..n]).to_string();

        let host = http_parser::extract_host(&request_str)?;
        let mut tls_stream = tls_connector::connect(host.clone(), tls_config)?;
        let response = http_forwarder::forward_request(&mut tls_stream, &host)?;

        client_stream.write_all(&response)?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Synchronous TLS proxy listening on http://127.0.0.1:8080");

    let tls_config = Arc::new(tls_config::build()?);

    for stream in listener.incoming() {
        match stream {
            Ok(client_stream) => {
                if let Err(e) = proxy_handler::handle_client(client_stream, tls_config.clone()) {
                    eprintln!("Error handling client: {}", e);
                }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    Ok(())
}
