//! End-to-end proof that the `oxiquic-crypto` bridge drives a real
//! `rustls::quic` TLS 1.3 handshake to completion — entirely on Pure-Rust
//! crypto (OxiCrypto primitives + `rustls_rustcrypto` kx/sig), no UDP.
//!
//! This is the load-bearing integration test for Wave 1: it exercises the
//! full provider (hash, hmac, hkdf, AEAD, kx, signatures, cert verification)
//! through rustls, including the QUIC key schedule that yields handshake and
//! 1-RTT packet keys.

use std::sync::Arc;

use oxiquic_crypto::quic_crypto_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::quic::{ClientConnection, KeyChange, ServerConnection, Version};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// QUIC transport parameters are opaque to the TLS layer; any bytes will do for
/// a handshake-only test. (A real endpoint encodes RFC 9000 §18 parameters.)
const CLIENT_TP: &[u8] = &[0x00, 0x01, 0x02, 0x03];
const SERVER_TP: &[u8] = &[0x04, 0x05, 0x06, 0x07];

/// Pump all currently-available handshake data from `from` into `to`, applying
/// key changes, and report whether `from` produced 1-RTT keys (handshake done
/// from its perspective).
fn transfer(from: &mut Connection, to: &mut Connection) -> bool {
    let mut buf = Vec::new();
    let key_change = from.write_hs(&mut buf);
    if !buf.is_empty() {
        to.read_hs(&buf).expect("peer accepted handshake data");
    }
    matches!(key_change, Some(KeyChange::OneRtt { .. }))
}

enum Connection {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl Connection {
    fn write_hs(&mut self, buf: &mut Vec<u8>) -> Option<KeyChange> {
        match self {
            Connection::Client(c) => c.write_hs(buf),
            Connection::Server(s) => s.write_hs(buf),
        }
    }
    fn read_hs(&mut self, buf: &[u8]) -> Result<(), rustls::Error> {
        match self {
            Connection::Client(c) => c.read_hs(buf),
            Connection::Server(s) => s.read_hs(buf),
        }
    }
    fn is_handshaking(&self) -> bool {
        match self {
            Connection::Client(c) => c.is_handshaking(),
            Connection::Server(s) => s.is_handshaking(),
        }
    }
    fn zero_rtt_or_one_rtt_available(&self) -> bool {
        // After the handshake, 1-RTT keys are available for app data.
        !self.is_handshaking()
    }
}

#[test]
fn quic_handshake_completes_in_memory() {
    // 1. Self-signed Ed25519 cert via oxitls-rcgen (Pure Rust, no ring).
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    // 2. Build client + server configs from our QUIC crypto provider.
    let provider = Arc::new(quic_crypto_provider());

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust the self-signed cert");

    let client_config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("client TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("server TLS1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server single cert");

    // 3. QUIC connections (TLS-encoded transport params supplied).
    let name = ServerName::try_from("localhost").expect("server name");
    let client = ClientConnection::new(
        Arc::new(client_config),
        Version::V1,
        name,
        CLIENT_TP.to_vec(),
    )
    .expect("client connection");
    let server = ServerConnection::new(Arc::new(server_config), Version::V1, SERVER_TP.to_vec())
        .expect("server connection");

    let mut client = Connection::Client(client);
    let mut server = Connection::Server(server);

    // 4. Drive the read_hs/write_hs loop until both sides finish.
    let mut client_done = false;
    let mut server_done = false;
    for _ in 0..16 {
        // Client -> server.
        if transfer(&mut client, &mut server) {
            client_done = true;
        }
        // Server -> client.
        if transfer(&mut server, &mut client) {
            server_done = true;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }

    // 5. Assert both sides completed and 1-RTT keys are available.
    assert!(!client.is_handshaking(), "client still handshaking");
    assert!(!server.is_handshaking(), "server still handshaking");
    assert!(
        client.zero_rtt_or_one_rtt_available(),
        "client has no 1-RTT keys"
    );
    assert!(
        server.zero_rtt_or_one_rtt_available(),
        "server has no 1-RTT keys"
    );
    // Both sides should have reported a 1-RTT KeyChange during the loop.
    assert!(client_done, "client never produced 1-RTT keys");
    assert!(server_done, "server never produced 1-RTT keys");

    // 6. The negotiated transport parameters round-tripped through TLS.
    match (&client, &server) {
        (Connection::Client(c), Connection::Server(s)) => {
            assert_eq!(
                c.quic_transport_parameters(),
                Some(SERVER_TP),
                "client sees server transport params"
            );
            assert_eq!(
                s.quic_transport_parameters(),
                Some(CLIENT_TP),
                "server sees client transport params"
            );
            // Negotiated suite must be one of ours, QUIC-enabled.
            let suite = c.negotiated_cipher_suite().expect("negotiated suite");
            assert!(
                matches!(suite, rustls::SupportedCipherSuite::Tls13(s) if s.quic.is_some()),
                "negotiated a non-QUIC suite"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn quic_initial_keys_available_before_handshake() {
    // RFC 9001 §5.2: Initial keys are derivable from the DCID before any
    // handshake bytes, through our provider's AES-128-GCM suite + quic alg.
    use oxiquic_crypto::quic::AES128_GCM;
    use oxiquic_crypto::suites::tls13_aes_128_gcm_sha256_internal;
    use rustls::quic::Keys;
    use rustls::Side;

    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = Keys::initial(
        Version::V1,
        tls13_aes_128_gcm_sha256_internal(),
        &AES128_GCM,
        &dcid,
        Side::Client,
    );
    let server = Keys::initial(
        Version::V1,
        tls13_aes_128_gcm_sha256_internal(),
        &AES128_GCM,
        &dcid,
        Side::Server,
    );

    // Client-sealed Initial packet opens with the server's remote keys.
    const HEADER: &[u8] = &[0xc3, 0x00, 0x00, 0x00, 0x01];
    const PAYLOAD: &[u8] = b"CRYPTO frame: ClientHello bytes";
    let mut buf = PAYLOAD.to_vec();
    let tag = client
        .local
        .packet
        .encrypt_in_place(0, HEADER, &mut buf)
        .expect("client seal");
    buf.extend_from_slice(tag.as_ref());
    let plain = server
        .remote
        .packet
        .decrypt_in_place(0, HEADER, &mut buf)
        .expect("server open");
    assert_eq!(plain, PAYLOAD);
}
