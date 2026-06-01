//! Tests for QUIC Version Negotiation (RFC 9000 §17.2.1).
//!
//! Coverage:
//!   1. Unit: `encode_version_negotiation` — wire-format correctness.
//!   2. Unit: `decode_version_negotiation` roundtrip.
//!   3. Unit: client-side `Connection::handle_datagram` returns
//!      `OxiQuicError::VersionNegotiation` on receiving a VN packet.
//!   4. Integration: server sends a VN packet when a client's Initial carries
//!      an unsupported version; the raw VN response is validated.

use std::sync::Arc;
use std::time::Instant;

use oxiquic_crypto::quic_crypto_provider;
use oxiquic_transport::{
    Connection, OxiQuicError, ServerEndpoint, TransportConfig, TransportParams,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::UdpSocket;

// ─── helpers ──────────────────────────────────────────────────────────────────

fn server_config() -> Arc<ServerConfig> {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let provider = Arc::new(quic_crypto_provider());
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust cert");
    let server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("TLS1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single cert");
    Arc::new(server)
}

fn client_config() -> Arc<ClientConfig> {
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let provider = Arc::new(quic_crypto_provider());
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("trust cert");
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("TLS1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(client)
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback")
}

// ─── unit tests ───────────────────────────────────────────────────────────────

/// Verify the byte-level wire format emitted by `encode_version_negotiation`.
///
/// RFC 9000 §17.2.1:
///   - first byte: bit 7 = 1 (long header), bit 6 = 0 (VN marker)
///   - bytes 1–4 = 0x00000000 (version field = 0)
///   - byte 5   = DCID length
///   - DCID     = client's SCID
///   - byte     = SCID length
///   - SCID     = client's DCID
///   - remaining = supported version list, each 4 bytes big-endian
#[test]
fn vn_packet_encodes_correctly() {
    // Simulate: client DCID = [0x01, 0x02], client SCID = [0x03, 0x04, 0x05]
    let client_dcid: &[u8] = &[0x01, 0x02];
    let client_scid: &[u8] = &[0x03, 0x04, 0x05];

    // In the VN response: VN's DCID = client's SCID; VN's SCID = client's DCID.
    let pkt =
        oxiquic_transport::encode_version_negotiation(client_scid, client_dcid, &[0x0000_0001]);

    // First byte: Header Form = 1, Fixed Bit = 0.
    assert_eq!(pkt[0] & 0x80, 0x80, "Header Form bit must be set");
    assert_eq!(pkt[0] & 0x40, 0x00, "Fixed Bit (bit 6) must be 0 for VN");

    // Bytes 1–4: Version = 0.
    assert_eq!(&pkt[1..5], &[0x00, 0x00, 0x00, 0x00], "Version must be 0");

    // DCID = client's SCID.
    let dcid_len = pkt[5] as usize;
    assert_eq!(dcid_len, client_scid.len(), "DCID length mismatch");
    let dcid_start = 6;
    assert_eq!(
        &pkt[dcid_start..dcid_start + dcid_len],
        client_scid,
        "DCID must equal client SCID"
    );

    // SCID = client's DCID.
    let scid_len_off = dcid_start + dcid_len;
    let scid_len = pkt[scid_len_off] as usize;
    assert_eq!(scid_len, client_dcid.len(), "SCID length mismatch");
    let scid_start = scid_len_off + 1;
    assert_eq!(
        &pkt[scid_start..scid_start + scid_len],
        client_dcid,
        "SCID must equal client DCID"
    );

    // Supported version list: 0x00000001.
    let vers_off = scid_start + scid_len;
    assert_eq!(pkt.len() - vers_off, 4, "exactly one version (4 bytes)");
    assert_eq!(
        u32::from_be_bytes(pkt[vers_off..vers_off + 4].try_into().expect("4 bytes")),
        0x0000_0001,
        "QUIC v1 must appear in supported-version list"
    );
}

/// Encode then decode a VN packet and confirm the version list is preserved.
#[test]
fn vn_decode_roundtrip() {
    let client_dcid: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let client_scid: &[u8] = &[0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
    let versions = &[0x0000_0001u32];

    let pkt = oxiquic_transport::encode_version_negotiation(client_scid, client_dcid, versions);
    let decoded = oxiquic_transport::decode_version_negotiation(&pkt)
        .expect("decode_version_negotiation returned None on valid VN packet");

    assert_eq!(decoded, versions, "decoded version list must match encoded");
}

/// A packet that isn't a VN (short header) must return `None`.
#[test]
fn vn_decode_rejects_short_header() {
    let not_vn = &[0x40u8, 0x01, 0x02, 0x03, 0x04]; // short-header first byte
    assert!(
        oxiquic_transport::decode_version_negotiation(not_vn).is_none(),
        "short-header packet must not decode as VN"
    );
}

/// A regular long-header packet (non-zero version) must return `None`.
#[test]
fn vn_decode_rejects_non_zero_version() {
    // Craft a minimal long-header first byte with version 0x00000001.
    let mut pkt = vec![0xC0u8]; // long header + fixed bit + Initial
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // dcid_len=0, scid_len=0
    assert!(
        oxiquic_transport::decode_version_negotiation(&pkt).is_none(),
        "non-VN long-header packet must not decode as VN"
    );
}

// ─── unit: client connection → error on receiving VN ─────────────────────────

/// Feed a Version Negotiation packet directly into a freshly-created client
/// [`Connection`] and verify it surfaces as
/// [`OxiQuicError::VersionNegotiation`].
///
/// This exercises the guard in `recv_long_packet`:
///   - `role == Client`
///   - `state == Handshaking`
///   - `initial.largest_received().is_none()` (no successfully decrypted packets)
///
/// The VN packet's CIDs are not validated by the receiving code (the guard
/// fires before the DCID check), so we can use arbitrary values.
#[test]
fn client_returns_version_negotiation_error_on_vn_packet() {
    let cfg = client_config();
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("addr");
    let server_name = ServerName::try_from("localhost".to_string()).expect("server name");
    let params = TransportParams::default();

    let mut conn = Connection::new_client(
        cfg,
        server_name,
        peer,
        params,
        Default::default(),
        Default::default(),
    )
    .expect("new_client");

    // Build a VN packet: use the connection's local CID as the VN's DCID so
    // the client can recognise it.  The VN's SCID (= our initial_dcid) is
    // not accessible, but the guard fires before CID validation anyway.
    let local_cid = conn.local_cid().as_bytes().to_vec();
    let fake_server_dcid = &[0xAA; 8];
    let mut vn = oxiquic_transport::encode_version_negotiation(
        &local_cid,       // VN DCID = client's local CID
        fake_server_dcid, // VN SCID = some server CID
        &[0x0a0a_0a0au32, 0x0000_0001u32],
    );

    let err = conn
        .handle_datagram(Instant::now(), &mut vn)
        .expect_err("client must fail on VN packet");

    match err {
        OxiQuicError::VersionNegotiation { supported } => {
            assert!(
                supported.contains(&0x0a0a_0a0a),
                "supported list must contain the grease version from VN"
            );
            assert!(
                supported.contains(&0x0000_0001),
                "supported list must contain QUIC v1"
            );
        }
        other => panic!("expected VersionNegotiation error, got: {other:?}"),
    }
}

// ─── integration: server → VN on unknown version ─────────────────────────────

/// Craft a minimal Initial-shaped datagram carrying an unsupported QUIC
/// version (0xFF00_0099), send it to a `ServerEndpoint`, and verify the
/// server responds with a well-formed Version Negotiation packet listing
/// QUIC v1 (0x00000001).
///
/// This test exercises the full server demux path without needing a real TLS
/// handshake — only the version check fires before any crypto is touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_sends_vn_for_unknown_version() {
    let server = ServerEndpoint::bind(loopback(), server_config(), TransportConfig::default())
        .await
        .expect("bind server");
    let server_addr = server.local_addr().expect("server addr");

    // Keep the server's accept loop running in the background; we only care
    // about the VN response at the UDP level.
    let _server_bg = tokio::spawn(async move {
        // The mock Initial won't progress past version check so this never
        // returns a real connection. Accept will block until the test finishes.
        let _ = server.accept().await;
    });

    // Bind a raw UDP socket to act as the "client".
    let sock = UdpSocket::bind(loopback()).await.expect("bind client sock");

    // Build a minimal Initial-shaped long-header datagram with version
    // 0xFF00_0099 (unknown / unsupported).
    let fake_initial = build_fake_initial(0xFF00_0099u32, &[0xAA; 8], &[0xBB; 8]);

    sock.send_to(&fake_initial, server_addr)
        .await
        .expect("send fake Initial");

    // Give the demux ~500 ms to process the datagram and send back the VN.
    let mut buf = vec![0u8; 2048];
    let timeout = tokio::time::Duration::from_millis(500);
    let (len, _from) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .expect("no VN received within 500 ms")
        .expect("recv_from error");

    let vn_bytes = &buf[..len];

    // Must be a VN packet.
    let versions = oxiquic_transport::decode_version_negotiation(vn_bytes)
        .expect("server response is not a valid VN packet");

    // Must list QUIC v1.
    assert!(
        versions.contains(&0x0000_0001),
        "VN response must advertise QUIC v1 (0x00000001); got: {versions:x?}"
    );

    // VN's DCID must equal the fake Initial's SCID (0xBB * 8).
    let dcid_len = vn_bytes[5] as usize;
    let dcid = &vn_bytes[6..6 + dcid_len];
    assert_eq!(dcid, &[0xBBu8; 8], "VN DCID must echo the Initial's SCID");

    // VN's SCID must equal the fake Initial's DCID (0xAA * 8).
    let scid_len_off = 6 + dcid_len;
    let scid_len = vn_bytes[scid_len_off] as usize;
    let scid = &vn_bytes[scid_len_off + 1..scid_len_off + 1 + scid_len];
    assert_eq!(scid, &[0xAAu8; 8], "VN SCID must echo the Initial's DCID");
}

// ─── helper: build a minimal Initial-shaped long-header datagram ─────────────

/// Construct the smallest possible long-header datagram that looks like a
/// client's first Initial.  It only needs to pass the demux's version check;
/// the "payload" can be zeros because the demux will reject it (version
/// mismatch) before attempting decryption.
fn build_fake_initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // First byte: Header Form=1, Fixed Bit=1, type bits=0b00 (Initial), reserved+PN len.
    buf.push(0xC0u8);
    // Version.
    buf.extend_from_slice(&version.to_be_bytes());
    // DCID.
    buf.push(dcid.len() as u8);
    buf.extend_from_slice(dcid);
    // SCID.
    buf.push(scid.len() as u8);
    buf.extend_from_slice(scid);
    // Token length (varint 0 = empty token).
    buf.push(0x00u8);
    // Length field (varint): covers PN + payload.  Use a small fixed value
    // (1 byte PN + 16 bytes dummy payload + 16 AEAD tag = 33, encoded as 0x4021).
    buf.push(0x40u8);
    buf.push(0x21u8);
    // Packet number (1 byte, value 0).
    buf.push(0x00u8);
    // Dummy payload (won't be decrypted — version mismatch is caught first).
    buf.extend_from_slice(&[0u8; 32]);
    buf
}
