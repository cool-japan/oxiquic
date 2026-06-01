//! HTTP/3 connection builders over OxiQUIC's [`DrivenConnection`].
//!
//! Provides [`connect_h3`] (client) and [`accept_h3`] (server) which wrap a
//! [`DrivenConnection`] in an [`OxiQuicH3Connection`] adapter and hand it to
//! the `h3` crate's builder, performing the HTTP/3 handshake (SETTINGS,
//! control-stream setup, QPACK streams) before returning.

use bytes::Bytes;

use crate::error::H3Error;
use oxiquic_transport::endpoint::DrivenConnection;
use oxiquic_transport::OxiQuicH3Connection;

/// Establish an HTTP/3 **client** connection over an already-connected QUIC
/// transport.
///
/// This function wraps `driven_conn` in an [`OxiQuicH3Connection`] adapter and
/// calls `h3::client::builder().build(conn)`, which opens the HTTP/3 control
/// and QPACK streams and exchanges `SETTINGS` frames before returning.
///
/// # Returns
///
/// A `(h3::client::Connection, h3::client::SendRequest)` tuple.  Use
/// `SendRequest::send_request` to issue HTTP/3 requests.
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the QUIC transport
/// encounters an error.
pub async fn connect_h3(
    driven_conn: DrivenConnection,
) -> Result<
    (
        h3::client::Connection<OxiQuicH3Connection, Bytes>,
        h3::client::SendRequest<OxiQuicOpenStreams, Bytes>,
    ),
    H3Error,
>
where
    OxiQuicOpenStreams: h3::quic::OpenStreams<Bytes>,
{
    let h3_conn = OxiQuicH3Connection::new(driven_conn);
    h3::client::builder()
        .build(h3_conn)
        .await
        .map_err(|e| H3Error::Connection(e.to_string()))
}

/// Accept an HTTP/3 **server** connection over an already-established QUIC
/// transport.
///
/// This function wraps `driven_conn` in an [`OxiQuicH3Connection`] adapter and
/// calls `h3::server::builder().build(conn)`, which opens the HTTP/3 control
/// and QPACK streams and exchanges `SETTINGS` frames before returning.
///
/// # Returns
///
/// An `h3::server::Connection` that can be polled for incoming requests with
/// `accept()`.
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the QUIC transport
/// encounters an error.
pub async fn accept_h3(
    driven_conn: DrivenConnection,
) -> Result<h3::server::Connection<OxiQuicH3Connection, Bytes>, H3Error> {
    let h3_conn = OxiQuicH3Connection::new(driven_conn);
    h3::server::builder()
        .build(h3_conn)
        .await
        .map_err(|e| H3Error::Connection(e.to_string()))
}

/// Establish an HTTP/3 **client** connection with custom settings.
///
/// Like [`connect_h3`] but threads `max_field_section_size` through the
/// `h3::client::Builder` before performing the HTTP/3 handshake.
///
/// # Returns
///
/// A `(h3::client::Connection, h3::client::SendRequest)` tuple.
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the QUIC transport
/// encounters an error.
pub async fn connect_h3_with(
    driven_conn: DrivenConnection,
    max_field_section_size: u64,
) -> Result<
    (
        h3::client::Connection<OxiQuicH3Connection, Bytes>,
        h3::client::SendRequest<OxiQuicOpenStreams, Bytes>,
    ),
    H3Error,
>
where
    OxiQuicOpenStreams: h3::quic::OpenStreams<Bytes>,
{
    let h3_conn = OxiQuicH3Connection::new(driven_conn);
    let mut builder = h3::client::builder();
    builder.max_field_section_size(max_field_section_size);
    builder
        .build(h3_conn)
        .await
        .map_err(|e| H3Error::Connection(e.to_string()))
}

/// Accept an HTTP/3 **server** connection with custom settings.
///
/// Like [`accept_h3`] but threads `max_field_section_size` through the
/// `h3::server::Builder` before performing the HTTP/3 handshake.
///
/// # Returns
///
/// An `h3::server::Connection` that can be polled for incoming requests with
/// `accept()`.
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the QUIC transport
/// encounters an error.
pub async fn accept_h3_with(
    driven_conn: DrivenConnection,
    max_field_section_size: u64,
) -> Result<h3::server::Connection<OxiQuicH3Connection, Bytes>, H3Error> {
    let h3_conn = OxiQuicH3Connection::new(driven_conn);
    let mut builder = h3::server::builder();
    builder.max_field_section_size(max_field_section_size);
    builder
        .build(h3_conn)
        .await
        .map_err(|e| H3Error::Connection(e.to_string()))
}

// Re-export OxiQuicOpenStreams so the return type of connect_h3 is resolvable
// from the public API surface of this crate without requiring callers to import
// from `oxiquic_transport` directly.
use oxiquic_transport::OxiQuicOpenStreams;
