//! HTTP/3 types and connection helpers for the OxiQUIC stack (RFC 9114 / RFC 9204).
//!
//! This crate provides:
//!
//! - The HTTP/3 message and settings model: [`H3Request`], [`H3Response`], [`H3Settings`].
//! - The HTTP/3 error taxonomy: [`H3Error`], [`H3ErrorCode`].
//! - With the `h3-compat` feature (default): [`connect_h3`] and [`accept_h3`] for
//!   establishing HTTP/3 connections over OxiQUIC's [`DrivenConnection`].
//!
//! # HTTP/3 over QUIC (h3-compat)
//!
//! ```ignore
//! // Client:
//! let (mut h3_conn, send_request) = connect_h3(driven_conn).await?;
//!
//! // Server:
//! let mut h3_conn = accept_h3(driven_conn).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod message;

pub use error::{H3Error, H3ErrorCode};
pub use message::{H3Request, H3Response, H3Settings, DEFAULT_MAX_FIELD_SECTION_SIZE};
pub use oxiquic_core::OxiQuicError;

#[cfg(feature = "h3-compat")]
pub use oxiquic_transport::{
    H3BidiStream, H3RecvStream, H3SendStream, OxiQuicH3Connection, OxiQuicOpenStreams,
};

// Re-export DrivenConnection so callers don't need to import oxiquic-transport directly.
#[cfg(feature = "h3-compat")]
pub use oxiquic_transport::endpoint::DrivenConnection;

#[cfg(feature = "h3-compat")]
mod h3_io;

#[cfg(feature = "h3-compat")]
pub use h3_io::{accept_h3, accept_h3_with, connect_h3, connect_h3_with};

#[cfg(feature = "h3-compat")]
mod client;

#[cfg(feature = "h3-compat")]
mod server;

#[cfg(feature = "h3-compat")]
mod push;

#[cfg(feature = "h3-compat")]
pub mod pool;

#[cfg(feature = "h3-compat")]
pub use client::{H3Client, H3ClientBuilder, RequestStream};

#[cfg(feature = "h3-compat")]
pub use pool::{H3Pool, OriginKey, PoolConfig, TlsFactory};

#[cfg(feature = "h3-compat")]
pub use server::{
    H3Connection, H3Incoming, H3RequestContext, H3Responder, H3Server, H3ServerBuilder,
    H3ServerEndpoint,
};

#[cfg(feature = "h3-compat")]
pub use push::{accept_push_stub, H3PushStream};

/// Creates an [`H3Client`] from an already-connected [`DrivenConnection`].
///
/// This is a thin convenience wrapper around [`H3Client::new`] for callers
/// who have a `DrivenConnection` from
/// [`ClientEndpoint::connect`](oxiquic_transport::ClientEndpoint::connect).
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the underlying QUIC
/// transport reports an error.
#[cfg(feature = "h3-compat")]
pub async fn connect_h3_client(driven: DrivenConnection) -> Result<H3Client, H3Error> {
    H3Client::new(driven).await
}

/// Creates an [`H3Server`] from an already-accepted [`DrivenConnection`].
///
/// This is a thin convenience wrapper around [`H3Server::new`] for callers
/// who have a `DrivenConnection` from
/// [`ServerEndpoint::accept`](oxiquic_transport::ServerEndpoint::accept).
///
/// # Errors
///
/// Returns [`H3Error`] if the HTTP/3 handshake fails or the underlying QUIC
/// transport reports an error.
#[cfg(feature = "h3-compat")]
pub async fn accept_h3_server(driven: DrivenConnection) -> Result<H3Server, H3Error> {
    H3Server::new(driven).await
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_wave4;
