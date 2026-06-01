//! 0-RTT connection establishment (RFC 9001 §4.6, RFC 9000 §4.6.1).
//!
//! Provides [`ClientEndpoint::connect_0rtt`], which wraps the normal handshake
//! and returns a [`ZeroRttAccepted`] future that resolves once the server's
//! acceptance/rejection decision is known (post-handshake).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::oneshot;

use oxiquic_core::OxiQuicError;

use super::{ClientEndpoint, QuicConnection};

/// A future that resolves to whether the server accepted 0-RTT early data.
///
/// Returns `true` if the server accepted the early data sent during the 0-RTT
/// handshake, `false` if it was rejected (the data was replayed in 1-RTT).
///
/// On a cold connection (no cached session ticket), this always resolves to
/// `false` — the data was sent via normal 1-RTT.
pub struct ZeroRttAccepted(pub(super) oneshot::Receiver<bool>);

impl Future for ZeroRttAccepted {
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        Pin::new(&mut self.0).poll(cx).map(|r| r.unwrap_or(false))
    }
}

impl ClientEndpoint {
    /// Connect to a QUIC server with 0-RTT early data support (RFC 9001 §4.6).
    ///
    /// On the first connection (no cached session ticket), this behaves like
    /// [`connect`][ClientEndpoint::connect]. If a session ticket from a previous
    /// connection is cached via the `ClientConfig`'s resumption store *and* the
    /// server has `max_early_data_size` set to `u32::MAX`, the 0-RTT handshake
    /// takes effect.
    ///
    /// To enable 0-RTT:
    /// - Build the `ClientConfig` with `enable_early_data = true`.
    /// - Use a shared `Resumption` store (`Resumption::in_memory_sessions(N)`)
    ///   so session tickets persist across connections.
    /// - Set `TransportConfig::max_early_data_size(1)` on the **server** endpoint.
    ///
    /// # Returns
    ///
    /// A `(QuicConnection, ZeroRttAccepted)` pair. The `ZeroRttAccepted` future
    /// resolves after the handshake completes:
    /// - `true` — early data was accepted by the server.
    /// - `false` — rejected (or cold connect); data was delivered via 1-RTT.
    ///
    /// # Errors
    ///
    /// Returns [`OxiQuicError`] on bind, TLS, or handshake failure.
    pub async fn connect_0rtt(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<(QuicConnection, ZeroRttAccepted), OxiQuicError> {
        // Drive the full handshake (including 0-RTT emission if keys are available).
        let conn = self.connect(server_addr, server_name).await?;

        // The handshake is complete; read the server's acceptance decision.
        let accepted = conn.zero_rtt_accepted().unwrap_or(false);

        // Wrap in a pre-resolved future so callers can await it uniformly.
        let (tx, rx) = oneshot::channel();
        // Ignore send error: rx will resolve to false if tx is dropped.
        let _ = tx.send(accepted);

        Ok((conn, ZeroRttAccepted(rx)))
    }
}
