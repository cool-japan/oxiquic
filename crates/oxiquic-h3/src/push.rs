//! HTTP/3 server push support (RFC 9114 §4.6).
//!
//! # Limitations
//!
//! h3 0.0.8 does not implement server push. This module provides the correct
//! API shape and documents the limitation. All methods return
//! [`OxiQuicError::NotImplemented`] with an explanatory message.
//!
//! The h3 crate currently rejects `PUSH_PROMISE` frames on both sides. For
//! production push support, upgrade to an h3 version that includes
//! `MAX_PUSH_ID` exchange and `PUSH_PROMISE` encoding.
//!
//! On the server side, initiate a push via [`H3Responder::push_promise`][crate::server::H3Responder::push_promise].
//! On the client side, [`accept_push_stub`] is a no-op placeholder that
//! always returns `Ok(None)`.

use bytes::Bytes;
use oxiquic_core::OxiQuicError;

// ─────────────────────────────────────────────────────────────────────────────
// H3PushStream — server-pushed resource stream
// ─────────────────────────────────────────────────────────────────────────────

/// A server push stream, carrying a pushed HTTP response.
///
/// Obtained via [`H3Responder::push_promise`][crate::server::H3Responder::push_promise].
///
/// # Limitations
///
/// h3 0.0.8 does not implement server push. All methods on this type return
/// [`OxiQuicError::NotImplemented`].
pub struct H3PushStream {
    /// The push ID assigned to this push stream.
    push_id: u64,
}

impl H3PushStream {
    /// Construct a new (stub) push stream with the given push ID.
    ///
    /// This is intentionally not `pub` — push streams are created only
    /// via [`H3Responder::push_promise`][crate::server::H3Responder::push_promise],
    /// which currently returns an error before this constructor would be reached.
    #[allow(dead_code)]
    pub(crate) fn new(push_id: u64) -> Self {
        Self { push_id }
    }

    /// The push ID for this stream (RFC 9114 §4.6).
    #[must_use]
    pub fn push_id(&self) -> u64 {
        self.push_id
    }

    /// Send the pushed response headers.
    ///
    /// # Errors
    ///
    /// Always returns [`OxiQuicError::NotImplemented`] — h3 0.0.8 does not
    /// support server push.
    pub async fn send_response(
        &mut self,
        _status: http::StatusCode,
        _headers: http::HeaderMap,
    ) -> Result<(), OxiQuicError> {
        Err(OxiQuicError::NotImplemented(
            "server push requires h3 > 0.0.8 with MAX_PUSH_ID support".into(),
        ))
    }

    /// Send pushed response body data.
    ///
    /// # Errors
    ///
    /// Always returns [`OxiQuicError::NotImplemented`] — h3 0.0.8 does not
    /// support server push.
    pub async fn send_data(&mut self, _data: Bytes) -> Result<(), OxiQuicError> {
        Err(OxiQuicError::NotImplemented(
            "server push requires h3 > 0.0.8 with MAX_PUSH_ID support".into(),
        ))
    }

    /// Finish the push stream (send FIN).
    ///
    /// # Errors
    ///
    /// Always returns [`OxiQuicError::NotImplemented`] — h3 0.0.8 does not
    /// support server push.
    pub async fn finish(&mut self) -> Result<(), OxiQuicError> {
        Err(OxiQuicError::NotImplemented(
            "server push requires h3 > 0.0.8 with MAX_PUSH_ID support".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client-side push acceptance (stub)
// ─────────────────────────────────────────────────────────────────────────────

/// Accept a server-pushed resource (RFC 9114 §4.6).
///
/// # Limitations
///
/// h3 0.0.8 does not support push reception. This function always returns
/// `Ok(None)`, indicating no push was received.
///
/// When h3 gains push support this function will return
/// `Ok(Some((promised_request, pushed_response)))`.
pub async fn accept_push_stub(
) -> Result<Option<(http::Request<()>, crate::message::H3Response)>, OxiQuicError> {
    Ok(None)
}
