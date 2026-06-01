//! HTTP/3 server types: [`H3Connection`], [`H3Server`], [`H3ServerBuilder`],
//! [`H3RequestContext`], and [`H3Responder`].
//!
//! # Quick start
//!
//! ```ignore
//! // Per-connection approach (for when you already have a DrivenConnection):
//! let mut h3_conn = H3Connection::new(driven).await?;
//! while let Some(ctx) = h3_conn.accept().await? {
//!     let mut resp = ctx.into_responder();
//!     resp.send_full(StatusCode::OK, HeaderMap::new(), Bytes::from_static(b"hello")).await?;
//! }
//!
//! // Endpoint approach:
//! let server = H3ServerBuilder::new("127.0.0.1:443".parse()?)
//!     .with_tls_config(server_tls)
//!     .build()
//!     .await?;
//! let conn = server.accept_connection().await?;
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use oxiquic_transport::{endpoint::DrivenConnection, H3BidiStream, OxiQuicH3Connection};

use crate::{
    error::H3Error,
    message::{H3Request, H3Response, H3Settings},
};

// ─────────────────────────────────────────────────────────────────────────────
// H3Connection — a single HTTP/3 server-side connection
// ─────────────────────────────────────────────────────────────────────────────

/// A single HTTP/3 server connection, wrapping an `h3::server::Connection`.
///
/// Accepts incoming requests via [`H3Connection::accept`] and optionally
/// shuts down with [`H3Connection::shutdown`] (GOAWAY) or [`H3Connection::close`].
///
/// Construct via:
/// - [`H3Connection::new`] — for backwards-compat callers with a raw
///   [`DrivenConnection`].
/// - [`H3ServerEndpoint::accept_connection`] — when using the high-level endpoint
///   owner.
pub struct H3Connection {
    h3_conn: h3::server::Connection<OxiQuicH3Connection, Bytes>,
    /// The locally-configured HTTP/3 settings (what we sent in our SETTINGS frame).
    local_settings: H3Settings,
}

/// Backward-compatible alias: `H3Server` used to be the per-connection type.
///
/// New code should use [`H3Connection`] directly. Existing callers that use
/// `H3Server::new(driven)` continue to work because `H3Server = H3Connection`.
/// The high-level endpoint-owning type is [`H3ServerEndpoint`], built via
/// [`H3ServerBuilder`].
pub type H3Server = H3Connection;

impl H3Connection {
    /// Perform the HTTP/3 server handshake over `driven` and return an
    /// [`H3Connection`] ready to accept requests.
    ///
    /// This uses the default `SETTINGS_MAX_FIELD_SECTION_SIZE` (16 KiB).
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the HTTP/3 handshake fails.
    pub async fn new(driven: DrivenConnection) -> Result<Self, H3Error> {
        Self::new_with_config(driven, crate::message::DEFAULT_MAX_FIELD_SECTION_SIZE).await
    }

    /// Perform the HTTP/3 handshake with a custom `max_field_section_size`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the HTTP/3 handshake fails.
    pub async fn new_with_config(
        driven: DrivenConnection,
        max_field_section_size: u64,
    ) -> Result<Self, H3Error> {
        let conn = OxiQuicH3Connection::new(driven);
        let mut builder = h3::server::builder();
        builder.max_field_section_size(max_field_section_size);
        let h3_conn = builder
            .build(conn)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))?;
        let local_settings = H3Settings {
            max_field_section_size,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        };
        Ok(Self {
            h3_conn,
            local_settings,
        })
    }

    /// Returns the effective HTTP/3 settings for this connection.
    ///
    /// Note: h3 0.0.8 does not expose the peer's SETTINGS frame directly.
    /// This returns the locally-configured settings, which reflects what
    /// was sent in our SETTINGS frame and agreed upon.
    #[must_use]
    pub fn peer_settings(&self) -> &H3Settings {
        &self.local_settings
    }

    /// Accept the next incoming HTTP/3 request.
    ///
    /// Returns `Ok(None)` when the connection has been gracefully shut down
    /// (GOAWAY received and all in-flight requests are complete).
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] on protocol violations or connection errors.
    pub async fn accept(&mut self) -> Result<Option<H3RequestContext>, H3Error> {
        // Record the span event at entry. We do NOT hold an `EnteredSpan`
        // guard across `.await` because `EnteredSpan` is `!Send`, which would
        // break the `Send` bound on `tokio::spawn` futures.
        #[cfg(feature = "tracing")]
        tracing::debug!("h3_accept: waiting for next request");

        let resolver = match self
            .h3_conn
            .accept()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?
        {
            Some(r) => r,
            None => return Ok(None),
        };

        let (req, stream) = resolver
            .resolve_request()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        let method = req.method().as_str().to_string();
        let uri = req.uri().to_string();
        let mut h3req = H3Request::new(method, uri);
        for (name, value) in req.headers() {
            if let Ok(v) = value.to_str() {
                h3req = h3req.with_header(name.as_str(), v);
            }
        }

        Ok(Some(H3RequestContext {
            request: h3req,
            stream,
        }))
    }

    /// Initiate a graceful shutdown by sending a GOAWAY frame (RFC 9114 §5.2).
    ///
    /// In-flight requests complete normally; new requests beyond `max_id` are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the shutdown procedure encounters a protocol error.
    pub async fn shutdown(&mut self, max_id: u64) -> Result<(), H3Error> {
        self.h3_conn
            .shutdown(max_id as usize)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))
    }

    /// Initiate a graceful shutdown with max_id = 0 (no more requests) and
    /// consume this connection handle.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the shutdown procedure encounters a protocol error.
    pub async fn close(mut self) -> Result<(), H3Error> {
        self.h3_conn
            .shutdown(0)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3ServerEndpoint — endpoint-owning type built by H3ServerBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// An HTTP/3 server bound to a local address.
///
/// Constructed via [`H3ServerBuilder`]. Accepts incoming connections via
/// [`H3ServerEndpoint::accept_connection`], each yielding an [`H3Connection`].
///
/// # Example
///
/// ```ignore
/// let server = H3ServerBuilder::new("0.0.0.0:443".parse()?)
///     .with_tls_config(tls)
///     .build()
///     .await?;
/// let conn = server.accept_connection().await?;
/// ```
pub struct H3ServerEndpoint {
    endpoint: oxiquic_transport::ServerEndpoint,
    max_field_section_size: u64,
    enable_server_push: bool,
}

impl H3ServerEndpoint {
    /// The local address this server endpoint is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] if the socket address cannot be
    /// retrieved.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, oxiquic_core::OxiQuicError> {
        self.endpoint.local_addr()
    }

    /// Whether server push was enabled in the builder.
    ///
    /// Note: h3 0.0.8 does not implement push. This flag is advisory only.
    #[must_use]
    pub fn server_push_enabled(&self) -> bool {
        self.enable_server_push
    }

    /// Accept the next incoming HTTP/3 connection.
    ///
    /// Performs the QUIC + HTTP/3 handshake and returns an [`H3Connection`]
    /// ready to accept requests.
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on connection failure or
    /// handshake error.
    pub async fn accept_connection(&self) -> Result<H3Connection, oxiquic_core::OxiQuicError> {
        let quic = self.endpoint.accept().await?;
        let driven = quic.into_driven();
        H3Connection::new_with_config(driven, self.max_field_section_size)
            .await
            .map_err(Into::into)
    }

    /// Return an async iterator over incoming HTTP/3 connections.
    ///
    /// Each call to [`H3Incoming::next`] performs a QUIC + HTTP/3 handshake
    /// and returns the next fully-established [`H3Connection`], or `None` if
    /// the endpoint has been closed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(server: oxiquic_h3::H3ServerEndpoint) {
    /// let incoming = server.incoming();
    /// while let Some(conn) = incoming.next().await {
    ///     tokio::spawn(async move { /* handle conn */ });
    /// }
    /// # }
    /// ```
    pub fn incoming(&self) -> H3Incoming<'_> {
        H3Incoming { server: self }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3Incoming — async iterator over accepted H3Connections
// ─────────────────────────────────────────────────────────────────────────────

/// An async iterator over incoming HTTP/3 connections.
///
/// Created by [`H3ServerEndpoint::incoming`]. Call [`H3Incoming::next`] to
/// accept connections one at a time without spawning a background task or
/// requiring the `Stream` trait.
///
/// # Lifetime
///
/// `H3Incoming` borrows the [`H3ServerEndpoint`] for its lifetime, so the
/// endpoint must outlive all `next()` calls.
pub struct H3Incoming<'a> {
    server: &'a H3ServerEndpoint,
}

impl<'a> H3Incoming<'a> {
    /// Accept the next incoming HTTP/3 connection.
    ///
    /// Performs the QUIC + HTTP/3 handshake. Returns `None` when the endpoint
    /// has been permanently closed (the background demux task has exited).
    pub async fn next(&self) -> Option<H3Connection> {
        self.server.accept_connection().await.ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3ServerBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`H3Server`].
///
/// At minimum you must supply a [`rustls::ServerConfig`] via
/// [`H3ServerBuilder::with_tls_config`] before calling [`H3ServerBuilder::build`].
///
/// # Example
///
/// ```ignore
/// let server = H3ServerBuilder::new("0.0.0.0:8443".parse()?)
///     .with_tls_config(rustls_server_config)
///     .with_max_field_section_size(32_768)
///     .with_server_push(false)
///     .build()
///     .await?;
/// ```
pub struct H3ServerBuilder {
    bind_addr: std::net::SocketAddr,
    tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    transport_config: Option<oxiquic_transport::TransportConfig>,
    max_field_section_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    enable_server_push: bool,
    /// Optional custom session ticket provider for TLS session resumption and 0-RTT.
    ticketer: Option<std::sync::Arc<dyn rustls::server::ProducesTickets>>,
}

impl H3ServerBuilder {
    /// Create a new builder bound to `bind_addr`.
    ///
    /// Call [`with_tls_config`][Self::with_tls_config] before [`build`][Self::build].
    #[must_use]
    pub fn new(bind_addr: std::net::SocketAddr) -> Self {
        Self {
            bind_addr,
            tls_config: None,
            transport_config: None,
            max_field_section_size: crate::message::DEFAULT_MAX_FIELD_SECTION_SIZE,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            enable_server_push: false,
            ticketer: None,
        }
    }

    /// Set the TLS configuration (required).
    ///
    /// ALPN `h3` is automatically prepended to `config.alpn_protocols` when
    /// [`build`][Self::build] is called.
    #[must_use]
    pub fn with_tls_config(mut self, config: rustls::ServerConfig) -> Self {
        self.tls_config = Some(std::sync::Arc::new(config));
        self
    }

    /// Override the bind address (overrides the address passed to [`new`][Self::new]).
    #[must_use]
    pub fn with_bind_address(mut self, addr: std::net::SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Override the QUIC transport configuration.
    #[must_use]
    pub fn with_transport_config(mut self, config: oxiquic_transport::TransportConfig) -> Self {
        self.transport_config = Some(config);
        self
    }

    /// Set a custom session ticket provider for TLS session resumption and 0-RTT.
    ///
    /// The ticketer is applied to the [`rustls::ServerConfig`] before binding the
    /// QUIC endpoint. Use `oxitls::OxiTicketer` for a pure-Rust AES-GCM-backed
    /// ticketer:
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use oxitls::OxiTicketer;
    /// builder.with_ticketer(Arc::new(OxiTicketer::new().expect("ticketer")));
    /// ```
    #[must_use]
    pub fn with_ticketer(
        mut self,
        ticketer: std::sync::Arc<dyn rustls::server::ProducesTickets>,
    ) -> Self {
        self.ticketer = Some(ticketer);
        self
    }

    /// Set `SETTINGS_MAX_FIELD_SECTION_SIZE` (default: 16 384 bytes).
    ///
    /// The server will reject HEADERS frames whose encoded size exceeds this
    /// value (RFC 9114 §7.2.4.1).
    #[must_use]
    pub fn with_max_field_section_size(mut self, size: u64) -> Self {
        self.max_field_section_size = size;
        self
    }

    /// Set `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (default: 0).
    #[must_use]
    pub fn with_qpack_max_table_capacity(mut self, capacity: u64) -> Self {
        self.qpack_max_table_capacity = capacity;
        self
    }

    /// Set `SETTINGS_QPACK_BLOCKED_STREAMS` (default: 0).
    #[must_use]
    pub fn with_qpack_blocked_streams(mut self, streams: u64) -> Self {
        self.qpack_blocked_streams = streams;
        self
    }

    /// Enable or disable server push (RFC 9114 §4.6).
    ///
    /// Note: h3 0.0.8 does not implement server push. This flag is advisory
    /// only and is surfaced via [`H3ServerEndpoint::server_push_enabled`].
    #[must_use]
    pub fn with_server_push(mut self, enabled: bool) -> Self {
        self.enable_server_push = enabled;
        self
    }

    /// Build and bind the [`H3ServerEndpoint`].
    ///
    /// Automatically injects `h3` into `alpn_protocols` if not already present.
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError::Tls`] if no TLS config was set.
    /// Returns [`oxiquic_core::OxiQuicError::Io`] if the UDP socket cannot be
    /// bound.
    pub async fn build(self) -> Result<H3ServerEndpoint, oxiquic_core::OxiQuicError> {
        use oxiquic_transport::ServerEndpoint;

        let mut tls = self.tls_config.ok_or_else(|| {
            oxiquic_core::OxiQuicError::Tls("H3ServerBuilder: tls_config is required".into())
        })?;
        let transport = self.transport_config.unwrap_or_default();

        // Inject `h3` ALPN if not already present, and apply optional ticketer.
        {
            let tls_ref = std::sync::Arc::make_mut(&mut tls);
            if !tls_ref.alpn_protocols.iter().any(|p| p == b"h3") {
                tls_ref.alpn_protocols.insert(0, b"h3".to_vec());
            }
            if let Some(ticketer) = self.ticketer {
                tls_ref.ticketer = ticketer;
            }
        }

        let endpoint = ServerEndpoint::bind(self.bind_addr, tls, transport).await?;
        Ok(H3ServerEndpoint {
            endpoint,
            max_field_section_size: self.max_field_section_size,
            enable_server_push: self.enable_server_push,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3RequestContext — single accepted request
// ─────────────────────────────────────────────────────────────────────────────

/// The context for a single accepted HTTP/3 request.
///
/// Holds the parsed request metadata and the underlying bidirectional stream.
/// Call [`H3RequestContext::request`] to inspect the request, optionally
/// [`H3RequestContext::body`] to read the request body, then either:
/// - [`H3RequestContext::respond`] for a simple response, or
/// - [`H3RequestContext::into_responder`] for a streaming [`H3Responder`].
pub struct H3RequestContext {
    request: H3Request,
    stream: h3::server::RequestStream<H3BidiStream, Bytes>,
}

impl H3RequestContext {
    /// The incoming request metadata (method, URI, headers).
    #[must_use]
    pub fn request(&self) -> &H3Request {
        &self.request
    }

    /// Read all request body bytes from the stream.
    ///
    /// Returns an empty [`Bytes`] when the client sent no body.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] on stream-level errors.
    pub async fn body(&mut self) -> Result<Bytes, H3Error> {
        let mut body = BytesMut::new();
        while let Some(mut chunk) = self
            .stream
            .recv_data()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?
        {
            body.put(chunk.copy_to_bytes(chunk.remaining()));
        }
        Ok(body.freeze())
    }

    /// Send `response` to the client and close the stream.
    ///
    /// Sends the status + headers, then the body (if non-empty), then
    /// finishes the stream.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] on protocol or stream errors.
    pub async fn respond(mut self, response: H3Response) -> Result<(), H3Error> {
        let status = http::StatusCode::from_u16(response.status())
            .map_err(|e| H3Error::Protocol(e.to_string()))?;
        let mut builder = http::Response::builder().status(status);
        for (name, value) in response.headers() {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_resp = builder
            .body(())
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        self.stream
            .send_response(http_resp)
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        let body = response.body_bytes();
        if !body.is_empty() {
            self.stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .map_err(|e| H3Error::Stream(e.to_string()))?;
        }

        self.stream
            .finish()
            .await
            .map_err(|e| H3Error::Stream(e.to_string()))?;

        Ok(())
    }

    /// Consume this context and return an [`H3Responder`] for streaming control.
    ///
    /// Use this when you need to send response headers, data, and trailers
    /// separately rather than as a single-shot response.
    #[must_use]
    pub fn into_responder(self) -> H3Responder {
        H3Responder {
            stream: self.stream,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3Responder — streaming response writer
// ─────────────────────────────────────────────────────────────────────────────

/// The response side of an HTTP/3 request/response exchange.
///
/// Obtained from [`H3RequestContext::into_responder`]. Provides fine-grained
/// control over response headers, DATA frames, trailing HEADERS, and stream
/// finish.  For a simple one-shot response, prefer [`H3RequestContext::respond`].
pub struct H3Responder {
    stream: h3::server::RequestStream<H3BidiStream, Bytes>,
}

impl H3Responder {
    /// Read all bytes from the request body DATA frames (RFC 9114 §4.1).
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on stream-level errors.
    pub async fn body_bytes(&mut self) -> Result<Bytes, oxiquic_core::OxiQuicError> {
        let mut buf = BytesMut::new();
        while let Some(mut data) = self
            .stream
            .recv_data()
            .await
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))?
        {
            buf.put(data.copy_to_bytes(data.remaining()));
        }
        Ok(buf.freeze())
    }

    /// Send HTTP response headers (RFC 9114 §4.1).
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on protocol or stream errors.
    pub async fn send_response(
        &mut self,
        status: http::StatusCode,
        headers: http::HeaderMap,
    ) -> Result<(), oxiquic_core::OxiQuicError> {
        let mut builder = http::Response::builder().status(status);
        // Safety: `builder` is newly constructed and has no error set yet.
        *builder.headers_mut().ok_or_else(|| {
            oxiquic_core::OxiQuicError::Protocol("response builder error before headers_mut".into())
        })? = headers;
        let resp = builder
            .body(())
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))?;
        self.stream
            .send_response(resp)
            .await
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))
    }

    /// Send a DATA frame (RFC 9114 §4.1).
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on stream write failure.
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), oxiquic_core::OxiQuicError> {
        self.stream
            .send_data(data)
            .await
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))
    }

    /// Send trailing HEADERS frame (RFC 9114 §4.1).
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on stream write failure.
    pub async fn send_trailers(
        &mut self,
        trailers: http::HeaderMap,
    ) -> Result<(), oxiquic_core::OxiQuicError> {
        self.stream
            .send_trailers(trailers)
            .await
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))
    }

    /// Finish the response stream (send FIN).
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on stream error.
    pub async fn finish(&mut self) -> Result<(), oxiquic_core::OxiQuicError> {
        self.stream
            .finish()
            .await
            .map_err(|e| oxiquic_core::OxiQuicError::Protocol(e.to_string()))
    }

    /// Convenience: send a complete single-shot response (headers + optional body + FIN).
    ///
    /// Equivalent to calling [`send_response`][Self::send_response],
    /// optionally [`send_data`][Self::send_data] if `body` is non-empty,
    /// then [`finish`][Self::finish].
    ///
    /// # Errors
    ///
    /// Returns [`oxiquic_core::OxiQuicError`] on any stream error.
    pub async fn send_full(
        &mut self,
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: Bytes,
    ) -> Result<(), oxiquic_core::OxiQuicError> {
        self.send_response(status, headers).await?;
        if !body.is_empty() {
            self.send_data(body).await?;
        }
        self.finish().await
    }

    /// Initiate a server push (RFC 9114 §4.6).
    ///
    /// # Limitations
    ///
    /// h3 0.0.8 does not support server push. This method always returns
    /// [`oxiquic_core::OxiQuicError::NotImplemented`] with an explanatory
    /// message. Upgrade to a newer h3 version for full push support.
    pub async fn push_promise(
        &mut self,
        _request: http::Request<()>,
    ) -> Result<crate::push::H3PushStream, oxiquic_core::OxiQuicError> {
        Err(oxiquic_core::OxiQuicError::NotImplemented(
            "server push requires h3 > 0.0.8 with MAX_PUSH_ID support".into(),
        ))
    }
}
