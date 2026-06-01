//! HTTP/3 client wrapper over OxiQUIC's [`DrivenConnection`].
//!
//! [`H3Client`] provides a high-level API for sending HTTP/3 requests over a
//! QUIC transport connection.
//!
//! For quick setup with sensible defaults use [`H3Client::new`]; for full
//! control over TLS configuration, transport parameters and per-client
//! HTTP/3 settings use [`H3ClientBuilder`].

// This entire file is only meaningful with the h3-compat feature.
#![cfg(feature = "h3-compat")]

use bytes::{Buf, Bytes, BytesMut};

use crate::error::H3Error;
use crate::message::{H3Request, H3Response, H3Settings};
use oxiquic_transport::endpoint::DrivenConnection;
use oxiquic_transport::{H3BidiStream, OxiQuicH3Connection, OxiQuicOpenStreams};

// ─────────────────────────────────────────────────────────────────────────────
// H3Client
// ─────────────────────────────────────────────────────────────────────────────

/// A high-level HTTP/3 client built on top of OxiQUIC.
///
/// Construct one with [`H3Client::new`] or [`H3ClientBuilder`], which
/// establishes the HTTP/3 handshake over the supplied [`DrivenConnection`].
/// Send requests with [`request`][H3Client::request], [`get`][H3Client::get],
/// [`post`][H3Client::post], [`head`][H3Client::head],
/// [`put`][H3Client::put], or [`delete`][H3Client::delete], and call
/// [`close`][H3Client::close] when done.
pub struct H3Client {
    h3_conn: h3::client::Connection<OxiQuicH3Connection, Bytes>,
    send_req: h3::client::SendRequest<OxiQuicOpenStreams, Bytes>,
    /// Default headers merged into every outgoing request.
    default_headers: Vec<(String, String)>,
    /// The locally-configured HTTP/3 settings (what we sent in our SETTINGS frame).
    local_settings: H3Settings,
}

impl H3Client {
    /// Establish an HTTP/3 client connection over an already-connected QUIC
    /// transport with default settings.
    ///
    /// This performs the HTTP/3 handshake (SETTINGS exchange, control-stream
    /// and QPACK-stream setup) and returns an [`H3Client`] ready to issue
    /// requests.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the HTTP/3 handshake fails or the underlying
    /// QUIC transport reports an error.
    pub async fn new(driven: DrivenConnection) -> Result<Self, H3Error> {
        Self::new_with_config(driven, 16_384, Vec::new()).await
    }

    /// Establish an HTTP/3 client connection with customised settings.
    ///
    /// `max_field_section_size` sets `SETTINGS_MAX_FIELD_SECTION_SIZE`
    /// (RFC 9114 §4.2.2).  `default_headers` is a list of `(name, value)`
    /// pairs prepended to every request.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the HTTP/3 handshake fails.
    pub async fn new_with_config(
        driven: DrivenConnection,
        max_field_section_size: u64,
        default_headers: Vec<(String, String)>,
    ) -> Result<Self, H3Error> {
        let conn = OxiQuicH3Connection::new(driven);
        let mut builder = h3::client::builder();
        builder.max_field_section_size(max_field_section_size);
        let (h3_conn, send_req) = builder
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
            send_req,
            default_headers,
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

    /// Send an HTTP/3 request and receive the full response.
    ///
    /// Default headers (set via [`H3ClientBuilder::with_default_headers`]) are
    /// prepended to the request before transmission.  An optional `body` may
    /// be supplied for methods that carry a request body (e.g. `POST`, `PUT`).
    /// The response headers and body are collected into an [`H3Response`]
    /// before returning.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request cannot be sent, the response cannot
    /// be received, or an I/O error occurs on the QUIC stream.
    pub async fn request(
        &mut self,
        req: H3Request,
        body: Option<Bytes>,
    ) -> Result<H3Response, H3Error> {
        // Record the trace event without holding an `EnteredSpan` guard across
        // any `.await` point: `EnteredSpan` is `!Send`, which breaks
        // `tokio::spawn` futures.
        #[cfg(feature = "tracing")]
        tracing::info!(
            method = %req.method(),
            uri = %req.uri(),
            "h3_request: sending",
        );
        // Convert H3Request → http::Request<()>, injecting default headers
        // first so per-request headers can override them.
        let mut builder = http::Request::builder().method(req.method()).uri(req.uri());
        for (name, value) in &self.default_headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        for (name, value) in req.headers() {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_req = builder
            .body(())
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        // Open the request stream and send headers.
        let mut req_stream = self
            .send_req
            .send_request(http_req)
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        // Send optional body data before finishing the stream.
        if let Some(b) = body {
            req_stream
                .send_data(b)
                .await
                .map_err(|e| H3Error::Stream(e.to_string()))?;
        }

        // Signal end-of-stream (no more data from client).
        req_stream
            .finish()
            .await
            .map_err(|e| H3Error::Stream(e.to_string()))?;

        // Receive response headers.
        let resp = req_stream
            .recv_response()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        // Collect response body chunks.
        let mut body_buf = BytesMut::new();
        while let Some(mut chunk) = req_stream
            .recv_data()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?
        {
            body_buf.extend_from_slice(chunk.chunk());
            let n = chunk.remaining();
            chunk.advance(n);
        }

        // Build H3Response from http::Response<()> + collected body.
        let status = resp.status().as_u16();
        let mut h3resp = H3Response::new(status);
        for (name, value) in resp.headers() {
            if let Ok(v) = value.to_str() {
                h3resp = h3resp.with_header(name.as_str(), v);
            }
        }
        Ok(h3resp.with_body(body_buf.to_vec()))
    }

    /// Send a `GET` request to `uri` and return the response.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request or response handling fails.
    pub async fn get(&mut self, uri: &str) -> Result<H3Response, H3Error> {
        self.request(H3Request::get(uri), None).await
    }

    /// Send a `POST` request to `uri` with the supplied `body`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request or response handling fails.
    pub async fn post(&mut self, uri: &str, body: Bytes) -> Result<H3Response, H3Error> {
        self.request(H3Request::post(uri), Some(body)).await
    }

    /// Send a `HEAD` request to `uri`.
    ///
    /// The server MUST NOT include a body in the response (RFC 9110 §9.3.2),
    /// though headers are still returned.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request or response handling fails.
    pub async fn head(&mut self, uri: &str) -> Result<H3Response, H3Error> {
        self.request(H3Request::new("HEAD", uri), None).await
    }

    /// Send a `PUT` request to `uri` with the supplied `body`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request or response handling fails.
    pub async fn put(&mut self, uri: &str, body: impl Into<Bytes>) -> Result<H3Response, H3Error> {
        self.request(H3Request::new("PUT", uri), Some(body.into()))
            .await
    }

    /// Send a `DELETE` request to `uri`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request or response handling fails.
    pub async fn delete(&mut self, uri: &str) -> Result<H3Response, H3Error> {
        self.request(H3Request::new("DELETE", uri), None).await
    }

    /// Open a streaming request/response pair for incremental body transfer.
    ///
    /// Unlike [`request`][H3Client::request], which collects the full response
    /// body before returning, `send_streaming` returns a [`RequestStream`] that
    /// lets the caller send body data incrementally and read the response in
    /// chunks.
    ///
    /// Default headers (set via [`H3ClientBuilder::with_default_headers`]) are
    /// still applied before the request is sent.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request stream cannot be opened.
    pub async fn send_streaming(&mut self, req: H3Request) -> Result<RequestStream, H3Error> {
        let mut builder = http::Request::builder().method(req.method()).uri(req.uri());
        for (name, value) in &self.default_headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        for (name, value) in req.headers() {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_req = builder
            .body(())
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        let inner = self
            .send_req
            .send_request(http_req)
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?;

        Ok(RequestStream { inner })
    }

    /// Deserialize the response body as JSON (requires the `serde` feature).
    ///
    /// Convenience wrapper that sends a `GET` request and deserialises the
    /// response body via `serde_json`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the request fails or the body cannot be decoded
    /// as JSON.
    #[cfg(feature = "serde")]
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &mut self,
        uri: &str,
    ) -> Result<T, H3Error> {
        self.get(uri).await?.body_json()
    }

    /// Send a `POST` request with a JSON-serialised body (requires `serde`).
    ///
    /// The `content-type` header is set to `application/json`.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if JSON serialisation fails or the request fails.
    #[cfg(feature = "serde")]
    pub async fn post_json<T: serde::Serialize>(
        &mut self,
        uri: &str,
        body: &T,
    ) -> Result<H3Response, H3Error> {
        let bytes =
            serde_json::to_vec(body).map_err(|e| H3Error::Protocol(format!("JSON encode: {e}")))?;
        let req = H3Request::new("POST", uri).with_header("content-type", "application/json");
        self.request(req, Some(Bytes::from(bytes))).await
    }

    /// Gracefully shut down the HTTP/3 connection.
    ///
    /// Sends a `GOAWAY` frame with the given stream ID (0 = "no more
    /// requests") to the peer and awaits the connection close.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if the shutdown fails.
    pub async fn close(mut self) -> Result<(), H3Error> {
        self.h3_conn
            .shutdown(0)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RequestStream
// ─────────────────────────────────────────────────────────────────────────────

/// A streaming HTTP/3 request/response pair.
///
/// Obtained via [`H3Client::send_streaming`].  Allows sending request data
/// incrementally and reading the response body in chunks without buffering the
/// entire body in memory.
///
/// # Usage
///
/// 1. Optionally call [`send_data`][RequestStream::send_data] one or more
///    times to transmit the request body.
/// 2. Call [`finish`][RequestStream::finish] to signal end-of-stream.
/// 3. Call [`recv_response`][RequestStream::recv_response] to get the status
///    and headers.
/// 4. Call [`recv_data`][RequestStream::recv_data] in a loop until it returns
///    `Ok(None)`.
/// 5. Optionally call [`recv_trailers`][RequestStream::recv_trailers] for
///    trailing headers.
pub struct RequestStream {
    inner: h3::client::RequestStream<H3BidiStream, Bytes>,
}

impl RequestStream {
    /// Send a chunk of request body data.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Stream`] if the stream has been reset or closed.
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), H3Error> {
        self.inner
            .send_data(data)
            .await
            .map_err(|e| H3Error::Stream(e.to_string()))
    }

    /// Finish the request stream — signals end-of-stream to the server.
    ///
    /// Must be called after all body data has been sent.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Stream`] on failure.
    pub async fn finish(&mut self) -> Result<(), H3Error> {
        self.inner
            .finish()
            .await
            .map_err(|e| H3Error::Stream(e.to_string()))
    }

    /// Receive the HTTP response status and headers.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] if the server sends an invalid response.
    pub async fn recv_response(&mut self) -> Result<http::Response<()>, H3Error> {
        self.inner
            .recv_response()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))
    }

    /// Receive the next chunk of response body data.
    ///
    /// Returns `Ok(None)` when the body is complete.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] on a framing or stream error.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>, H3Error> {
        match self
            .inner
            .recv_data()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))?
        {
            Some(mut buf) => {
                let b = buf.copy_to_bytes(buf.remaining());
                Ok(Some(b))
            }
            None => Ok(None),
        }
    }

    /// Receive trailing headers after the body.
    ///
    /// Returns `Ok(None)` if no trailers are present.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] if the trailers are malformed.
    pub async fn recv_trailers(&mut self) -> Result<Option<http::HeaderMap>, H3Error> {
        self.inner
            .recv_trailers()
            .await
            .map_err(|e| H3Error::Protocol(e.to_string()))
    }

    /// Cancel this request stream.
    ///
    /// Sends `STOP_SENDING` with `H3_REQUEST_CANCELLED` (RFC 9114 §8.1) to
    /// signal to the server that this request is being abandoned.
    pub fn cancel(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// H3ClientBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`H3Client`] with full HTTP/3 configuration.
///
/// Provides control over TLS configuration, QUIC transport parameters, and
/// HTTP/3 settings (RFC 9114 §7.2.4 / RFC 9204 §5) before opening the
/// connection.
///
/// # Example
///
/// ```ignore
/// let client = H3ClientBuilder::new()
///     .with_server_name("example.com")
///     .with_tls_config(my_rustls_client_config)
///     .with_max_field_section_size(8_192)
///     .connect("93.184.216.34:443".parse().unwrap())
///     .await?;
/// ```
pub struct H3ClientBuilder {
    server_name: Option<String>,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
    transport_config: Option<oxiquic_transport::TransportConfig>,
    /// RFC 9114 §4.2.2: maximum size of encoded field section (default 16384).
    max_field_section_size: u64,
    /// RFC 9204: QPACK max dynamic table capacity (stored for forward-compat).
    qpack_max_table_capacity: u64,
    /// RFC 9204: QPACK max blocked streams (stored for forward-compat).
    qpack_blocked_streams: u64,
    /// Default headers prepended to every request.
    default_headers: Vec<(String, String)>,
}

impl Default for H3ClientBuilder {
    fn default() -> Self {
        Self {
            server_name: None,
            tls_config: None,
            transport_config: None,
            max_field_section_size: 16_384,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            default_headers: Vec::new(),
        }
    }
}

impl H3ClientBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the TLS server name used for certificate validation.
    ///
    /// This field is **required** before calling [`connect`][Self::connect].
    #[must_use]
    pub fn with_server_name(mut self, name: &str) -> Self {
        self.server_name = Some(name.to_owned());
        self
    }

    /// Set the rustls [`ClientConfig`][rustls::ClientConfig].
    ///
    /// This field is **required** before calling [`connect`][Self::connect].
    /// The `h3` ALPN token is injected automatically if not already present.
    #[must_use]
    pub fn with_tls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.tls_config = Some(std::sync::Arc::new(config));
        self
    }

    /// Override the QUIC transport configuration.
    #[must_use]
    pub fn with_transport_config(mut self, config: oxiquic_transport::TransportConfig) -> Self {
        self.transport_config = Some(config);
        self
    }

    /// Set `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2).
    ///
    /// Controls the maximum size (in bytes) of the encoded header field
    /// section the client is willing to receive.  Default is 16 384.
    #[must_use]
    pub fn with_max_field_section_size(mut self, size: u64) -> Self {
        self.max_field_section_size = size;
        self
    }

    /// Configure QPACK dynamic table parameters (RFC 9204 §5).
    ///
    /// Note: h3 0.0.8 uses stateless QPACK; these values are stored for
    /// forward-compatibility but the dynamic table is always disabled in
    /// practice.
    #[must_use]
    pub fn with_qpack_config(mut self, max_table: u64, blocked_streams: u64) -> Self {
        self.qpack_max_table_capacity = max_table;
        self.qpack_blocked_streams = blocked_streams;
        self
    }

    /// Set default headers that are prepended to every request sent by the
    /// resulting [`H3Client`].
    ///
    /// Per-request headers added via [`H3Request::with_header`] may override
    /// these defaults (last-write wins at the HTTP/3 layer).
    #[must_use]
    pub fn with_default_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.default_headers = headers;
        self
    }

    /// Connect to an HTTP/3 server at `addr`.
    ///
    /// Steps:
    /// 1. Bind an ephemeral UDP socket.
    /// 2. Inject the `h3` ALPN token into the TLS config if absent (RFC 9114 §3.3).
    /// 3. Perform the QUIC handshake.
    /// 4. Enforce that the negotiated ALPN is `h3`.
    /// 5. Perform the HTTP/3 handshake (control stream + SETTINGS frame).
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] on bind failure, QUIC handshake failure, ALPN
    /// mismatch, or HTTP/3 handshake failure.
    pub async fn connect(self, addr: std::net::SocketAddr) -> Result<H3Client, H3Error> {
        let server_name = self.server_name.ok_or_else(|| {
            H3Error::Connection("H3ClientBuilder: server_name is required".into())
        })?;
        let mut tls = self
            .tls_config
            .ok_or_else(|| H3Error::Tls("H3ClientBuilder: tls_config is required".into()))?;
        let transport = self.transport_config.unwrap_or_default();

        // Inject `h3` ALPN if the config doesn't already include it
        // (RFC 9114 §3.3 requires ALPN negotiation).
        let tls_ref = std::sync::Arc::make_mut(&mut tls);
        if !tls_ref.alpn_protocols.iter().any(|p| p == b"h3") {
            tls_ref.alpn_protocols.insert(0, b"h3".to_vec());
        }

        let bind_addr: std::net::SocketAddr = ([0u8, 0, 0, 0], 0u16).into();
        let ep = oxiquic_transport::ClientEndpoint::bind(bind_addr, tls, transport)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))?;
        let quic = ep
            .connect(addr, &server_name)
            .await
            .map_err(|e| H3Error::Connection(e.to_string()))?;

        // Enforce ALPN == "h3" (RFC 9114 §3.3).
        if let Some(alpn) = quic.negotiated_alpn() {
            if alpn != b"h3" {
                return Err(H3Error::Protocol(format!(
                    "ALPN mismatch: expected h3, got {}",
                    String::from_utf8_lossy(&alpn)
                )));
            }
        }

        let driven = quic.into_driven();

        // The QPACK fields are stored in the builder for forward-compatibility
        // (h3 0.0.8 always uses a zero-capacity dynamic table, so there is no
        // runtime setter to call).
        let _ = (self.qpack_max_table_capacity, self.qpack_blocked_streams);

        H3Client::new_with_config(driven, self.max_field_section_size, self.default_headers).await
    }
}
