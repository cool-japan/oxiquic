//! HTTP/3 settings, requests and responses (RFC 9114).

use crate::error::H3Error;

/// The default `SETTINGS_MAX_FIELD_SECTION_SIZE` value used by OxiQUIC when the
/// peer advertises no limit. RFC 9114 leaves the default unlimited; OxiQUIC
/// applies a conservative 16 KiB cap.
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16_384;

/// HTTP/3 connection settings exchanged on the control stream
/// (RFC 9114 Section 7.2.4 / RFC 9204 Section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Settings {
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`: the largest header section the
    /// endpoint will accept, in bytes (RFC 9114 Section 7.2.4.1).
    pub max_field_section_size: u64,
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the QPACK dynamic-table capacity
    /// the endpoint will use, in bytes (RFC 9204 Section 5; default 0).
    pub qpack_max_table_capacity: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`: the number of streams that may be
    /// blocked on QPACK decoding (RFC 9204 Section 5; default 0).
    pub qpack_blocked_streams: u64,
}

impl Default for H3Settings {
    /// The OxiQUIC defaults: a 16 KiB field-section cap and QPACK dynamic table
    /// disabled (capacity and blocked-streams both zero), which is the simplest
    /// interoperable configuration.
    fn default() -> Self {
        Self {
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        }
    }
}

/// An HTTP/3 request's control information (RFC 9114 Section 4.1).
///
/// Pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`) are modelled as
/// dedicated fields; ordinary header fields are stored as lowercase
/// name/value pairs as required by RFC 9114 Section 4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Request {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
}

impl H3Request {
    /// Construct a request from a method and target URI.
    #[must_use]
    pub fn new(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            headers: Vec::new(),
        }
    }

    /// Construct a `GET` request for the given URI.
    #[must_use]
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new("GET", uri)
    }

    /// Construct a `POST` request for the given URI.
    #[must_use]
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new("POST", uri)
    }

    /// Append a header field. The name is lowercased per RFC 9114 Section 4.2.
    #[must_use]
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.as_ref().to_ascii_lowercase(), value.into()));
        self
    }

    /// The request method (`:method`).
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target URI (`:path` / `:authority`).
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The request header fields as lowercase name/value pairs.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

/// An HTTP/3 response (RFC 9114 Section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl H3Response {
    /// Construct a response with the given status code and an empty body.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Append a response header field (name lowercased per RFC 9114).
    #[must_use]
    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.as_ref().to_ascii_lowercase(), value.into()));
        self
    }

    /// Set the response body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response header fields as lowercase name/value pairs.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The raw response body bytes.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response, returning the body bytes.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// The response body decoded as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] if the body is not valid UTF-8.
    pub fn body_text(&self) -> Result<String, H3Error> {
        String::from_utf8(self.body.clone())
            .map_err(|e| H3Error::Protocol(format!("response body is not valid UTF-8: {e}")))
    }

    /// The first value of the named header, if present (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let lname = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == lname)
            .map(|(_, v)| v.as_str())
    }

    /// The `content-length` header parsed as an integer, if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// The `content-type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Whether the status code is in the 2xx success range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Returns `true` if the HTTP status code is in the 200-299 range.
    ///
    /// This is an alias for [`is_success`](Self::is_success).
    #[must_use]
    pub fn ok(&self) -> bool {
        self.is_success()
    }

    /// Return `self` if the status is successful (2xx), or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] if the HTTP status code indicates an error.
    pub fn error_for_status(self) -> Result<Self, H3Error> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(H3Error::Protocol(format!("HTTP error: {}", self.status)))
        }
    }

    /// Deserialize the response body as JSON.
    ///
    /// Requires the `serde` feature flag.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error::Protocol`] if the body is not valid JSON or
    /// deserialization fails.
    #[cfg(feature = "serde")]
    pub fn body_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, H3Error> {
        serde_json::from_slice(&self.body)
            .map_err(|e| H3Error::Protocol(format!("JSON decode: {e}")))
    }
}
