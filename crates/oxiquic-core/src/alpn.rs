//! Well-known ALPN protocol identifiers and helpers for OxiQUIC.
//!
//! This module provides byte-string constants for common QUIC ALPN identifiers
//! and a convenience function for building owned protocol lists from slices.
//!
//! # Example
//!
//! ```
//! use oxiquic_core::alpn;
//!
//! // Use the well-known H3 constant.
//! assert_eq!(alpn::H3, b"h3");
//!
//! // Build an owned list from byte-string literals.
//! let list = alpn::protocols(&[b"my-app/1.0", b"my-app/1.1"]);
//! assert_eq!(list.len(), 2);
//! assert_eq!(list[0], b"my-app/1.0");
//! ```

/// HTTP/3 over QUIC (RFC 9114 §3.3).
pub const H3: &[u8] = b"h3";

/// HTTP/0.9 interoperability shim used in IETF QUIC interop testing.
pub const HTTP_0_9: &[u8] = b"hq-interop";

/// Build an owned ALPN protocol list from byte-string slices.
///
/// Converts a slice of byte-string literals into a `Vec<Vec<u8>>` suitable for
/// passing to `rustls::ClientConfig::alpn_protocols` or
/// `rustls::ServerConfig::alpn_protocols`.
///
/// # Example
///
/// ```
/// use oxiquic_core::alpn;
///
/// let list = alpn::protocols(&[b"my-proto/1.0", b"my-proto/1.1"]);
/// assert_eq!(list.len(), 2);
/// assert_eq!(list[0].as_slice(), b"my-proto/1.0");
/// assert_eq!(list[1].as_slice(), b"my-proto/1.1");
/// ```
#[must_use]
pub fn protocols(list: &[&[u8]]) -> Vec<Vec<u8>> {
    list.iter().map(|p| p.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_constant_is_correct() {
        assert_eq!(H3, b"h3");
    }

    #[test]
    fn http_0_9_constant_is_correct() {
        assert_eq!(HTTP_0_9, b"hq-interop");
    }

    #[test]
    fn protocols_builds_correct_list() {
        let list = protocols(&[b"proto-a", b"proto-b", b"proto-c"]);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], b"proto-a");
        assert_eq!(list[1], b"proto-b");
        assert_eq!(list[2], b"proto-c");
    }

    #[test]
    fn protocols_empty_list() {
        let list = protocols(&[]);
        assert!(list.is_empty());
    }

    #[test]
    fn protocols_single_entry() {
        let list = protocols(&[H3]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], b"h3");
    }
}
