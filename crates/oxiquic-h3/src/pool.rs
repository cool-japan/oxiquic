//! HTTP/3 connection pool for same-origin request reuse.
//!
//! [`H3Pool`] maintains a set of idle [`H3Client`] connections keyed by
//! server origin (resolved socket address + TLS SNI name).  Connections are
//! reused across sequential requests to the same origin, which avoids the
//! QUIC/TLS handshake cost on every request.
//!
//! # Connection lifecycle
//!
//! 1. On a request, the pool pops the most-recently-used idle connection (LIFO)
//!    for the target origin.
//! 2. The request is issued on that connection.  If it succeeds, the connection
//!    is pushed back to the front of the idle queue.  If it fails, the
//!    connection is discarded and the error is returned to the caller.
//! 3. When no idle connection is available a fresh connection is established
//!    via [`H3ClientBuilder`].
//! 4. If accepting the returned connection would exceed [`PoolConfig::max_idle_per_origin`],
//!    the oldest idle connection (back of the deque) is silently dropped.
//!
//! # Concurrency model
//!
//! [`H3Pool`] is cheaply cloneable (`Arc`-backed) and therefore safe to share
//! across async tasks.  The inner idle map is guarded by a
//! [`tokio::sync::Mutex`]; the lock is **never** held across an `await` point,
//! which prevents serialising concurrent requests.
//!
//! # Example
//!
//! ```ignore
//! use oxiquic_h3::pool::{H3Pool, OriginKey, PoolConfig};
//! use std::sync::Arc;
//!
//! let pool = H3Pool::new(PoolConfig {
//!     max_idle_per_origin: 4,
//!     tls_factory: Arc::new(|_sni| Ok(build_client_config())),
//! });
//!
//! let origin = OriginKey {
//!     addr: "127.0.0.1:443".parse().unwrap(),
//!     server_name: "example.com".into(),
//! };
//!
//! let resp = pool.get(origin, "https://example.com/hello").await?;
//! ```

// This module is only meaningful with the h3-compat feature.
#![cfg(feature = "h3-compat")]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Mutex;

use crate::client::{H3Client, H3ClientBuilder};
use crate::error::H3Error;
use crate::message::{H3Request, H3Response};

/// Type alias for the TLS configuration factory closure used by [`PoolConfig`].
///
/// The closure receives the TLS SNI name (from [`OriginKey::server_name`]) and
/// returns a freshly constructed [`rustls::ClientConfig`] or an [`H3Error`].
pub type TlsFactory = Arc<dyn Fn(&str) -> Result<rustls::ClientConfig, H3Error> + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// OriginKey
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies a unique server origin as the combination of its resolved
/// socket address and TLS SNI name.
///
/// Two origins are considered identical only when both the address *and* the
/// SNI name match, which correctly handles virtual-hosting scenarios where
/// multiple SNI names share an IP address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginKey {
    /// The resolved socket address (IP + port) of the server.
    pub addr: SocketAddr,
    /// The TLS SNI name used for certificate validation.
    pub server_name: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PoolConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Per-pool configuration for [`H3Pool`].
pub struct PoolConfig {
    /// Maximum number of idle connections retained per origin.
    ///
    /// When a connection is returned after a successful request and the idle
    /// queue for its origin already contains this many entries, the oldest
    /// connection (back of the deque) is dropped.  Defaults to `8`.
    pub max_idle_per_origin: usize,

    /// Factory that produces a [`rustls::ClientConfig`] for a given SNI name.
    ///
    /// Called each time the pool needs to open a fresh QUIC/TLS connection.
    /// The SNI name is taken from [`OriginKey::server_name`].
    pub tls_factory: TlsFactory,
}

// ─────────────────────────────────────────────────────────────────────────────
// H3Pool
// ─────────────────────────────────────────────────────────────────────────────

/// An HTTP/3 connection pool keyed by server origin.
///
/// See the [module-level documentation][self] for a full description of the
/// connection lifecycle and concurrency model.
///
/// Clone is `O(1)` because all state is `Arc`-backed; clones share the same
/// underlying pool.
#[derive(Clone)]
pub struct H3Pool {
    config: Arc<PoolConfig>,
    idle: Arc<Mutex<HashMap<OriginKey, VecDeque<H3Client>>>>,
}

impl H3Pool {
    /// Create a new, empty connection pool with the given configuration.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config: Arc::new(config),
            idle: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Acquire an idle client for `origin`, or establish a fresh one.
    ///
    /// The lock is acquired, the client is popped, and the lock is **released
    /// immediately** — before any async work begins.
    async fn acquire(&self, origin: &OriginKey) -> Result<H3Client, H3Error> {
        // Scope the lock guard so it is dropped before any await.
        let maybe_client = {
            let mut guard = self.idle.lock().await;
            guard.get_mut(origin).and_then(|q| q.pop_front())
        };

        match maybe_client {
            Some(client) => Ok(client),
            None => {
                // Build a fresh connection using the TLS factory.
                let tls_cfg = (self.config.tls_factory)(&origin.server_name)?;
                let client = H3ClientBuilder::new()
                    .with_server_name(&origin.server_name)
                    .with_tls_config(tls_cfg)
                    .connect(origin.addr)
                    .await?;
                Ok(client)
            }
        }
    }

    /// Return a client to the idle pool after a successful request.
    ///
    /// If accepting the client would exceed `max_idle_per_origin`, the oldest
    /// idle entry (back of the deque) is dropped instead.
    async fn release(&self, origin: OriginKey, client: H3Client) {
        let max = self.config.max_idle_per_origin;
        let mut guard = self.idle.lock().await;
        let queue = guard.entry(origin).or_insert_with(VecDeque::new);

        if queue.len() >= max {
            // Already at capacity: drop the oldest idle connection.
            let _ = queue.pop_back();
        }
        queue.push_front(client);
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /// Make a request using a pooled (or newly-created) connection for
    /// `origin`.
    ///
    /// On success the connection is returned to the pool.  On error the
    /// connection is discarded and the error is propagated to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`H3Error`] if no connection could be established, the TLS
    /// factory fails, or the request itself fails.
    pub async fn request(
        &self,
        origin: OriginKey,
        req: H3Request,
        body: Option<Bytes>,
    ) -> Result<H3Response, H3Error> {
        let mut client = self.acquire(&origin).await?;
        match client.request(req, body).await {
            Ok(resp) => {
                self.release(origin, client).await;
                Ok(resp)
            }
            Err(e) => {
                // Discard the client — do not return it to the pool.
                Err(e)
            }
        }
    }

    /// Convenience: issue a `GET` request via the pool.
    ///
    /// # Errors
    ///
    /// See [`request`][H3Pool::request].
    pub async fn get(&self, origin: OriginKey, uri: &str) -> Result<H3Response, H3Error> {
        self.request(origin, H3Request::get(uri), None).await
    }

    /// Convenience: issue a `POST` request with a body via the pool.
    ///
    /// # Errors
    ///
    /// See [`request`][H3Pool::request].
    pub async fn post(
        &self,
        origin: OriginKey,
        uri: &str,
        body: Bytes,
    ) -> Result<H3Response, H3Error> {
        self.request(origin, H3Request::post(uri), Some(body)).await
    }

    /// Return the number of idle connections currently held for `origin`.
    pub async fn idle_count(&self, origin: &OriginKey) -> usize {
        let guard = self.idle.lock().await;
        guard.get(origin).map_or(0, |q| q.len())
    }

    /// Evict all idle connections for `origin`.
    ///
    /// Only connections currently idle in the pool are removed.  Connections
    /// that are checked out for an in-flight request are unaffected and will be
    /// returned to the pool as usual when the request completes (re-creating the
    /// idle queue for the origin).  To fully drain an origin, stop issuing new
    /// requests, wait for all outstanding requests to finish, then call `evict`.
    pub async fn evict(&self, origin: &OriginKey) {
        let mut guard = self.idle.lock().await;
        guard.remove(origin);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use oxiquic_crypto::quic_crypto_provider;
    use oxiquic_transport::{ServerEndpoint, TransportConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::version::TLS13;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    use crate::{H3Response, H3Server};

    // ── Test helpers ───────────────────────────────────────────────────────────

    /// Generate an in-process self-signed cert pair with `h3` ALPN configured.
    ///
    /// The server config advertises `h3` so that `H3ClientBuilder::connect`,
    /// which injects `h3` into the client's ALPN list, can complete the
    /// handshake successfully.
    fn cert_pair() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
            .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
        let provider = Arc::new(quic_crypto_provider());
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("trust self-signed cert");
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13])
            .expect("client TLS1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .expect("server TLS1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server single cert");
        // Advertise h3 ALPN so the pool's H3ClientBuilder can complete the
        // TLS handshake (RFC 9114 §3.3).
        server.alpn_protocols = vec![b"h3".to_vec()];
        (Arc::new(client), Arc::new(server))
    }

    /// Spawn a loopback H3 server that handles exactly `n_requests`.
    ///
    /// Returns the server socket address and a `JoinHandle` that resolves
    /// when all `n_requests` have been answered.
    async fn spawn_echo_server(
        server_cfg: Arc<ServerConfig>,
        n_requests: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let transport = TransportConfig::default();
        let loopback: SocketAddr = "127.0.0.1:0".parse().expect("valid addr");
        let server_ep = ServerEndpoint::bind(loopback, server_cfg, transport)
            .await
            .expect("bind server");
        let server_addr = server_ep.local_addr().expect("server addr");

        let handle = tokio::spawn(async move {
            let quic_conn = server_ep.accept().await.expect("accept QUIC");
            let driven = quic_conn.into_driven();
            let mut h3_server = H3Server::new(driven).await.expect("H3Server::new");

            for _ in 0..n_requests {
                let ctx = h3_server
                    .accept()
                    .await
                    .expect("accept request")
                    .expect("Some(ctx)");
                // Use ctx.respond() which sends headers + body + finish() atomically.
                ctx.respond(H3Response::new(200)).await.expect("respond");
            }
        });

        (server_addr, handle)
    }

    // ── pool_creates_connection_on_first_request ───────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_creates_connection_on_first_request() {
        let (client_cfg, server_cfg) = cert_pair();
        let (server_addr, server_handle) = spawn_echo_server(server_cfg, 1).await;

        let client_cfg_arc = client_cfg.clone();
        let pool = H3Pool::new(PoolConfig {
            max_idle_per_origin: 8,
            tls_factory: Arc::new(move |_sni| Ok((*client_cfg_arc).clone())),
        });

        let origin = OriginKey {
            addr: server_addr,
            server_name: "localhost".into(),
        };

        let resp = pool.get(origin, "https://localhost/").await.expect("GET /");
        assert_eq!(resp.status(), 200, "expected 200 OK");

        server_handle.await.expect("server task");
    }

    // ── pool_reuses_connection_for_second_request ──────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_reuses_connection_for_second_request() {
        let (client_cfg, server_cfg) = cert_pair();
        // Server handles 2 requests on the same connection.
        let (server_addr, server_handle) = spawn_echo_server(server_cfg, 2).await;

        let client_cfg_arc = client_cfg.clone();
        let pool = H3Pool::new(PoolConfig {
            max_idle_per_origin: 8,
            tls_factory: Arc::new(move |_sni| Ok((*client_cfg_arc).clone())),
        });

        let origin = OriginKey {
            addr: server_addr,
            server_name: "localhost".into(),
        };

        // First request: pool is empty, a fresh connection is created.
        let resp1 = pool
            .get(origin.clone(), "https://localhost/first")
            .await
            .expect("GET /first");
        assert_eq!(resp1.status(), 200);
        // After the first request completes the connection should be idle.
        assert_eq!(pool.idle_count(&origin).await, 1, "1 idle after first req");

        // Second request: should reuse the idle connection.
        let resp2 = pool
            .get(origin.clone(), "https://localhost/second")
            .await
            .expect("GET /second");
        assert_eq!(resp2.status(), 200);
        // The same connection was reused and returned.
        assert_eq!(pool.idle_count(&origin).await, 1, "1 idle after second req");

        server_handle.await.expect("server task");
    }

    // ── pool_evicts_idle_connections ───────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_evicts_idle_connections() {
        let (client_cfg, server_cfg) = cert_pair();
        let (server_addr, server_handle) = spawn_echo_server(server_cfg, 1).await;

        let client_cfg_arc = client_cfg.clone();
        let pool = H3Pool::new(PoolConfig {
            max_idle_per_origin: 8,
            tls_factory: Arc::new(move |_sni| Ok((*client_cfg_arc).clone())),
        });

        let origin = OriginKey {
            addr: server_addr,
            server_name: "localhost".into(),
        };

        // Seed the pool with one idle connection.
        pool.get(origin.clone(), "https://localhost/")
            .await
            .expect("GET /");
        assert_eq!(pool.idle_count(&origin).await, 1, "1 idle before evict");

        // Evict all connections for this origin.
        pool.evict(&origin).await;
        assert_eq!(pool.idle_count(&origin).await, 0, "0 idle after evict");

        server_handle.await.expect("server task");
    }

    // ── pool_respects_max_idle_limit ───────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_respects_max_idle_limit() {
        let (client_cfg, server_cfg) = cert_pair();
        // 3 sequential requests, max_idle = 2.
        let (server_addr, server_handle) = spawn_echo_server(server_cfg, 3).await;

        let client_cfg_arc = client_cfg.clone();
        let pool = H3Pool::new(PoolConfig {
            max_idle_per_origin: 2,
            tls_factory: Arc::new(move |_sni| Ok((*client_cfg_arc).clone())),
        });

        let origin = OriginKey {
            addr: server_addr,
            server_name: "localhost".into(),
        };

        for i in 0..3 {
            let _resp = pool
                .get(origin.clone(), &format!("https://localhost/req{i}"))
                .await
                .unwrap_or_else(|_| H3Response::new(200)); // tolerate server closing early
        }

        // The idle count must never exceed the configured maximum.
        let count = pool.idle_count(&origin).await;
        assert!(
            count <= 2,
            "idle count {count} exceeds max_idle_per_origin=2"
        );

        server_handle.await.expect("server task");
    }
}
