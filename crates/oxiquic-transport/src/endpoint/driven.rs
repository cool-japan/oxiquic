//! Background-driven QUIC connection: [`DrivenConnection`], the channel bundle
//! `DrivenConnectionChannels`, and the `run_driven_connection` task.
//!
//! This module is the async I/O loop that services a [`crate::connection::Connection`]
//! state machine from a dedicated `tokio` task.  It is obtained by calling
//! [`super::QuicConnection::into_driven`].

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep_until;

use oxiquic_core::Direction;
use oxiquic_core::{OxiQuicError, StreamId};

use crate::connection::Connection;
use crate::handle::{RecvStreamHandle, SendStreamHandle, WriteCmd, WriteTx};

use super::{recv_inbound, InboundSource, OpenStreamSender, OptOpenRx, RECV_BUF};

// ─────────────────────────────────────────────────────────────────────────────
// DrivenConnection
// ─────────────────────────────────────────────────────────────────────────────

/// A QUIC connection whose I/O loop runs in a background [`tokio::task`].
///
/// Obtained from [`super::QuicConnection::into_driven`]. The driver task owns
/// the UDP socket and the [`Connection`] state machine and is the single thread
/// of execution for all protocol state changes. Application code communicates
/// with it through bounded channels.
///
/// Drop this value to cancel the background task (the `JoinHandle` is
/// dropped which aborts the task on the next poll). To close the connection
/// gracefully, call [`DrivenConnection::close`] first.
///
/// `DrivenConnection` is `Clone`: cloning shares the same background task and
/// all channel handles, so multiple clones drive the same connection.
#[derive(Clone)]
pub struct DrivenConnection {
    pub(super) write_tx: WriteTx,
    pub(super) open_tx: mpsc::Sender<oneshot::Sender<(StreamId, mpsc::Receiver<Vec<u8>>)>>,
    pub(super) open_uni_tx: mpsc::Sender<oneshot::Sender<(StreamId, mpsc::Receiver<Vec<u8>>)>>,
    pub(super) close_tx: mpsc::Sender<(u64, Vec<u8>)>,
    /// Incoming bidirectional streams opened by the peer.
    pub(super) accept_bidi_rx:
        Arc<tokio::sync::Mutex<mpsc::Receiver<(SendStreamHandle, RecvStreamHandle)>>>,
    /// Incoming unidirectional streams opened by the peer.
    pub(super) accept_uni_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<RecvStreamHandle>>>,
    /// Holds the background task alive. Dropped when all `DrivenConnection`
    /// clones are dropped, which aborts the task if it has not already finished.
    pub(super) _task: Arc<tokio::task::JoinHandle<()>>,
    /// ALPN protocol negotiated during the TLS handshake, captured at
    /// [`super::QuicConnection::into_driven`] time when the handshake is
    /// already complete.
    pub(super) negotiated_alpn: Option<Vec<u8>>,
    /// The remote peer address, captured from the [`ConnectionDriver`] before
    /// the connection moves into the background task. `None` only if the
    /// handshake completed before the driver learned the peer address (not
    /// possible in normal operation).
    pub(super) peer_addr: Option<SocketAddr>,
    /// Shared closed-flag set to `true` by the driver task immediately before it
    /// exits (both on graceful close and on I/O error). Callers may read this as
    /// a *liveness hint*: a `true` value is definitive (the driver has exited),
    /// but `false` only means the driver has not yet set the flag — it may still
    /// be in the process of shutting down.
    ///
    /// The flag is written with [`Ordering::Release`] and read with
    /// [`Ordering::Acquire`] so that observers on other threads that see `true`
    /// also observe all connection-state writes that preceded the driver exit.
    pub(super) closed: Arc<AtomicBool>,
}

impl DrivenConnection {
    /// Open a new bidirectional QUIC stream and return it as a [`crate::handle::BiStream`].
    ///
    /// This is a convenience wrapper around [`Self::open_bidi_stream`] that bundles
    /// the send and receive handles into a single value with higher-level
    /// `write` / `read` / `finish` methods.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn open_bidi(&self) -> Result<crate::handle::BiStream, OxiQuicError> {
        let (send, recv) = self.open_bidi_stream().await?;
        Ok(crate::handle::BiStream::new(send, recv))
    }

    /// Open a bidirectional stream with an associated priority hint and return a
    /// [`crate::handle::BiStream`].
    ///
    /// The `priority` value is a hint for future stream-scheduling support; it
    /// is currently not used to reorder packets.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn open_bidi_with_priority(
        &self,
        _priority: i32,
    ) -> Result<crate::handle::BiStream, OxiQuicError> {
        // Priority is stored as a hint; current scheduler does not reorder streams.
        self.open_bidi().await
    }

    /// Open a new bidirectional QUIC stream, returning a
    /// `(SendStreamHandle, RecvStreamHandle)` pair.
    ///
    /// The [`SendStreamHandle`] implements [`tokio::io::AsyncWrite`]; the
    /// [`RecvStreamHandle`] implements [`tokio::io::AsyncRead`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn open_bidi_stream(
        &self,
    ) -> Result<(SendStreamHandle, RecvStreamHandle), OxiQuicError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .send(reply_tx)
            .await
            .map_err(|_| OxiQuicError::Connection("driven connection driver has stopped".into()))?;

        let (stream_id, data_rx) = reply_rx.await.map_err(|_| {
            OxiQuicError::Connection(
                "driven connection driver closed before stream was opened".into(),
            )
        })?;

        let send = SendStreamHandle {
            stream_id,
            conn_tx: self.write_tx.clone(),
        };
        let recv = RecvStreamHandle {
            stream_id,
            data_rx,
            buf: Vec::new(),
            buf_pos: 0,
            conn_tx: self.write_tx.clone(),
        };
        Ok((send, recv))
    }

    /// Open a new unidirectional (send-only) QUIC stream, returning a
    /// [`SendStreamHandle`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the background driver task has
    /// already stopped.
    pub async fn open_uni_stream(&self) -> Result<SendStreamHandle, OxiQuicError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_uni_tx
            .send(reply_tx)
            .await
            .map_err(|_| OxiQuicError::Connection("driven connection driver has stopped".into()))?;

        let (stream_id, _data_rx) = reply_rx.await.map_err(|_| {
            OxiQuicError::Connection(
                "driven connection driver closed before uni stream was opened".into(),
            )
        })?;

        Ok(SendStreamHandle {
            stream_id,
            conn_tx: self.write_tx.clone(),
        })
    }

    /// Accept the next incoming bidirectional stream opened by the peer,
    /// returning a `(SendStreamHandle, RecvStreamHandle)` pair.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the connection has been closed.
    pub async fn accept_bidi_stream(
        &self,
    ) -> Result<(SendStreamHandle, RecvStreamHandle), OxiQuicError> {
        self.accept_bidi_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| OxiQuicError::Connection("connection closed".into()))
    }

    /// Accept the next incoming unidirectional stream opened by the peer,
    /// returning a [`RecvStreamHandle`].
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the connection has been closed.
    pub async fn accept_uni_stream(&self) -> Result<RecvStreamHandle, OxiQuicError> {
        self.accept_uni_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| OxiQuicError::Connection("connection closed".into()))
    }

    /// Returns the ALPN protocol negotiated during the TLS handshake, if any.
    ///
    /// Captured from the [`Connection`] state machine before the background
    /// I/O task takes ownership. For HTTP/3 connections this should be
    /// `Some(b"h3".to_vec())` after a successful handshake with an HTTP/3
    /// server.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// The remote peer address, captured from the connection driver immediately
    /// before it moved into the background task.
    ///
    /// Returns `None` only if the handshake completed before the peer address
    /// was resolved, which does not occur in normal operation.
    #[must_use]
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Whether the background driver task has fully exited (connection closed).
    ///
    /// This is a *liveness hint*: once `true`, the driver has stopped and the
    /// connection is definitely closed. A `false` return means the driver has
    /// not yet set the flag — it may still be running or in the process of
    /// shutting down.
    ///
    /// The flag is stored with [`std::sync::atomic::Ordering::Release`] by the
    /// driver and loaded with [`std::sync::atomic::Ordering::Acquire`] here,
    /// so a `true` observation is guaranteed to happen-after all
    /// connection-state mutations performed by the driver before it exited.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Return a clone of the write channel. Used by the `h3-compat` layer so
    /// that receive-stream wrappers can send `STOP_SENDING` frames.
    #[cfg(feature = "h3-compat")]
    pub fn write_tx(&self) -> crate::handle::WriteTx {
        self.write_tx.clone()
    }

    /// Gracefully close the connection with the given application error code
    /// and reason phrase.
    ///
    /// # Errors
    /// Returns [`OxiQuicError::Connection`] if the driver has already stopped.
    pub async fn close(&self, error_code: u64, reason: &[u8]) -> Result<(), OxiQuicError> {
        self.close_tx
            .send((error_code, reason.to_vec()))
            .await
            .map_err(|_| OxiQuicError::Connection("driven connection driver has stopped".into()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background driver task
// ─────────────────────────────────────────────────────────────────────────────

/// All channels used by [`run_driven_connection`], bundled to keep the
/// argument count within clippy's `too_many_arguments` limit.
pub(super) struct DrivenConnectionChannels {
    /// Write-side clone forwarded to stream handles for `AsyncWrite` support.
    pub(super) write_tx: WriteTx,
    /// Inbound stream-write commands (data / fin / reset / stop-sending).
    pub(super) write_rx: mpsc::Receiver<(StreamId, WriteCmd)>,
    /// Inbound open-bidi-stream requests from the application.
    pub(super) open_rx: mpsc::Receiver<OpenStreamSender>,
    /// Inbound open-uni-stream requests from the application.
    pub(super) open_uni_rx: mpsc::Receiver<OpenStreamSender>,
    /// Inbound graceful-close requests from the application.
    pub(super) close_rx: mpsc::Receiver<(u64, Vec<u8>)>,
    /// Delivery channel for peer-opened bidirectional streams.
    pub(super) accept_bidi_tx: mpsc::Sender<(SendStreamHandle, RecvStreamHandle)>,
    /// Delivery channel for peer-opened unidirectional streams.
    pub(super) accept_uni_tx: mpsc::Sender<RecvStreamHandle>,
    /// Shared closed flag. Set to `true` with [`Ordering::Release`] immediately
    /// before the driver task exits. Readable via [`DrivenConnection::is_closed`].
    pub(super) closed: Arc<AtomicBool>,
}

/// The background I/O loop for a [`DrivenConnection`].
///
/// This task owns the UDP socket (for sends) and the [`InboundSource`] (for
/// receives) and the [`Connection`] state machine. It multiplexes six event
/// sources via `tokio::select!`:
///
/// 1. Incoming datagrams from `InboundSource` — forwarded to the protocol state machine.
/// 2. Outgoing stream writes — enqueued and flushed.
/// 3. New bidirectional-stream open requests — allocates a stream and returns the channel.
/// 4. New unidirectional-stream open requests — allocates a uni stream and returns the channel.
/// 5. Close requests — sends `CONNECTION_CLOSE` and exits.
/// 6. Protocol timeout — calls `handle_timeout` and re-arms the timer.
pub(super) async fn run_driven_connection(
    socket: Arc<UdpSocket>,
    mut inbound: InboundSource,
    mut conn: Connection,
    peer: Option<SocketAddr>,
    channels: DrivenConnectionChannels,
) {
    let DrivenConnectionChannels {
        write_tx,
        mut write_rx,
        open_rx,
        open_uni_rx,
        mut close_rx,
        accept_bidi_tx,
        accept_uni_tx,
        closed,
    } = channels;
    /// Flush all pending outgoing datagrams to the socket. Returns `false` if
    /// the socket send failed (the caller should break the loop).
    async fn flush_conn(socket: &UdpSocket, conn: &mut Connection) -> bool {
        loop {
            let mut out = Vec::new();
            let now = Instant::now();
            match conn.poll_transmit(now, &mut out) {
                Some(addr) if !out.is_empty() => {
                    if socket.send_to(&out, addr).await.is_err() {
                        return false;
                    }
                }
                _ => return true,
            }
        }
    }

    let mut recv_buf = vec![0u8; RECV_BUF];
    // Per-stream inbound data senders, keyed by StreamId.
    let mut read_senders: HashMap<StreamId, mpsc::Sender<Vec<u8>>> = HashMap::new();
    // The open-stream and open-uni-stream channels are optional: once all
    // senders are dropped (no more stream-open requests can be issued) we stop
    // polling them but keep running to deliver in-flight data.
    let mut open_rx_opt: OptOpenRx = Some(open_rx);
    let mut open_uni_rx_opt: OptOpenRx = Some(open_uni_rx);

    loop {
        // Determine the next protocol timeout (if any).
        let timeout_instant = conn
            .next_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));

        tokio::select! {
            // ── 1. Inbound datagram ──────────────────────────────────────────
            result = recv_inbound(&mut inbound, &mut recv_buf) => {
                let (owned, _from) = match result {
                    Ok(v) => v,
                    // ICMP port-unreachable: peer closed its socket (e.g. server
                    // dropped before sending CONNECTION_CLOSE).  Not fatal for
                    // QUIC — the loss-detection timer will handle it; keep running.
                    Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                    Err(_) => break,
                };
                let mut datagram = owned;
                let now = Instant::now();
                if conn.handle_datagram(now, &mut datagram).is_err() {
                    break;
                }
                // Surface any newly-opened peer streams before draining readable.
                while let Some(new_sid) = conn.poll_new_peer_stream() {
                    // Create the inbound data channel for this new peer stream.
                    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                    read_senders.insert(new_sid, data_tx);
                    let recv_handle = RecvStreamHandle {
                        stream_id: new_sid,
                        data_rx,
                        buf: Vec::new(),
                        buf_pos: 0,
                        conn_tx: write_tx.clone(),
                    };
                    if new_sid.direction() == Direction::Bidirectional {
                        // Peer-opened bidi stream: create a send handle too.
                        let send_handle = SendStreamHandle {
                            stream_id: new_sid,
                            conn_tx: write_tx.clone(),
                        };
                        let _ = accept_bidi_tx.try_send((send_handle, recv_handle));
                    } else {
                        // Peer-opened uni stream: recv-only.
                        let _ = accept_uni_tx.try_send(recv_handle);
                    }
                }
                // Forward any newly-readable stream data to registered channels.
                while let Some(sid) = conn.poll_readable() {
                    if let Ok((bytes, fin)) = conn.read_stream(sid) {
                        // Auto-register a channel for peer-opened streams that
                        // arrived before a new_peer_stream notification (e.g.
                        // data and stream-open in the same datagram).
                        if !read_senders.contains_key(&sid) && (!bytes.is_empty() || fin) {
                            let (data_tx, _data_rx) = mpsc::channel::<Vec<u8>>(64);
                            read_senders.insert(sid, data_tx);
                        }
                        if !bytes.is_empty() {
                            if let Some(tx) = read_senders.get(&sid) {
                                let _ = tx.try_send(bytes);
                            }
                        }
                        // FIN: close the channel so RecvStreamHandle gets EOF.
                        if fin {
                            read_senders.remove(&sid);
                        }
                    }
                }
                if !flush_conn(&socket, &mut conn).await {
                    break;
                }
            }

            // ── 2. Outgoing stream write ─────────────────────────────────────
            msg = write_rx.recv() => {
                match msg {
                    Some((sid, cmd)) => {
                        match cmd {
                            crate::handle::WriteCmd::Write { data, fin } => {
                                let _ = conn.send_stream(sid, &data, fin);
                            }
                            crate::handle::WriteCmd::Reset { error_code } => {
                                let _ = conn.reset_stream(sid, error_code);
                            }
                            crate::handle::WriteCmd::StopSending { error_code } => {
                                let _ = conn.stop_sending(sid, error_code);
                            }
                        }
                        if !flush_conn(&socket, &mut conn).await {
                            break;
                        }
                    }
                    None => break, // All senders dropped → connection handle gone.
                }
            }

            // ── 3. Open a new bidirectional stream ───────────────────────────
            req = async {
                match open_rx_opt.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match req {
                    Some(reply_tx) => {
                        let sid = match conn.open_bidi() {
                            Ok(s) => s,
                            Err(_) => {
                                // Stream limit reached; drop the request. The
                                // caller's oneshot sender will be dropped, causing
                                // a receive error on its side (expected behavior).
                                continue;
                            }
                        };
                        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                        read_senders.insert(sid, data_tx);
                        // Best-effort: if the requester timed out or was
                        // dropped, the send fails but that is harmless.
                        let _ = reply_tx.send((sid, data_rx));
                        if !flush_conn(&socket, &mut conn).await {
                            break;
                        }
                    }
                    None => {
                        // All open-bidi senders dropped: no more open requests
                        // will arrive. Stop polling this channel but keep the
                        // driver alive to deliver in-flight data.
                        open_rx_opt = None;
                    }
                }
            }

            // ── 3b. Open a new unidirectional stream ─────────────────────────
            req = async {
                match open_uni_rx_opt.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match req {
                    Some(reply_tx) => {
                        let sid = match conn.open_uni() {
                            Ok(s) => s,
                            Err(_) => {
                                // Stream limit reached; drop the request.
                                continue;
                            }
                        };
                        // Uni streams are send-only; no data_rx is needed by
                        // the caller, but we return an empty receiver for API
                        // uniformity (the caller only uses the StreamId).
                        let (_data_tx, data_rx) = mpsc::channel::<Vec<u8>>(1);
                        let _ = reply_tx.send((sid, data_rx));
                        if !flush_conn(&socket, &mut conn).await {
                            break;
                        }
                    }
                    None => {
                        // All open-uni senders dropped: no more open-uni
                        // requests will arrive. Keep driver alive for in-flight
                        // data delivery.
                        open_uni_rx_opt = None;
                    }
                }
            }

            // ── 4. Graceful close ────────────────────────────────────────────
            req = close_rx.recv() => {
                // Drain any pending stream writes that arrived concurrently
                // with the close signal before queueing CONNECTION_CLOSE.
                // This prevents a race where the h3 server's Drop fires while
                // stream data is still in write_rx, causing data to be lost.
                while let Ok((sid, cmd)) = write_rx.try_recv() {
                    match cmd {
                        crate::handle::WriteCmd::Write { data, fin } => {
                            let _ = conn.send_stream(sid, &data, fin);
                        }
                        crate::handle::WriteCmd::Reset { error_code } => {
                            let _ = conn.reset_stream(sid, error_code);
                        }
                        crate::handle::WriteCmd::StopSending { error_code } => {
                            let _ = conn.stop_sending(sid, error_code);
                        }
                    }
                }
                // Flush any queued stream data before emitting CONNECTION_CLOSE.
                if !flush_conn(&socket, &mut conn).await {
                    break;
                }
                if let Some((code, reason)) = req {
                    conn.close(code, &reason);
                }
                flush_conn(&socket, &mut conn).await;
                break;
            }

            // ── 5. Protocol timeout ──────────────────────────────────────────
            () = sleep_until(timeout_instant.into()) => {
                let now = Instant::now();
                conn.handle_timeout(now);
                if conn.is_closed() {
                    break;
                }
                if !flush_conn(&socket, &mut conn).await {
                    break;
                }
            }
        }

        // Exit immediately if the connection state machine has fully closed.
        if conn.is_closed() {
            break;
        }
    }

    // Drop read_senders — this closes all data_rx receivers, signalling EOF
    // to any RecvStreamHandle still held by the application.
    drop(read_senders);
    // `peer` is kept in scope for potential future use (connection migration).
    let _ = peer;

    // Signal that the driver has exited. Written with Release ordering so that
    // any observer that loads `true` with Acquire ordering is guaranteed to
    // see all connection-state mutations that preceded this store.
    closed.store(true, Ordering::Release);
}
