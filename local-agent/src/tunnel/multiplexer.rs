use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::tunnel::client::FramedTunnel;
use crate::domain_filter::DomainFilter;
use crate::tunnel::protocol::{Frame, FrameType};

/// Heartbeat interval and timeout.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Channel for sending frames to the tunnel write half.
pub type TunnelSender = mpsc::Sender<Frame>;

/// Tracks one multiplexed connection.
struct Connection {
    /// Channel to push DATA frames toward the local socket.
    local_tx: mpsc::Sender<Bytes>,
}

/// Manages multiplexed connections over a single tunnel.
pub struct Multiplexer {
    connections: Arc<DashMap<u32, Connection>>,
    next_conn_id: AtomicU32,
    tunnel_tx: TunnelSender,
    last_heartbeat: Arc<tokio::sync::Mutex<Instant>>,
    max_connections: u32,
    domain_filter: Arc<DomainFilter>,
}

/// Status snapshot for health reporting.
pub struct MultiplexerStatus {
    pub active_connections: usize,
    pub last_heartbeat: Instant,
}

impl Multiplexer {
    /// Create a new multiplexer from a connected+authenticated tunnel.
    /// Spawns the tunnel read loop and heartbeat sender.
    /// Returns the multiplexer handle.
    pub fn start(framed: FramedTunnel, shutdown: tokio::sync::watch::Receiver<bool>, max_connections: u32, domain_filter: Arc<DomainFilter>) -> Arc<Self> {
        let (write_half, read_half) = framed.split();

        let (tunnel_tx, tunnel_rx) = mpsc::channel::<Frame>(256);

        let connections: Arc<DashMap<u32, Connection>> = Arc::new(DashMap::new());
        let last_heartbeat = Arc::new(tokio::sync::Mutex::new(Instant::now()));

        let mux = Arc::new(Self {
            connections: connections.clone(),
            next_conn_id: AtomicU32::new(1),
            tunnel_tx: tunnel_tx.clone(),
            last_heartbeat: last_heartbeat.clone(),
            max_connections,
            domain_filter: domain_filter.clone(),
        });

        // Spawn tunnel writer task: drains tunnel_rx and writes to the tunnel.
        tokio::spawn(Self::tunnel_write_loop(write_half, tunnel_rx));

        // Spawn tunnel reader task: reads frames and dispatches them.
        tokio::spawn(Self::tunnel_read_loop(
            read_half,
            connections.clone(),
            tunnel_tx.clone(),
            last_heartbeat.clone(),
            domain_filter,
        ));

        // Spawn heartbeat sender.
        tokio::spawn(Self::heartbeat_loop(
            tunnel_tx.clone(),
            last_heartbeat.clone(),
            shutdown,
        ));

        mux
    }

    /// Open a new multiplexed connection. Sends NEW_CONNECTION frame and
    /// spawns a bridge between the local stream and the tunnel.
    pub async fn new_connection(
        self: &Arc<Self>,
        local_stream: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<u32> {
        if self.connections.len() >= self.max_connections as usize {
            warn!(
                active = self.connections.len(),
                max = self.max_connections,
                "connection limit reached, rejecting new connection"
            );
            bail!("connection limit reached ({} active, max {})", self.connections.len(), self.max_connections);
        }

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);

        let (local_tx, mut local_rx) = mpsc::channel::<Bytes>(64);
        self.connections.insert(conn_id, Connection { local_tx });

        // Send NEW_CONNECTION frame with "host:port" payload.
        info!(conn_id, host = %host, port, "multiplexer: sending NEW_CONNECTION");
        let payload = format!("{}:{}", host, port);
        let frame = Frame::new(conn_id, FrameType::NewConnection, Bytes::from(payload));
        self.tunnel_tx
            .send(frame)
            .await
            .context("sending NEW_CONNECTION frame")?;

        // Spawn bridge: local socket read -> tunnel DATA frames
        let tunnel_tx = self.tunnel_tx.clone();
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let (mut read_half, mut write_half) = local_stream.into_split();

            // Local -> tunnel
            let tunnel_tx_clone = tunnel_tx.clone();
            let conn_id_copy = conn_id;
            let mut upload = tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let frame = Frame::new(
                                conn_id_copy,
                                FrameType::Data,
                                Bytes::copy_from_slice(&buf[..n]),
                            );
                            if tunnel_tx_clone.send(frame).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(conn_id = conn_id_copy, error = %e, "local read error");
                            break;
                        }
                    }
                }
            });

            // Tunnel -> local (receive from local_rx channel)
            let mut download = tokio::spawn(async move {
                while let Some(data) = local_rx.recv().await {
                    if write_half.write_all(&data).await.is_err() {
                        break;
                    }
                }
            });

            // Wait for either direction to finish, then clean up.
            let upload_first = tokio::select! {
                _ = &mut upload => true,
                _ = &mut download => false,
            };

            let close_frame = Frame::new(conn_id, FrameType::Close, Bytes::new());
            let _ = tunnel_tx.send(close_frame).await;

            // Wait for the other direction to drain. Normally the server's
            // CLOSE causes tunnel_read_loop to remove the connection, ending
            // the download task. Timeout is a safety net.
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                if upload_first {
                    let _ = download.await;
                } else {
                    let _ = upload.await;
                }
            }).await;

            connections.remove(&conn_id);  // no-op if tunnel_read_loop already removed
            debug!(conn_id, "connection bridge closed");
        });

        Ok(conn_id)
    }

    pub async fn status_async(&self) -> MultiplexerStatus {
        MultiplexerStatus {
            active_connections: self.connections.len(),
            last_heartbeat: *self.last_heartbeat.lock().await,
        }
    }

    /// Gracefully drain all active connections.
    /// Sends CLOSE frames for each connection, then waits up to 5 seconds
    /// for connections to drain before clearing any remaining.
    pub async fn shutdown(&self) {
        let conn_ids: Vec<u32> = self.connections.iter().map(|entry| *entry.key()).collect();
        if conn_ids.is_empty() {
            return;
        }

        info!(active = conn_ids.len(), "draining connections for shutdown");

        for conn_id in &conn_ids {
            let close_frame = Frame::new(*conn_id, FrameType::Close, Bytes::new());
            if self.tunnel_tx.send(close_frame).await.is_err() {
                debug!("tunnel_tx closed during shutdown drain");
                break;
            }
        }

        // Wait up to 5 seconds for connections to drain (polled every 100ms).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !self.connections.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !self.connections.is_empty() {
            warn!(
                remaining = self.connections.len(),
                "shutdown drain timeout, clearing remaining connections"
            );
            self.connections.clear();
        }

        info!("connection drain complete");
    }

    /// Send a DOMAIN_LIST_REQUEST frame to the server on the control channel.
    pub async fn request_domain_list(&self) -> Result<()> {
        let frame = Frame::new(0, FrameType::DomainListRequest, Bytes::new());
        self.tunnel_tx
            .send(frame)
            .await
            .context("sending DOMAIN_LIST_REQUEST")?;
        debug!("sent DOMAIN_LIST_REQUEST");
        Ok(())
    }

    // --- Internal tasks ---

    async fn tunnel_write_loop(
        mut sink: SplitSink<FramedTunnel, Frame>,
        mut rx: mpsc::Receiver<Frame>,
    ) {
        while let Some(frame) = rx.recv().await {
            if let Err(e) = sink.send(frame).await {
                error!(error = %e, "tunnel write error");
                break;
            }
        }
        debug!("tunnel write loop exited");
    }

    async fn tunnel_read_loop(
        mut stream: futures_util::stream::SplitStream<FramedTunnel>,
        connections: Arc<DashMap<u32, Connection>>,
        _tunnel_tx: TunnelSender,
        last_heartbeat: Arc<tokio::sync::Mutex<Instant>>,
        domain_filter: Arc<DomainFilter>,
    ) {
        while let Some(result) = stream.next().await {
            match result {
                Ok(frame) => {
                    match frame.frame_type {
                        FrameType::Data => {
                            if let Some(conn) = connections.get(&frame.conn_id) {
                                if conn.local_tx.send(frame.payload).await.is_err() {
                                    debug!(conn_id = frame.conn_id, "local receiver dropped");
                                    connections.remove(&frame.conn_id);
                                }
                            }
                        }
                        FrameType::Close => {
                            debug!(conn_id = frame.conn_id, "received CLOSE from server");
                            connections.remove(&frame.conn_id);
                        }
                        FrameType::HeartbeatAck => {
                            let mut hb = last_heartbeat.lock().await;
                            *hb = Instant::now();
                        }
                        FrameType::AuthFail => {
                            error!("received AUTH_FAIL from server, tunnel closing");
                            break;
                        }
                        FrameType::DomainListResponse => {
                            match serde_json::from_slice::<Vec<String>>(&frame.payload) {
                                Ok(domains) => {
                                    info!(count = domains.len(), "received domain list from server");
                                    domain_filter.update(domains);
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse domain list response");
                                }
                            }
                        }
                        other => {
                            warn!(frame_type = ?other, "unexpected frame type from server");
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "tunnel read error");
                    break;
                }
            }
        }
        info!("tunnel read loop exited");
    }

    async fn heartbeat_loop(
        tunnel_tx: TunnelSender,
        last_heartbeat: Arc<tokio::sync::Mutex<Instant>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let hb_frame = Frame::new(0, FrameType::Heartbeat, Bytes::new());
                    if tunnel_tx.send(hb_frame).await.is_err() {
                        break;
                    }

                    let elapsed = {
                        let hb = last_heartbeat.lock().await;
                        hb.elapsed()
                    };
                    if elapsed > HEARTBEAT_TIMEOUT {
                        error!("heartbeat timeout — no ACK in {:?}", HEARTBEAT_TIMEOUT);
                        break;
                    }
                }
                _ = shutdown.changed() => {
                    break;
                }
            }
        }
        debug!("heartbeat loop exited");
    }
}
