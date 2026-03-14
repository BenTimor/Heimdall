use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use bytes::Bytes;
use futures_util::SinkExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use sha2::{Sha256, Digest};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::{AuthConfig, ReconnectConfig, ServerConfig};
use crate::tunnel::protocol::{Frame, FrameCodec, FrameType};

/// Type alias for a framed TLS connection carrying protocol frames.
pub type FramedTunnel = Framed<tokio_rustls::client::TlsStream<TcpStream>, FrameCodec>;

/// Custom TLS certificate verifier that delegates to the default WebPKI verifier
/// and additionally checks that the end-entity certificate matches a pinned SHA-256 hash.
#[derive(Debug)]
struct PinningVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected_pin: String, // base64-encoded SHA-256 hash (without "sha256/" prefix)
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // First delegate to the inner (WebPKI) verifier
        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // Compute SHA-256 of the end-entity certificate's DER bytes
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash = hasher.finalize();
        let actual_pin = base64::engine::general_purpose::STANDARD.encode(hash);

        if actual_pin != self.expected_pin {
            return Err(rustls::Error::General(format!(
                "certificate pin mismatch: expected {}, got {}",
                self.expected_pin, actual_pin
            )));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls ClientConfig. Uses system root certs (via webpki-roots) by default,
/// or loads a custom CA cert if specified. If `cert_pin` is provided (format: "sha256/<base64>"),
/// wraps the verifier with a PinningVerifier.
fn build_tls_config(server: &ServerConfig, cert_pin: Option<String>) -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = &server.ca_cert {
        let pem = std::fs::read(ca_path)
            .context(format!("reading CA cert: {}", ca_path.display()))?;
        let certs = rustls_pemfile::certs(&mut &pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing CA PEM")?;
        for cert in certs {
            root_store.add(cert).context("adding CA cert to root store")?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = if let Some(pin) = cert_pin {
        let pin_hash = pin.strip_prefix("sha256/")
            .ok_or_else(|| anyhow::anyhow!("cert_pin must start with 'sha256/', got: {}", pin))?
            .to_string();

        let default_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .context("building WebPKI verifier")?;

        let pinning_verifier = PinningVerifier {
            inner: default_verifier,
            expected_pin: pin_hash,
        };

        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(pinning_verifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// Connect to the tunnel server over TLS and authenticate.
/// Returns a framed tunnel connection ready for multiplexing.
pub async fn connect_and_auth(
    server: &ServerConfig,
    auth: &AuthConfig,
) -> Result<FramedTunnel> {
    let tls_config = build_tls_config(server, server.cert_pin.clone())?;
    let connector = TlsConnector::from(tls_config);

    let server_name = server.host.parse::<std::net::IpAddr>()
        .map(|ip| ServerName::IpAddress(ip.into()))
        .unwrap_or_else(|_| ServerName::try_from(server.host.clone()).unwrap());

    info!(host = %server.host, port = server.port, "connecting to tunnel server");

    let tcp = TcpStream::connect((server.host.as_str(), server.port))
        .await
        .context("TCP connect to tunnel server")?;

    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with tunnel server")?;

    let mut framed = Framed::new(tls, FrameCodec::new());

    // Send AUTH frame: "machine_id:token"
    let auth_payload = Zeroizing::new(format!("{}:{}", auth.machine_id, auth.token));
    let auth_frame = Frame::new(0, FrameType::Auth, Bytes::from((*auth_payload).clone()));
    framed.send(auth_frame).await.context("sending AUTH frame")?;

    // Wait for AUTH_OK with timeout
    let auth_timeout = Duration::from_secs(10);
    let response = tokio::time::timeout(auth_timeout, framed.next())
        .await
        .context("auth response timeout")?
        .ok_or_else(|| anyhow::anyhow!("tunnel closed before auth response"))?
        .context("reading auth response frame")?;

    match response.frame_type {
        FrameType::AuthOk => {
            info!("tunnel authenticated successfully");
        }
        FrameType::AuthFail => {
            let msg = String::from_utf8_lossy(&response.payload);
            bail!("tunnel authentication failed: {}", msg);
        }
        other => {
            bail!("unexpected frame type during auth: {:?}", other);
        }
    }

    Ok(framed)
}

/// Connect with exponential backoff reconnection.
/// Keeps trying until a connection succeeds or the shutdown signal fires.
pub async fn connect_with_reconnect(
    server: &ServerConfig,
    auth: &AuthConfig,
    reconnect: &ReconnectConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<FramedTunnel> {
    let mut delay_ms = reconnect.initial_delay_ms;

    loop {
        match connect_and_auth(server, auth).await {
            Ok(framed) => return Ok(framed),
            Err(e) => {
                warn!(error = ?e, retry_in_ms = delay_ms, "tunnel connection failed, retrying");

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                    _ = shutdown.changed() => {
                        bail!("shutdown requested during reconnect");
                    }
                }

                delay_ms = ((delay_ms as f64) * reconnect.multiplier) as u64;
                delay_ms = delay_ms.min(reconnect.max_delay_ms);
            }
        }
    }
}
