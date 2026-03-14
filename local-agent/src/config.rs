use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub local_proxy: LocalProxyConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub transparent: TransparentConfig,
    pub tunnel: Option<TunnelConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub ca_cert: Option<PathBuf>,
    /// TLS certificate pin in "sha256/<base64-encoded-hash>" format.
    pub cert_pin: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub machine_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalProxyConfig {
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_localhost")]
    pub host: String,
    /// Optional auth token for local CONNECT proxy (Proxy-Authorization: Basic).
    pub auth_token: Option<String>,
}

impl Default for LocalProxyConfig {
    fn default() -> Self {
        Self {
            port: default_proxy_port(),
            host: default_localhost(),
            auth_token: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthConfig {
    #[serde(default = "default_health_port")]
    pub port: u16,
    #[serde(default = "default_localhost")]
    pub host: String,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            port: default_health_port(),
            host: default_localhost(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReconnectConfig {
    #[serde(default = "default_initial_delay")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_max_delay")]
    pub max_delay_ms: u64,
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: default_initial_delay(),
            max_delay_ms: default_max_delay(),
            multiplier: default_multiplier(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TunnelConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

fn default_max_connections() -> u32 {
    1000
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionMethod {
    Auto,
    Windivert,
    SystemProxy,
}

impl Default for InterceptionMethod {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransparentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_transparent_port")]
    pub port: u16,
    #[serde(default = "default_all_interfaces")]
    pub host: String,
    #[serde(default)]
    pub method: InterceptionMethod,
    /// PIDs to exclude from WinDivert interception (manual override).
    /// The agent auto-detects the proxy server PID; use this for additional exclusions.
    #[serde(default)]
    pub exclude_pids: Vec<u32>,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_transparent_port(),
            host: default_all_interfaces(),
            method: InterceptionMethod::default(),
            exclude_pids: Vec::new(),
        }
    }
}

fn default_transparent_port() -> u16 {
    19443
}
fn default_all_interfaces() -> String {
    "0.0.0.0".to_string()
}
fn default_proxy_port() -> u16 {
    19080
}
fn default_health_port() -> u16 {
    19876
}
fn default_localhost() -> String {
    "127.0.0.1".to_string()
}
fn default_initial_delay() -> u64 {
    1000
}
fn default_max_delay() -> u64 {
    60000
}
fn default_multiplier() -> f64 {
    2.0
}
fn default_log_level() -> String {
    "info".to_string()
}

impl AgentConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).context(format!("reading config file: {}", path.display()))?;
        let config: AgentConfig =
            serde_yml::from_str(&contents).context("parsing config YAML")?;
        Ok(config)
    }
}
