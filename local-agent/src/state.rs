use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// State tracking for runtime CA trust environment variables.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RuntimeTrustState {
    pub configured: bool,
    pub ca_bundle_path: Option<PathBuf>,
    pub guardian_ca_path: Option<PathBuf>,
    /// Env vars that were set → their original values (None = didn't exist before)
    pub original_env_vars: HashMap<String, Option<String>>,
}

/// Persistent install state tracking what Guardian components are set up.
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallState {
    pub version: u32,
    pub installed_at: u64,
    pub ca_cert_installed: bool,
    pub ca_cert_path: Option<PathBuf>,
    pub interception_enabled: bool,
    pub service_installed: bool,
    #[serde(default)]
    pub runtime_trust: RuntimeTrustState,
}

impl InstallState {
    pub fn new() -> Self {
        Self {
            version: 1,
            installed_at: unix_timestamp(),
            ca_cert_installed: false,
            ca_cert_path: None,
            interception_enabled: false,
            service_installed: false,
            runtime_trust: RuntimeTrustState::default(),
        }
    }

    /// Get the platform-appropriate path for the state file.
    pub fn state_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(appdata).join("Guardian").join("state.json")
        }
        #[cfg(not(target_os = "windows"))]
        {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home)
                .join(".config")
                .join("guardian")
                .join("state.json")
        }
    }

    /// Load install state from disk, returning None if no state file exists.
    pub fn load() -> Result<Option<Self>> {
        let path = Self::state_path();
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .context("reading install state")?;
        let state: Self = serde_json::from_str(&contents)
            .context("parsing install state")?;
        Ok(Some(state))
    }

    /// Save the current install state to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::state_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .context("creating state directory")?;
        }
        let json = serde_json::to_string_pretty(self)
            .context("serializing install state")?;
        std::fs::write(&path, json)
            .context("writing install state")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .context("setting state file permissions")?;
            if let Some(parent) = path.parent() {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .context("setting state directory permissions")?;
            }
        }
        Ok(())
    }

    /// Delete the state file from disk.
    pub fn delete() -> Result<()> {
        let path = Self::state_path();
        if path.exists() {
            std::fs::remove_file(&path)
                .context("removing install state file")?;
        }
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
