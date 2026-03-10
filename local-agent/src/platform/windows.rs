use std::path::Path;
use anyhow::{Context, Result, bail};
use tracing::{info, warn, debug};

use super::PlatformOps;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

/// Check if the current process is running with administrator privileges.
pub fn is_elevated() -> Result<bool> {
    use std::process::Command;
    let output = Command::new("net").arg("session").output();
    match output {
        Ok(o) => Ok(o.status.success()),
        Err(_) => Ok(false),
    }
}

impl PlatformOps for WindowsPlatform {
    fn enable_interception(&self, transparent_port: u16) -> Result<()> {
        if !is_elevated()? {
            bail!("Administrator privileges required to enable traffic interception");
        }

        info!(
            transparent_port,
            "Enabling WinDivert traffic interception"
        );

        // Configure system proxy as primary interception method on Windows.
        // WinDivert requires a signed driver and additional setup; system proxy
        // is the reliable default that works without driver installation.
        set_system_proxy(true, transparent_port)?;

        info!("System proxy configured for localhost:{}", transparent_port);
        Ok(())
    }

    fn disable_interception(&self) -> Result<()> {
        info!("Disabling traffic interception");
        set_system_proxy(false, 0)?;
        info!("System proxy disabled");
        Ok(())
    }

    fn is_interception_active(&self) -> Result<bool> {
        is_system_proxy_enabled()
    }

    fn install_ca_cert(&self, cert_pem_path: &Path) -> Result<()> {
        if !is_elevated()? {
            bail!("Administrator privileges required to install CA certificate");
        }

        info!(path = %cert_pem_path.display(), "Installing CA certificate to Windows trust store");

        let pem_data = std::fs::read_to_string(cert_pem_path)
            .context("reading CA certificate PEM file")?;

        // Extract DER from PEM
        let der = pem_to_der(&pem_data)
            .context("decoding PEM certificate")?;

        // Use certutil to add to ROOT store
        let tmp_der = std::env::temp_dir().join("guardian-ca.cer");
        std::fs::write(&tmp_der, &der)
            .context("writing temporary DER certificate")?;

        let output = std::process::Command::new("certutil")
            .args(["-addstore", "ROOT"])
            .arg(&tmp_der)
            .output()
            .context("running certutil")?;

        // Clean up temp file
        let _ = std::fs::remove_file(&tmp_der);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("certutil failed: {}", stderr);
        }

        info!("CA certificate installed to Windows ROOT store");
        Ok(())
    }

    fn uninstall_ca_cert(&self) -> Result<()> {
        if !is_elevated()? {
            bail!("Administrator privileges required to remove CA certificate");
        }

        info!("Removing Guardian CA certificate from Windows trust store");

        // Use certutil to find and delete Guardian certificates from ROOT store
        let output = std::process::Command::new("certutil")
            .args(["-delstore", "ROOT", "Guardian"])
            .output()
            .context("running certutil -delstore")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("certutil -delstore may have failed (cert might not exist): {}", stderr);
        }

        info!("Guardian CA certificate removed from ROOT store");
        Ok(())
    }

    fn is_ca_installed(&self, _cert_pem_path: &Path) -> Result<bool> {
        // Check ROOT store for a Guardian certificate using certutil
        let output = std::process::Command::new("certutil")
            .args(["-verifystore", "ROOT", "Guardian"])
            .output()
            .context("running certutil -verifystore")?;

        Ok(output.status.success())
    }

    fn install_service(&self, exe_path: &Path, config_path: &Path) -> Result<()> {
        if !is_elevated()? {
            bail!("Administrator privileges required to install service");
        }

        let exe = exe_path.to_string_lossy();
        let config = config_path.to_string_lossy();

        info!("Installing Guardian agent as Windows service");

        // Use sc.exe to create the service
        let output = std::process::Command::new("sc")
            .args([
                "create",
                "GuardianAgent",
                "binPath=",
                &format!("\"{}\" run --config \"{}\"", exe, config),
                "start=",
                "auto",
                "DisplayName=",
                "Guardian Secret Proxy Agent",
            ])
            .output()
            .context("running sc create")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sc create failed: {}", stderr);
        }

        // Set description
        let _ = std::process::Command::new("sc")
            .args([
                "description",
                "GuardianAgent",
                "Guardian transparent secret injection proxy agent",
            ])
            .output();

        // Configure recovery: restart on failure
        let _ = std::process::Command::new("sc")
            .args([
                "failure",
                "GuardianAgent",
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/10000/restart/30000",
            ])
            .output();

        info!("Guardian agent service installed");
        Ok(())
    }

    fn uninstall_service(&self) -> Result<()> {
        if !is_elevated()? {
            bail!("Administrator privileges required to uninstall service");
        }

        info!("Uninstalling Guardian agent Windows service");

        // Stop the service first (ignore errors if not running)
        let _ = std::process::Command::new("sc")
            .args(["stop", "GuardianAgent"])
            .output();

        let output = std::process::Command::new("sc")
            .args(["delete", "GuardianAgent"])
            .output()
            .context("running sc delete")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sc delete failed: {}", stderr);
        }

        info!("Guardian agent service uninstalled");
        Ok(())
    }

    fn is_service_installed(&self) -> Result<bool> {
        let output = std::process::Command::new("sc")
            .args(["query", "GuardianAgent"])
            .output()
            .context("running sc query")?;

        Ok(output.status.success())
    }

    fn start_service(&self) -> Result<()> {
        info!("Starting Guardian agent service");

        let output = std::process::Command::new("sc")
            .args(["start", "GuardianAgent"])
            .output()
            .context("running sc start")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sc start failed: {}", stderr);
        }

        info!("Guardian agent service started");
        Ok(())
    }

    fn stop_service(&self) -> Result<()> {
        info!("Stopping Guardian agent service");

        let output = std::process::Command::new("sc")
            .args(["stop", "GuardianAgent"])
            .output()
            .context("running sc stop")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("sc stop failed: {}", stderr);
        }

        info!("Guardian agent service stopped");
        Ok(())
    }
}

/// Set or clear the Windows system proxy via the registry.
fn set_system_proxy(enable: bool, port: u16) -> Result<()> {
    use std::process::Command;

    let internet_settings = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    if enable {
        // Set proxy server
        let proxy_value = format!("127.0.0.1:{}", port);
        let output = Command::new("reg")
            .args([
                "add",
                internet_settings,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &proxy_value,
                "/f",
            ])
            .output()
            .context("setting ProxyServer registry key")?;

        if !output.status.success() {
            bail!("Failed to set ProxyServer registry key");
        }

        // Enable proxy
        let output = Command::new("reg")
            .args([
                "add",
                internet_settings,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output()
            .context("setting ProxyEnable registry key")?;

        if !output.status.success() {
            bail!("Failed to enable proxy in registry");
        }

        // Bypass list: don't proxy localhost traffic
        let output = Command::new("reg")
            .args([
                "add",
                internet_settings,
                "/v",
                "ProxyOverride",
                "/t",
                "REG_SZ",
                "/d",
                "localhost;127.0.0.1;<local>",
                "/f",
            ])
            .output()
            .context("setting ProxyOverride registry key")?;

        if !output.status.success() {
            warn!("Failed to set proxy bypass list");
        }

        debug!("System proxy set to 127.0.0.1:{}", port);
    } else {
        // Disable proxy
        let output = Command::new("reg")
            .args([
                "add",
                internet_settings,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output()
            .context("clearing ProxyEnable registry key")?;

        if !output.status.success() {
            bail!("Failed to disable proxy in registry");
        }

        debug!("System proxy disabled");
    }

    // Notify the system that internet settings have changed
    notify_internet_settings_change();

    Ok(())
}

/// Check if the system proxy is currently enabled.
fn is_system_proxy_enabled() -> Result<bool> {
    let internet_settings = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let output = std::process::Command::new("reg")
        .args(["query", internet_settings, "/v", "ProxyEnable"])
        .output()
        .context("querying ProxyEnable registry key")?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // reg query output contains "0x1" when enabled
    Ok(stdout.contains("0x1"))
}

/// Notify Windows that internet settings have changed so apps pick up the new proxy.
fn notify_internet_settings_change() {
    // Use PowerShell to call InternetSetOption to refresh proxy settings
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"
            Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class WinInet {
                    [DllImport("wininet.dll", SetLastError = true)]
                    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
                    public const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
                    public const int INTERNET_OPTION_REFRESH = 37;
                }
"@
            [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_SETTINGS_CHANGED, [IntPtr]::Zero, 0)
            [WinInet]::InternetSetOption([IntPtr]::Zero, [WinInet]::INTERNET_OPTION_REFRESH, [IntPtr]::Zero, 0)
            "#,
        ])
        .output();
}

/// Decode a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use std::io::BufRead;

    let mut in_cert = false;
    let mut base64_data = String::new();

    for line in pem.as_bytes().lines() {
        let line = line.context("reading PEM line")?;
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            continue;
        }
        if line == "-----END CERTIFICATE-----" {
            break;
        }
        if in_cert {
            base64_data.push_str(line);
        }
    }

    if base64_data.is_empty() {
        bail!("No certificate found in PEM data");
    }

    base64_decode(&base64_data)
}

/// Simple base64 decoder (avoids adding a base64 crate dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn decode_char(c: u8) -> Result<u8> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => bail!("invalid base64 character: {}", c as char),
        }
    }

    let input: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    for chunk in input.chunks(4) {
        let len = chunk.len();
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        let data_len = len - pad;

        if data_len < 2 {
            continue;
        }

        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        output.push((a << 2) | (b >> 4));

        if data_len >= 3 {
            let c = decode_char(chunk[2])?;
            output.push((b << 4) | (c >> 2));

            if data_len >= 4 {
                let d = decode_char(chunk[3])?;
                output.push((c << 6) | d);
            }
        }
    }

    Ok(output)
}
