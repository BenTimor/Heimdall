use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result, bail};
use tracing::{info, warn, debug};

use super::PlatformOps;
use crate::state::RuntimeTrustState;

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

        // Purge ALL existing Guardian CA certs first to prevent duplicates.
        // certutil -addstore doesn't deduplicate, so repeated installs accumulate
        // copies. Multiple copies cause OpenSSL to pick the wrong one (e.g. an
        // older cert missing SubjectKeyIdentifier), breaking Python/Go/Ruby TLS.
        purge_guardian_certs_from_root();

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

        info!("Removing Guardian CA certificate(s) from Windows trust store");

        let removed = purge_guardian_certs_from_root();
        if removed == 0 {
            warn!("No Guardian CA certificates found in ROOT store");
        } else {
            info!(count = removed, "Removed Guardian CA certificate(s) from ROOT store");
        }

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

    fn configure_runtime_trust(&self, ca_cert_path: &Path) -> Result<RuntimeTrustState> {
        let data_dir = guardian_data_dir();
        std::fs::create_dir_all(&data_dir)
            .context("creating Guardian data directory")?;

        let bundle_path = data_dir.join("ca-bundle.pem");
        let guardian_ca_path = data_dir.join("guardian-ca.pem");

        // Export combined CA bundle (system CAs + Guardian CA already in store)
        export_windows_ca_bundle(&bundle_path)
            .context("exporting Windows CA bundle")?;
        info!(path = %bundle_path.display(), "Exported combined CA bundle");

        // Copy Guardian CA cert for NODE_EXTRA_CA_CERTS (additive, not a full bundle)
        std::fs::copy(ca_cert_path, &guardian_ca_path)
            .context("copying Guardian CA cert")?;
        info!(path = %guardian_ca_path.display(), "Copied Guardian CA cert");

        // Check existing state to handle re-install correctly
        let existing_state = crate::state::InstallState::load()
            .ok()
            .flatten();
        let preserve_originals = existing_state
            .as_ref()
            .map(|s| s.runtime_trust.configured)
            .unwrap_or(false);
        let existing_originals = existing_state
            .map(|s| s.runtime_trust.original_env_vars);

        let bundle_str = bundle_path.to_string_lossy().to_string();
        let guardian_ca_str = guardian_ca_path.to_string_lossy().to_string();

        let env_vars = vec![
            ("SSL_CERT_FILE", bundle_str.as_str()),
            ("REQUESTS_CA_BUNDLE", bundle_str.as_str()),
            ("NODE_EXTRA_CA_CERTS", guardian_ca_str.as_str()),
        ];

        let mut original_env_vars = HashMap::new();

        for (name, value) in &env_vars {
            // On re-install, preserve the original values from previous state
            let original = if preserve_originals {
                existing_originals
                    .as_ref()
                    .and_then(|m| m.get(*name).cloned())
                    .unwrap_or(None)
            } else {
                read_user_env_var(name)
            };

            original_env_vars.insert(name.to_string(), original);
            set_user_env_var(name, value)
                .with_context(|| format!("setting {} env var", name))?;
            info!(var = name, value = value, "Set user environment variable");
        }

        broadcast_environment_change();
        info!("Broadcast WM_SETTINGCHANGE for environment update");

        Ok(RuntimeTrustState {
            configured: true,
            ca_bundle_path: Some(bundle_path),
            guardian_ca_path: Some(guardian_ca_path),
            original_env_vars,
        })
    }

    fn remove_runtime_trust(&self, state: &RuntimeTrustState) -> Result<()> {
        // Restore or delete each env var
        for (name, original) in &state.original_env_vars {
            match original {
                Some(value) => {
                    set_user_env_var(name, value)
                        .with_context(|| format!("restoring {} env var", name))?;
                    info!(var = name, "Restored original environment variable");
                }
                None => {
                    delete_user_env_var(name)
                        .with_context(|| format!("deleting {} env var", name))?;
                    info!(var = name, "Deleted environment variable");
                }
            }
        }

        // Delete bundle files
        if let Some(ref path) = state.ca_bundle_path {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
        }
        if let Some(ref path) = state.guardian_ca_path {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
        }

        broadcast_environment_change();
        info!("Runtime CA trust removed and environment broadcast sent");

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

/// Remove all Guardian CA certificates from the Windows Root stores.
/// Returns the number of certificates removed.
///
/// Uses PowerShell to enumerate both LocalMachine\Root and CurrentUser\Root,
/// find all certs whose Subject contains "Guardian", and remove them by
/// thumbprint.  This is more reliable than `certutil -delstore` which has
/// inconsistent substring matching and doesn't touch CurrentUser.
fn purge_guardian_certs_from_root() -> usize {
    let ps_script = r#"
$removed = 0
foreach ($loc in @('LocalMachine', 'CurrentUser')) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $loc)
        $store.Open('ReadWrite')
        $toRemove = @()
        foreach ($cert in $store.Certificates) {
            if ($cert.Subject -match 'Guardian') {
                $toRemove += $cert
            }
        }
        foreach ($cert in $toRemove) {
            $store.Remove($cert)
            $removed++
        }
        $store.Close()
    } catch { }
}
Write-Host $removed
"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let count: usize = stdout.trim().parse().unwrap_or(0);
            if count > 0 {
                debug!(count, "Purged Guardian CA certificates from Root stores");
            }
            count
        }
        _ => {
            debug!("PowerShell cert purge failed, falling back to certutil");
            // Fallback: certutil loop for LocalMachine only
            let mut removed = 0;
            for _ in 0..50 {
                let out = std::process::Command::new("certutil")
                    .args(["-f", "-delstore", "ROOT", "Guardian"])
                    .output();
                match out {
                    Ok(o) if o.status.success() => removed += 1,
                    _ => break,
                }
            }
            removed
        }
    }
}

/// Get the Guardian data directory (%APPDATA%\Guardian).
fn guardian_data_dir() -> PathBuf {
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(appdata).join("Guardian")
}

/// Export all trusted root certificates from the Windows certificate stores
/// to a combined PEM bundle, deduplicated by thumbprint.
///
/// Includes both `Root` (manually trusted) and `AuthRoot` (third-party roots
/// auto-downloaded by Windows from Microsoft's Trusted Root Certificate Program).
/// The `Root` store alone is often sparse on modern Windows — most CAs live in
/// `AuthRoot` and are downloaded on demand.
fn export_windows_ca_bundle(output_path: &Path) -> Result<()> {
    let ps_script = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$thumbprints = @{}
$pems = [System.Collections.ArrayList]@()
foreach ($storeLocation in @('LocalMachine', 'CurrentUser')) {
    foreach ($storeName in @('Root', 'AuthRoot')) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
            $store.Open('ReadOnly')
            foreach ($cert in $store.Certificates) {
                $tp = $cert.Thumbprint
                if ($tp -and -not $thumbprints.ContainsKey($tp)) {
                    # Skip certs missing Subject Key Identifier (OID 2.5.29.14).
                    # OpenSSL 3.x rejects CA certs without SKI during chain validation.
                    $hasSki = $false
                    foreach ($ext in $cert.Extensions) {
                        if ($ext.Oid.Value -eq '2.5.29.14') { $hasSki = $true; break }
                    }
                    if (-not $hasSki) { continue }
                    $thumbprints[$tp] = $true
                    $b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
                    $null = $pems.Add("-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----")
                }
            }
            $store.Close()
        } catch { }
    }
}
$pems -join "`n"
"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_script])
        .output()
        .context("running PowerShell to export CA bundle")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("PowerShell CA export failed: {}", stderr);
    }

    // Normalize line endings (InsertLineBreaks uses \r\n, we want \n throughout)
    let pem_data = String::from_utf8_lossy(&output.stdout);
    let pem_data = pem_data.replace("\r\n", "\n");
    let pem_data = pem_data.trim();

    if pem_data.is_empty() {
        bail!("CA bundle export produced empty output");
    }

    let cert_count = pem_data.matches("-----BEGIN CERTIFICATE-----").count();
    info!(cert_count, path = %output_path.display(), "Exported CA bundle");

    std::fs::write(output_path, pem_data.as_bytes())
        .context("writing CA bundle PEM file")?;

    Ok(())
}

/// Read a user-level environment variable from the registry (HKCU\Environment).
fn read_user_env_var(name: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", r"HKCU\Environment", "/v", name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // reg query output format: "    VarName    REG_SZ    Value"
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with(name) || line.contains(name) {
            // Find REG_SZ or REG_EXPAND_SZ and extract the value after it
            if let Some(pos) = line.find("REG_SZ") {
                let after = &line[pos + "REG_SZ".len()..];
                return Some(after.trim().to_string());
            }
            if let Some(pos) = line.find("REG_EXPAND_SZ") {
                let after = &line[pos + "REG_EXPAND_SZ".len()..];
                return Some(after.trim().to_string());
            }
        }
    }

    None
}

/// Set a user-level environment variable via the registry (HKCU\Environment).
fn set_user_env_var(name: &str, value: &str) -> Result<()> {
    let output = std::process::Command::new("reg")
        .args([
            "add", r"HKCU\Environment",
            "/v", name,
            "/t", "REG_SZ",
            "/d", value,
            "/f",
        ])
        .output()
        .with_context(|| format!("running reg add for {}", name))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to set env var {}: {}", name, stderr);
    }
    Ok(())
}

/// Delete a user-level environment variable from the registry (HKCU\Environment).
fn delete_user_env_var(name: &str) -> Result<()> {
    let output = std::process::Command::new("reg")
        .args([
            "delete", r"HKCU\Environment",
            "/v", name,
            "/f",
        ])
        .output()
        .with_context(|| format!("running reg delete for {}", name))?;

    if !output.status.success() {
        // Not an error if the var doesn't exist
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("reg delete for {} may have failed (might not exist): {}", name, stderr);
    }
    Ok(())
}

/// Broadcast WM_SETTINGCHANGE so new processes pick up environment changes.
fn broadcast_environment_change() {
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"
            Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class EnvBroadcast {
                    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
                    public static extern IntPtr SendMessageTimeout(
                        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
                        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
                    public static void Broadcast() {
                        UIntPtr result;
                        SendMessageTimeout(
                            (IntPtr)0xFFFF, 0x001A, UIntPtr.Zero, "Environment",
                            0x0002, 5000, out result);
                    }
                }
"@
            [EnvBroadcast]::Broadcast()
            "#,
        ])
        .output();
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
