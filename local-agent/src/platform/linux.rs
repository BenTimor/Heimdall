use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::PlatformOps;
use crate::state::RuntimeTrustState;

const SERVICE_NAME: &str = "guardian-agent";
const UNIT_FILE_PATH: &str = "/etc/systemd/system/guardian-agent.service";
const CA_CERT_PATH: &str = "/usr/local/share/ca-certificates/guardian-proxy.crt";
const IPTABLES_COMMENT: &str = "guardian-redirect";

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }
}

fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {} {}", program, args.join(" ")))?;
    Ok(output)
}

fn run_command_check(program: &str, args: &[&str]) -> Result<()> {
    let output = run_command(program, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{} {} failed: {}", program, args.join(" "), stderr);
    }
    Ok(())
}

/// Get the UID of the current process using `id -u`.
fn get_uid() -> Result<String> {
    let output = std::process::Command::new("id")
        .arg("-u")
        .output()
        .context("running id -u")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

impl PlatformOps for LinuxPlatform {
    fn enable_interception(&self, transparent_port: u16) -> Result<()> {
        let uid = get_uid()?;

        info!(
            transparent_port,
            uid = %uid,
            "Enabling iptables REDIRECT for outbound TCP:443"
        );

        // Redirect outbound TCP:443 to the transparent listener port,
        // excluding traffic from the agent's own UID to avoid loops.
        run_command_check(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                &uid,
                "-m",
                "comment",
                "--comment",
                IPTABLES_COMMENT,
                "-j",
                "REDIRECT",
                "--to-port",
                &transparent_port.to_string(),
            ],
        )?;

        info!("iptables REDIRECT rule added");
        Ok(())
    }

    fn disable_interception(&self) -> Result<()> {
        info!("Disabling iptables REDIRECT rule");

        let uid = get_uid()?;

        // Remove the exact rule we added. If it fails (e.g., rule doesn't exist), warn.
        let output = run_command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                &uid,
                "-m",
                "comment",
                "--comment",
                IPTABLES_COMMENT,
                "-j",
                "REDIRECT",
                "--to-port",
                "0",
            ],
        )?;

        if !output.status.success() {
            // Try a broader approach: list and delete by line number
            warn!("Direct rule deletion failed, attempting to find and remove by comment");
            remove_rules_by_comment()?;
        }

        info!("iptables REDIRECT rule removed");
        Ok(())
    }

    fn is_interception_active(&self) -> Result<bool> {
        let output = run_command(
            "iptables",
            &["-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers"],
        )?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(IPTABLES_COMMENT))
    }

    fn install_ca_cert(&self, cert_pem_path: &Path) -> Result<()> {
        info!(
            src = %cert_pem_path.display(),
            dst = CA_CERT_PATH,
            "Installing CA certificate"
        );

        std::fs::copy(cert_pem_path, CA_CERT_PATH)
            .context("copying CA cert to ca-certificates directory")?;

        run_command_check("update-ca-certificates", &[])?;

        info!("CA certificate installed and trust store updated");
        Ok(())
    }

    fn uninstall_ca_cert(&self) -> Result<()> {
        info!("Removing Guardian CA certificate");

        if Path::new(CA_CERT_PATH).exists() {
            std::fs::remove_file(CA_CERT_PATH).context("removing CA certificate file")?;
        }

        run_command_check("update-ca-certificates", &[])?;

        info!("CA certificate removed and trust store updated");
        Ok(())
    }

    fn is_ca_installed(&self, _cert_pem_path: &Path) -> Result<bool> {
        Ok(Path::new(CA_CERT_PATH).exists())
    }

    fn install_service(&self, exe_path: &Path, config_path: &Path) -> Result<()> {
        let exe = exe_path.to_string_lossy();
        let config = config_path.to_string_lossy();

        info!("Installing Guardian agent as systemd service");

        let unit_contents = format!(
            "\
[Unit]
Description=Guardian Secret Proxy Agent
After=network.target

[Service]
Type=simple
ExecStart={exe} run --config {config}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"
        );

        std::fs::write(UNIT_FILE_PATH, unit_contents).context("writing systemd unit file")?;

        run_command_check("systemctl", &["daemon-reload"])?;
        run_command_check("systemctl", &["enable", SERVICE_NAME])?;

        info!("Guardian agent systemd service installed and enabled");
        Ok(())
    }

    fn uninstall_service(&self) -> Result<()> {
        info!("Uninstalling Guardian agent systemd service");

        // Stop and disable (ignore errors if not running)
        let _ = run_command("systemctl", &["stop", SERVICE_NAME]);
        let _ = run_command("systemctl", &["disable", SERVICE_NAME]);

        if Path::new(UNIT_FILE_PATH).exists() {
            std::fs::remove_file(UNIT_FILE_PATH).context("removing systemd unit file")?;
        }

        run_command_check("systemctl", &["daemon-reload"])?;

        info!("Guardian agent systemd service uninstalled");
        Ok(())
    }

    fn is_service_installed(&self) -> Result<bool> {
        Ok(Path::new(UNIT_FILE_PATH).exists())
    }

    fn start_service(&self) -> Result<()> {
        info!("Starting Guardian agent service");
        run_command_check("systemctl", &["start", SERVICE_NAME])?;
        info!("Guardian agent service started");
        Ok(())
    }

    fn stop_service(&self) -> Result<()> {
        info!("Stopping Guardian agent service");
        run_command_check("systemctl", &["stop", SERVICE_NAME])?;
        info!("Guardian agent service stopped");
        Ok(())
    }

    fn configure_runtime_trust(&self, ca_cert_path: &Path) -> Result<RuntimeTrustState> {
        let data_dir = guardian_data_dir_linux();
        std::fs::create_dir_all(&data_dir).context("creating Guardian data directory")?;

        let guardian_ca_path = data_dir.join("guardian-ca.pem");

        // Copy Guardian CA cert
        std::fs::copy(ca_cert_path, &guardian_ca_path).context("copying Guardian CA cert")?;
        info!(path = %guardian_ca_path.display(), "Copied Guardian CA cert");

        // On Linux, update-ca-certificates handles most runtimes.
        // We only need NODE_EXTRA_CA_CERTS for Node.js.
        let env_vars = vec![(
            "NODE_EXTRA_CA_CERTS",
            guardian_ca_path.to_string_lossy().to_string(),
        )];

        let mut original_env_vars = HashMap::new();

        for (name, value) in &env_vars {
            let original = read_etc_environment_var(name);
            original_env_vars.insert(name.to_string(), original);
            set_etc_environment_var(name, value)
                .with_context(|| format!("setting {} in /etc/environment", name))?;
            info!(
                var = name,
                value = value,
                "Set environment variable in /etc/environment"
            );
        }

        Ok(RuntimeTrustState {
            configured: true,
            ca_bundle_path: None,
            guardian_ca_path: Some(guardian_ca_path),
            original_env_vars,
        })
    }

    fn remove_runtime_trust(&self, state: &RuntimeTrustState) -> Result<()> {
        for (name, original) in &state.original_env_vars {
            match original {
                Some(value) => {
                    set_etc_environment_var(name, value)
                        .with_context(|| format!("restoring {} in /etc/environment", name))?;
                    info!(var = name, "Restored original environment variable");
                }
                None => {
                    remove_etc_environment_var(name)
                        .with_context(|| format!("removing {} from /etc/environment", name))?;
                    info!(
                        var = name,
                        "Removed environment variable from /etc/environment"
                    );
                }
            }
        }

        // Delete cert file
        if let Some(ref path) = state.guardian_ca_path {
            if path.exists() {
                std::fs::remove_file(path).ok();
            }
        }

        info!("Runtime CA trust removed");
        Ok(())
    }
}

/// Get the Guardian data directory on Linux (~/.config/guardian).
fn guardian_data_dir_linux() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("guardian")
}

/// Read a variable's value from /etc/environment.
fn read_etc_environment_var(name: &str) -> Option<String> {
    let contents = std::fs::read_to_string("/etc/environment").ok()?;
    let prefix = format!("{}=", name);
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&prefix) {
            let value = &trimmed[prefix.len()..];
            // Strip surrounding quotes if present
            let value = value.trim_matches('"').trim_matches('\'');
            return Some(value.to_string());
        }
    }
    None
}

/// Set a variable in /etc/environment (add or update).
fn set_etc_environment_var(name: &str, value: &str) -> Result<()> {
    let path = Path::new("/etc/environment");
    let contents = std::fs::read_to_string(path).unwrap_or_default();

    let prefix = format!("{}=", name);
    let new_line = format!("{}=\"{}\"", name, value);

    let mut found = false;
    let mut lines: Vec<String> = contents
        .lines()
        .map(|line| {
            if line.trim().starts_with(&prefix) {
                found = true;
                new_line.clone()
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(new_line);
    }

    // Ensure trailing newline
    let mut output = lines.join("\n");
    if !output.ends_with('\n') {
        output.push('\n');
    }

    std::fs::write(path, output).context("writing /etc/environment")?;
    Ok(())
}

/// Remove a variable from /etc/environment.
fn remove_etc_environment_var(name: &str) -> Result<()> {
    let path = Path::new("/etc/environment");
    let contents = std::fs::read_to_string(path).unwrap_or_default();

    let prefix = format!("{}=", name);
    let lines: Vec<&str> = contents
        .lines()
        .filter(|line| !line.trim().starts_with(&prefix))
        .collect();

    let mut output = lines.join("\n");
    if !output.ends_with('\n') && !output.is_empty() {
        output.push('\n');
    }

    std::fs::write(path, output).context("writing /etc/environment")?;
    Ok(())
}

/// Remove all guardian iptables rules by searching for the comment marker.
fn remove_rules_by_comment() -> Result<()> {
    let output = run_command(
        "iptables",
        &["-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers"],
    )?;

    if !output.status.success() {
        bail!("Failed to list iptables NAT OUTPUT rules");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse line numbers for guardian rules (in reverse order to preserve indices)
    let mut line_numbers: Vec<u32> = Vec::new();
    for line in stdout.lines() {
        if line.contains(IPTABLES_COMMENT) {
            if let Some(num_str) = line.split_whitespace().next() {
                if let Ok(num) = num_str.parse::<u32>() {
                    line_numbers.push(num);
                }
            }
        }
    }

    // Delete in reverse order so line numbers stay valid
    line_numbers.reverse();
    for num in line_numbers {
        let _ = run_command("iptables", &["-t", "nat", "-D", "OUTPUT", &num.to_string()]);
    }

    Ok(())
}
