use std::path::Path;
use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use super::PlatformOps;

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
                "-t", "nat",
                "-A", "OUTPUT",
                "-p", "tcp",
                "--dport", "443",
                "-m", "owner", "!", "--uid-owner", &uid,
                "-m", "comment", "--comment", IPTABLES_COMMENT,
                "-j", "REDIRECT",
                "--to-port", &transparent_port.to_string(),
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
                "-t", "nat",
                "-D", "OUTPUT",
                "-p", "tcp",
                "--dport", "443",
                "-m", "owner", "!", "--uid-owner", &uid,
                "-m", "comment", "--comment", IPTABLES_COMMENT,
                "-j", "REDIRECT",
                "--to-port", "0",
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
        let output = run_command("iptables", &["-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers"])?;

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
            std::fs::remove_file(CA_CERT_PATH)
                .context("removing CA certificate file")?;
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

        std::fs::write(UNIT_FILE_PATH, unit_contents)
            .context("writing systemd unit file")?;

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
            std::fs::remove_file(UNIT_FILE_PATH)
                .context("removing systemd unit file")?;
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
}

/// Remove all guardian iptables rules by searching for the comment marker.
fn remove_rules_by_comment() -> Result<()> {
    let output = run_command("iptables", &["-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers"])?;

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
        let _ = run_command("iptables", &[
            "-t", "nat", "-D", "OUTPUT", &num.to_string(),
        ]);
    }

    Ok(())
}
