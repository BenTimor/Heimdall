use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

use super::PlatformOps;
use crate::state::RuntimeTrustState;

const SERVICE_NAME: &str = "guardian-agent";
const UNIT_FILE_PATH: &str = "/etc/systemd/system/guardian-agent.service";
const CA_CERT_PATH: &str = "/usr/local/share/ca-certificates/guardian-proxy.crt";
const IPTABLES_COMMENT: &str = "guardian-redirect";
const NAT_OUTPUT_LIST_ARGS: [&str; 6] = ["-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterceptionTable {
    program: &'static str,
    family: &'static str,
}

const INTERCEPTION_TABLES: [InterceptionTable; 2] = [
    InterceptionTable {
        program: "iptables",
        family: "IPv4",
    },
    InterceptionTable {
        program: "ip6tables",
        family: "IPv6",
    },
];

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
            "Enabling transparent REDIRECT rules for outbound TCP:443"
        );

        // Remove any stale Guardian rules first so reinstalling can repair an
        // older redirect target without accumulating duplicates.
        remove_all_guardian_rules()?;

        if let Err(error) = add_all_redirect_rules(&uid, transparent_port) {
            let rollback_error = remove_all_guardian_rules().err();
            return Err(match rollback_error {
                Some(rollback_error) => anyhow!(
                    "failed to enable dual-stack transparent interception: {:#}; cleanup after partial failure also failed: {:#}",
                    error,
                    rollback_error
                ),
                None => error.context("failed to enable dual-stack transparent interception"),
            });
        }

        info!("iptables/ip6tables REDIRECT rules added");
        Ok(())
    }

    fn disable_interception(&self) -> Result<()> {
        info!("Disabling transparent REDIRECT rules");
        remove_all_guardian_rules()?;
        info!("iptables/ip6tables REDIRECT rules removed");
        Ok(())
    }

    fn is_interception_active(&self) -> Result<bool> {
        for table in interception_tables() {
            if !table_has_guardian_rule(table.program)? {
                return Ok(false);
            }
        }
        Ok(true)
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

fn interception_tables() -> &'static [InterceptionTable] {
    &INTERCEPTION_TABLES
}

fn run_command_check_owned(program: &str, args: &[String]) -> Result<()> {
    let borrowed_args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command_check(program, &borrowed_args)
}

fn build_redirect_rule_args(uid: &str, transparent_port: u16) -> Vec<String> {
    vec![
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        "OUTPUT".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--dport".to_string(),
        "443".to_string(),
        "-m".to_string(),
        "owner".to_string(),
        "!".to_string(),
        "--uid-owner".to_string(),
        uid.to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        IPTABLES_COMMENT.to_string(),
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-port".to_string(),
        transparent_port.to_string(),
    ]
}

fn build_delete_rule_args(line_number: u32) -> Vec<String> {
    vec![
        "-t".to_string(),
        "nat".to_string(),
        "-D".to_string(),
        "OUTPUT".to_string(),
        line_number.to_string(),
    ]
}

fn parse_guardian_rule_line_numbers(stdout: &str) -> Vec<u32> {
    let mut line_numbers = Vec::new();
    for line in stdout.lines() {
        if !line.contains(IPTABLES_COMMENT) {
            continue;
        }

        if let Some(num_str) = line.split_whitespace().next() {
            if let Ok(num) = num_str.parse::<u32>() {
                line_numbers.push(num);
            }
        }
    }
    line_numbers
}

fn list_guardian_rule_line_numbers(program: &str) -> Result<Vec<u32>> {
    let output = run_command(program, &NAT_OUTPUT_LIST_ARGS)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{} {} failed: {}",
            program,
            NAT_OUTPUT_LIST_ARGS.join(" "),
            stderr
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_guardian_rule_line_numbers(&stdout))
}

fn table_has_guardian_rule(program: &str) -> Result<bool> {
    Ok(!list_guardian_rule_line_numbers(program)?.is_empty())
}

fn add_all_redirect_rules(uid: &str, transparent_port: u16) -> Result<()> {
    for table in interception_tables() {
        let args = build_redirect_rule_args(uid, transparent_port);
        run_command_check_owned(table.program, &args).with_context(|| {
            format!(
                "adding {} transparent redirect rule via {}",
                table.family, table.program
            )
        })?;
    }
    Ok(())
}

fn remove_rules_by_comment(program: &str) -> Result<()> {
    let mut line_numbers = list_guardian_rule_line_numbers(program)?;

    // Delete in reverse order so line numbers stay valid.
    line_numbers.reverse();
    for num in line_numbers {
        let args = build_delete_rule_args(num);
        run_command_check_owned(program, &args)
            .with_context(|| format!("removing Guardian redirect rule {} via {}", num, program))?;
    }

    Ok(())
}

fn remove_all_guardian_rules() -> Result<()> {
    let mut errors = Vec::new();

    for table in interception_tables() {
        if let Err(error) = remove_rules_by_comment(table.program) {
            errors.push(format!("{}: {:#}", table.program, error));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to remove existing transparent redirect rules: {}",
            errors.join("; ")
        )
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

#[cfg(test)]
mod tests {
    use super::{
        build_delete_rule_args, build_redirect_rule_args, interception_tables,
        parse_guardian_rule_line_numbers,
    };

    #[test]
    fn interception_tables_cover_ipv4_and_ipv6() {
        let tables = interception_tables();
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].program, "iptables");
        assert_eq!(tables[1].program, "ip6tables");
    }

    #[test]
    fn build_redirect_rule_args_redirects_tcp_443_to_listener_port() {
        let args = build_redirect_rule_args("1000", 19443);
        assert_eq!(
            args,
            vec![
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
                "1000",
                "-m",
                "comment",
                "--comment",
                "guardian-redirect",
                "-j",
                "REDIRECT",
                "--to-port",
                "19443",
            ]
        );
    }

    #[test]
    fn parse_guardian_rule_line_numbers_ignores_unrelated_rules() {
        let listing = "\
num  target     prot opt source               destination
1    RETURN     tcp  --  anywhere             anywhere             owner UID match 0 tcp dpt:https
2    REDIRECT   tcp  --  anywhere             anywhere             owner UID match ! 1000 /* guardian-redirect */ redir ports 19443
3    REDIRECT   tcp  --  anywhere             anywhere             tcp dpt:https redir ports 12345
7    REDIRECT   tcp  --  anywhere             anywhere             owner UID match ! 1000 /* guardian-redirect */ redir ports 19443
";

        assert_eq!(parse_guardian_rule_line_numbers(listing), vec![2, 7]);
    }

    #[test]
    fn build_delete_rule_args_uses_output_line_number() {
        assert_eq!(
            build_delete_rule_args(7),
            vec!["-t", "nat", "-D", "OUTPUT", "7"]
        );
    }
}
