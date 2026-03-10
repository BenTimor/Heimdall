mod agent;
mod config;
mod health;
mod local_proxy;
mod platform;
mod sni;
mod state;
mod transparent;
mod tunnel;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "guardian-agent", about = "Guardian local proxy agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the agent
    Run {
        /// Path to config YAML file
        #[arg(short, long, default_value = "config/agent-config.yaml")]
        config: PathBuf,
        /// Run in Windows service mode (hidden, used by service manager)
        #[arg(long, hide = true)]
        service_mode: bool,
    },
    /// Test connectivity to tunnel server
    Test {
        /// Path to config YAML file
        #[arg(short, long, default_value = "config/agent-config.yaml")]
        config: PathBuf,
    },
    /// Show agent status via health endpoint
    Status {
        /// Health endpoint URL
        #[arg(short, long, default_value = "http://127.0.0.1:19876")]
        url: String,
    },
    /// Install Guardian: set up CA cert, enable interception, optionally install service
    Install {
        /// Path to config YAML file
        #[arg(short, long, default_value = "config/agent-config.yaml")]
        config: PathBuf,
        /// Path to the CA certificate PEM file to install
        #[arg(long)]
        ca_cert: PathBuf,
        /// Skip CA certificate installation
        #[arg(long)]
        no_cert: bool,
        /// Skip enabling traffic interception
        #[arg(long)]
        no_interception: bool,
        /// Also install as a system service
        #[arg(long)]
        service: bool,
    },
    /// Uninstall Guardian: reverse all install actions
    Uninstall {
        /// Force uninstall even if state file is missing
        #[arg(long)]
        force: bool,
    },
    /// Manage the Guardian system service
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install the agent as a system service
    Install {
        /// Path to config YAML file
        #[arg(short, long, default_value = "config/agent-config.yaml")]
        config: PathBuf,
    },
    /// Uninstall the agent system service
    Uninstall,
    /// Start the agent service
    Start,
    /// Stop the agent service
    Stop,
    /// Show service status
    Status,
}

fn main() {
    // Run the real entry point on a thread with a larger stack.
    // The async state machine for agent::run (TLS handshake + Framed codec)
    // plus WinDivert FFI need more than the default 1 MB Windows stack.
    const STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

    let result = std::thread::Builder::new()
        .name("guardian-main".into())
        .stack_size(STACK_SIZE)
        .spawn(run)
        .expect("failed to spawn runtime thread")
        .join()
        .expect("runtime thread panicked");

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Synchronous commands run directly — no tokio runtime, no async futures.
    match cli.command {
        Command::Install { config: ref config_path, ref ca_cert, no_cert, no_interception, service } => {
            return cmd_install(config_path, ca_cert, no_cert, no_interception, service);
        }
        Command::Uninstall { force } => {
            return cmd_uninstall(force);
        }
        Command::Service { action } => {
            return cmd_service(action);
        }
        _ => {}
    }

    // Async commands go through a separate #[inline(never)] function.
    // This prevents LLVM from merging the async future's stack allocation
    // into run()'s prologue, which would overflow even for sync commands
    // that return early (LLVM allocates the full frame at function entry).
    run_async_commands(cli.command)
}

/// Runs async commands (run, test, status) on a tokio runtime.
///
/// Must be `#[inline(never)]` so its large stack frame (the async state
/// machine temporary from `Box::pin(run_async(...))`) is NOT merged into
/// the caller's frame.  Without this, `run()`'s prologue allocates space
/// for the future even when handling sync commands like `install`.
#[inline(never)]
fn run_async_commands(command: Command) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(Box::pin(run_async(command)))
}

async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Run { config: config_path, service_mode: _ } => {
            let cfg = config::AgentConfig::load(&config_path)?;
            init_tracing(&cfg.logging.level);
            Box::pin(agent::run(cfg)).await?;
        }
        Command::Test { config: config_path } => {
            let cfg = config::AgentConfig::load(&config_path)?;
            init_tracing(&cfg.logging.level);
            println!("Testing connection to {}:{}...", cfg.server.host, cfg.server.port);
            match Box::pin(tunnel::client::connect_and_auth(&cfg.server, &cfg.auth)).await {
                Ok(_) => println!("Connection and authentication successful!"),
                Err(e) => {
                    eprintln!("Connection test failed: {:#}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::Status { url } => {
            cmd_status(&url).await?;
        }
        _ => unreachable!("sync commands handled before runtime creation"),
    }

    Ok(())
}

/// Handle the `status` subcommand.
async fn cmd_status(url: &str) -> Result<()> {
    let url = url.trim_end_matches('/');
    let health_url = format!("{}/health", url);
    let addr = url.strip_prefix("http://").unwrap_or(url);

    match tokio::net::TcpStream::connect(addr).await {
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let request = format!(
                "GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                addr
            );
            stream.write_all(request.as_bytes()).await?;
            let mut response = String::new();
            stream.read_to_string(&mut response).await?;
            if let Some(pos) = response.find("\r\n\r\n") {
                let body = &response[pos + 4..];
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else {
                    println!("{}", body);
                }
            } else {
                println!("{}", response);
            }
        }
        Err(e) => {
            eprintln!("Could not reach agent at {}: {}", health_url, e);
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Handle the `install` subcommand.
fn cmd_install(
    config_path: &PathBuf,
    ca_cert: &PathBuf,
    no_cert: bool,
    no_interception: bool,
    install_service: bool,
) -> Result<()> {
    let cfg = config::AgentConfig::load(config_path)?;
    let ops = platform::platform();

    // Check privileges
    let elevated = platform::check_privileges()?;
    if !elevated {
        eprintln!("Warning: Running without elevated privileges. Some operations may fail.");
        eprintln!("  On Windows: run as Administrator");
        eprintln!("  On Linux: run with sudo");
    }

    let mut install_state = state::InstallState::new();
    let mut summary = Vec::new();

    // Install CA certificate
    if !no_cert {
        print!("Installing CA certificate... ");
        match ops.install_ca_cert(ca_cert) {
            Ok(()) => {
                install_state.ca_cert_installed = true;
                install_state.ca_cert_path = Some(ca_cert.clone());
                summary.push("CA certificate installed");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("CA certificate FAILED");
            }
        }
    }

    // Enable traffic interception
    if !no_interception {
        let transparent_port = cfg.transparent.port;
        print!("Enabling traffic interception (port {})... ", transparent_port);
        match ops.enable_interception(transparent_port) {
            Ok(()) => {
                install_state.interception_enabled = true;
                summary.push("Traffic interception enabled");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("Traffic interception FAILED");
            }
        }
    }

    // Install system service
    if install_service {
        let exe_path = std::env::current_exe().context("getting current exe path")?;
        print!("Installing system service... ");
        match ops.install_service(&exe_path, config_path) {
            Ok(()) => {
                install_state.service_installed = true;
                summary.push("System service installed");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("System service FAILED");
            }
        }
    }

    // Save state
    install_state.save().context("saving install state")?;

    println!("\nInstall summary:");
    for item in &summary {
        println!("  - {}", item);
    }
    println!("State saved to: {}", state::InstallState::state_path().display());

    Ok(())
}

/// Handle the `uninstall` subcommand.
fn cmd_uninstall(force: bool) -> Result<()> {
    let install_state = state::InstallState::load()?;

    let install_state = match install_state {
        Some(s) => s,
        None => {
            if force {
                eprintln!("No install state found, performing forced cleanup...");
                let mut s = state::InstallState::new();
                s.ca_cert_installed = true;
                s.interception_enabled = true;
                s.service_installed = true;
                s
            } else {
                eprintln!("No install state found. Nothing to uninstall.");
                eprintln!("Use --force to attempt cleanup anyway.");
                return Ok(());
            }
        }
    };

    let ops = platform::platform();
    let mut summary = Vec::new();

    // Disable traffic interception
    if install_state.interception_enabled {
        print!("Disabling traffic interception... ");
        match ops.disable_interception() {
            Ok(()) => {
                summary.push("Traffic interception disabled");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("Traffic interception removal FAILED");
            }
        }
    }

    // Uninstall CA certificate
    if install_state.ca_cert_installed {
        print!("Removing CA certificate... ");
        match ops.uninstall_ca_cert() {
            Ok(()) => {
                summary.push("CA certificate removed");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("CA certificate removal FAILED");
            }
        }
    }

    // Uninstall service
    if install_state.service_installed {
        print!("Stopping service... ");
        let _ = ops.stop_service();
        println!("done");

        print!("Removing system service... ");
        match ops.uninstall_service() {
            Ok(()) => {
                summary.push("System service removed");
                println!("done");
            }
            Err(e) => {
                println!("FAILED: {:#}", e);
                summary.push("System service removal FAILED");
            }
        }
    }

    // Delete state file
    state::InstallState::delete().ok();

    println!("\nUninstall summary:");
    for item in &summary {
        println!("  - {}", item);
    }

    Ok(())
}

/// Handle the `service` subcommand.
fn cmd_service(action: ServiceCommand) -> Result<()> {
    let ops = platform::platform();

    match action {
        ServiceCommand::Install { config: config_path } => {
            let exe_path = std::env::current_exe().context("getting current exe path")?;
            print!("Installing system service... ");
            ops.install_service(&exe_path, &config_path)?;
            println!("done");
        }
        ServiceCommand::Uninstall => {
            print!("Removing system service... ");
            ops.uninstall_service()?;
            println!("done");
        }
        ServiceCommand::Start => {
            print!("Starting service... ");
            ops.start_service()?;
            println!("done");
        }
        ServiceCommand::Stop => {
            print!("Stopping service... ");
            ops.stop_service()?;
            println!("done");
        }
        ServiceCommand::Status => {
            let installed = ops.is_service_installed()?;
            let interception = ops.is_interception_active()?;

            println!("Service installed: {}", if installed { "yes" } else { "no" });
            println!("Traffic interception: {}", if interception { "active" } else { "inactive" });

            if let Some(state) = state::InstallState::load()? {
                println!("Install state:");
                println!("  Installed at: {}", state.installed_at);
                println!("  CA cert: {}", if state.ca_cert_installed { "installed" } else { "not installed" });
                println!("  Interception: {}", if state.interception_enabled { "enabled" } else { "disabled" });
                println!("  Service: {}", if state.service_installed { "installed" } else { "not installed" });
            }
        }
    }

    Ok(())
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}
