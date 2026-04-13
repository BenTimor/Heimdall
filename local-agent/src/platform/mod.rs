use crate::config::TransparentConfig;
use crate::state::RuntimeTrustState;
use anyhow::Result;
use std::path::Path;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windivert;
#[cfg(target_os = "windows")]
pub mod windows;

/// Platform-specific operations for traffic interception, certificate management,
/// and service management.
pub trait PlatformOps {
    /// Enable transparent traffic interception, redirecting TCP:443 to the given port.
    fn enable_interception(
        &self,
        transparent_config: &TransparentConfig,
        local_proxy_port: u16,
    ) -> Result<()>;

    /// Disable transparent traffic interception.
    fn disable_interception(&self) -> Result<()>;

    /// Check if traffic interception is currently active.
    fn is_interception_active(
        &self,
        transparent_config: &TransparentConfig,
        local_proxy_port: u16,
    ) -> Result<bool>;

    /// Install the CA certificate into the system/user trust store.
    fn install_ca_cert(&self, cert_pem_path: &Path) -> Result<()>;

    /// Remove the CA certificate from the system/user trust store.
    fn uninstall_ca_cert(&self) -> Result<()>;

    /// Check if the CA certificate is installed.
    #[allow(dead_code)]
    fn is_ca_installed(&self, cert_pem_path: &Path) -> Result<bool>;

    /// Register the agent as a system service.
    fn install_service(&self, exe_path: &Path, config_path: &Path) -> Result<()>;

    /// Unregister the agent system service.
    fn uninstall_service(&self) -> Result<()>;

    /// Check if the agent service is installed.
    fn is_service_installed(&self) -> Result<bool>;

    /// Start the agent system service.
    fn start_service(&self) -> Result<()>;

    /// Stop the agent system service.
    fn stop_service(&self) -> Result<()>;

    /// Configure runtime CA trust so runtimes with their own CA stores
    /// (Python, Node.js, Ruby, Go) trust the Heimdall CA certificate.
    fn configure_runtime_trust(&self, ca_cert_path: &Path) -> Result<RuntimeTrustState>;

    /// Remove runtime CA trust configuration, restoring original env var values.
    fn remove_runtime_trust(&self, state: &RuntimeTrustState) -> Result<()>;
}

/// Get the platform-specific implementation.
pub fn platform() -> Box<dyn PlatformOps> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsPlatform::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }
}

/// Check if the current process has elevated/root privileges.
pub fn check_privileges() -> Result<bool> {
    #[cfg(target_os = "windows")]
    {
        windows::is_elevated()
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("id").arg("-u").output()?;
        let uid: u32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap_or(1000);
        Ok(uid == 0)
    }
}
