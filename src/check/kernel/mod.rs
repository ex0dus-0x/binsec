//! Defines the kernel security checks configured for the current host's operating system, if it is
//! supported by binsec.

pub mod linux;

use crate::check::FeatureCheck;
use crate::errors::{BinError, BinResult, ErrorKind};

use platforms::platform::Platform;
use platforms::target::OS;
use procfs::ConfigSetting;

use std::boxed::Box;

/// used to define rudimentary trait to represent a kernel-based security checker
pub trait KernelCheck {
    fn check() -> BinResult<Self>
    where
        Self: std::marker::Sized;

    /// parses the kernel configuration and checks to see if a specific parameter is initialized
    /// as something, and returns true if exists.
    fn kernel_config_set(name: String) -> BinResult<bool> {
        let kernel_config = procfs::kernel_config().map_err(|e| BinError {
            kind: ErrorKind::KernelCheckError,
            msg: e.to_string(),
        })?;
        Ok(kernel_config.contains_key(&name))
    }

    /// parses the kernel configuration and returns the value a specific parameter is initialized
    /// as, and returns if exists.
    fn kernel_config_get(name: String) -> BinResult<String> {
        let kernel_config = procfs::kernel_config().map_err(|e| BinError {
            kind: ErrorKind::KernelCheckError,
            msg: e.to_string(),
        })?;

        // attempt to retrieve value and parse to string
        if let Some(value) = kernel_config.get(&name) {
            match value {
                ConfigSetting::Yes => Ok("y".to_string()),
                ConfigSetting::Module => Ok("m".to_string()),
                ConfigSetting::Value(val) => Ok(val.to_string()),
            }
        } else {
            Err(BinError {
                kind: ErrorKind::KernelCheckError,
                msg: format!(
                    "cannot get kernel configuration value for given key {}",
                    name
                ),
            })
        }
    }
}

/// used to represent a kernel-checker interface, which encapsulates the OS detection functionality
/// and all the checks being used on the host.
pub struct KernelChecker;

impl KernelChecker {
    pub fn detect() -> BinResult<Box<dyn FeatureCheck>> {
        if let Some(platform) = Platform::guess_current() {
            match platform.target_os {
                OS::Linux | OS::Android => Ok(Box::new(linux::LinuxKernelChecker::check()?)),
                OS::MacOS | OS::FreeBSD | OS::NetBSD => Err(BinError {
                    kind: ErrorKind::KernelCheckError,
                    msg: "Darwin/BSD kernel security checks not yet supported".to_string(),
                }),
                OS::Windows => Err(BinError {
                    kind: ErrorKind::KernelCheckError,
                    msg: "Windows kernel security checks not yet supported".to_string(),
                }),
                _ => Err(BinError {
                    kind: ErrorKind::KernelCheckError,
                    msg: "unknown unsupported operating system".to_string(),
                }),
            }
        } else {
            Err(BinError {
                kind: ErrorKind::KernelCheckError,
                msg: "cannot determine the platform the host is running on".to_string(),
            })
        }
    }
}
