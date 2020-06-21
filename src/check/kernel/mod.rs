//! Defines the kernel security checks configured for the current host's operating system, if it is
//! supported by binsec.

pub mod linux;

use crate::check::FeatureCheck;
use crate::errors::{BinError, BinResult, ErrorKind};

use platforms::target::OS;

use std::boxed::Box;

/// used to define rudimentary trait to represent a kernel-based security checker
pub trait KernelCheck {
    fn check() -> Self;
}

/// used to represent a kernel-checker interface, which encapsulates the OS detection functionality
/// and all the checks being used on the host.
pub struct KernelChecker;

impl KernelChecker {
    pub fn detect() -> BinResult<Box<dyn FeatureCheck>> {
        if let Some(platform) = platforms::guess_current() {
            match platform.target_os {
                OS::Linux | OS::Android => {
                    return Ok(Box::new(linux::LinuxKernelChecker::check()))
                },
                OS::MacOS => {
                    return Err(BinError {
                        kind: ErrorKind::KernelCheckError,
                        msg: "Darwin kernel security checks not yet supported".to_string(),
                    });
                },
                OS::Windows => {
                    return Err(BinError {
                        kind: ErrorKind::KernelCheckError,
                        msg: "Win32 kernel security checks not yet supported".to_string(),
                    });
                },
                _ => {
                    return Err(BinError {
                        kind: ErrorKind::KernelCheckError,
                        msg: "unknown unsupported operating system".to_string(),
                    });
                }
            }
        } else {
            Err(BinError {
                kind: ErrorKind::KernelCheckError,
                msg: "cannot determine the platform the host is running on".to_string(),
            })
        }
    }
}
