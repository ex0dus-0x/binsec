//! Kernel security mitigation checker that can be deployed on a Linux host. Checks for the the
//! following features on the host:
//! * AppArmor
//! * ASLR
//! * kASLR
//! * `ptrace` scope
//! *

use crate::check::kernel::KernelCheck;
use crate::check::{FeatureCheck, FeatureMap};
use crate::errors::{BinResult, BinError, ErrorKind};

use serde::{Deserialize, Serialize};
use serde_json::json;

use sysctl::Sysctl;
use procfs::ConfigSetting;

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// TODO: make this work!!
#[derive(Serialize, Deserialize)]
enum Aslr {
    Stack,
    Mmap,
    Exec,
    Brk,
    Vdso,
}

/// defines the type of restriction being used on calls to `ptrace` when doing
/// any type of process introspection.
#[derive(Serialize, Deserialize, Debug)]
enum PtraceScope {
    Classic,
    Restricted,
    AdminOnly,
    NoAttach,
    None,
}

#[derive(Serialize, Deserialize)]
pub struct LinuxKernelChecker {
    apparmor: bool,
    ptrace_scope: PtraceScope,
    aslr: bool, // TODO: aslr type
    kaslr: bool,
    dev_mem_access: bool,
    dev_kmem_access: bool,
    ro_kernel_sections: bool,
    ro_kernel_modules: bool,
    kernel_stack_protector: bool,
}

#[typetag::serde]
impl FeatureCheck for LinuxKernelChecker {
    fn dump_mapping(&self) -> FeatureMap {
        let mut feature_map = FeatureMap::new();
        feature_map.insert("AppArmor", json!(self.apparmor));
        feature_map.insert("Ptrace Scope", json!(self.ptrace_scope));
        feature_map.insert("ASLR Enabled", json!(self.aslr));
        feature_map
    }
}

impl KernelCheck for LinuxKernelChecker {
    fn check() -> BinResult<Self> {
        // check if path exists to determine if AppArmor is loaded in kernel
        let apparmor: bool = Path::new("/sys/kernel/security/apparmor").exists();

        // get ptrace permissions from sysctl settings
        let ps_ctl = sysctl::Ctl::new("kernel.yama.ptrace_scope").unwrap();
        let ptrace_scope_val: PtraceScope = match ps_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => match val {
                0 => PtraceScope::Classic,
                1 => PtraceScope::Restricted,
                2 => PtraceScope::AdminOnly,
                3 => PtraceScope::NoAttach,
                _ => PtraceScope::None,
            },
            _ => PtraceScope::None,
        };

        // check if ASLR is enabled
        let aslr_ctl = sysctl::Ctl::new("kernel.randomize_va_space").unwrap();
        let aslr_val: bool = match aslr_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => match val {
                0 => false,
                1 | _ => true,
            },
            _ => false,
        };

        // check if kASLR is enabled through `/proc/cmdline`
        let mut procfile: File = File::open("/proc/cmdline")?;
        let mut kernel_params = String::new();
        procfile.read_to_string(&mut kernel_params)?;

        // check if `kaslr` was configured for boot
        let kaslr: bool = kernel_params.contains("kaslr");

        // check if /dev/mem protection is enabled

        // check if /dev/kmem virtual device is enabled, which is a potential attack surface
        let dev_kmem: String = String::from("CONFIG_DEVKMEM");
        let dev_kmem_access: bool = LinuxKernelChecker::kernel_config_set(dev_kmem);
        todo!()
    }
}
