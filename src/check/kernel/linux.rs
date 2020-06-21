//! Kernel security mitigation checker that can be deployed on a Linux host.

use crate::check::{FeatureCheck, FeatureMap};
use crate::check::kernel::KernelCheck;

use serde::{Serialize, Deserialize};

use sysctl::Sysctl;

use std::path::Path;

#[derive(Serialize, Deserialize)]
enum Aslr {
    Stack,
    Mmap,
    Exec,
    Brk,
    Vdso
}

#[derive(Serialize, Deserialize)]
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
        feature_map
    }
}

impl KernelCheck for LinuxKernelChecker {
    fn check() -> Self {
        // check if path exists to determine if AppArmor is loaded in kernel
        let apparmor: bool = Path::new("/sys/kernel/security/apparmor").exists();

        // get ptrace permissions from sysctl settings
        let ps_ctl = sysctl::Ctl::new("kernel.yama.ptrace_scope").unwrap();
        let ptrace_scope_val: PtraceScope = match ps_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => {
                match val {
                    0 => PtraceScope::Classic,
                    1 => PtraceScope::Restricted,
                    2 => PtraceScope::AdminOnly,
                    3 => PtraceScope::NoAttach,
                    _ => PtraceScope::None,
                }
            },
            _ => PtraceScope::None,
        };

        // check if ASLR is enabled
        let aslr_ctl = sysctl::Ctl::new("kernel.randomize_va_sapce").unwrap();
        let aslr_val: bool = match aslr_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => {
                match val {
                    0 => false,
                    1 | _ => true,
                }
            }
            _ => false
        };

        todo!()
    }
}
