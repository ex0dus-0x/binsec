//! Kernel security mitigation checker that can be deployed on a Linux host. Checks for the the
//! following features on the host:
//!
//! * AppArmor
//! * ASLR
//! * kASLR
//! * `ptrace` scope
//! * /dev/mem access
//! * /dev/kmem access
//! * Read-only kernel data sections
//! * Read-only Linux kernel modules
//! * Kernel stack protector

use crate::check::kernel::KernelCheck;
use crate::errors::BinResult;
use crate::format::{BinTable, FeatureMap};

use serde::{Deserialize, Serialize};

use structmap::ToHashMap;
use structmap_derive::ToHashMap;

use sysctl::Sysctl;

use std::fs;
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
#[derive(Serialize, Deserialize,Debug)]
enum PtraceScope {
    Classic,
    Restricted,
    AdminOnly,
    NoAttach,
    None,
}

#[derive(Serialize, Deserialize, ToHashMap)]
pub struct LinuxKernelChecker {
    //#[rename("AppArmor")]
    apparmor: bool,

    //#[rename("Ptrace Scope")]
    ptrace_scope: PtraceScope,

    //#[rename("ASLR")]
    aslr: bool, // TODO: aslr type

    //#[rename("kASLR")]
    kaslr: bool,

    //#[rename("/dev/mem protection")]
    dev_mem_protected: bool,

    //#[rename("/dev/kmem protection")]
    dev_kmem_access: bool,

    //#[rename("Read-only data sections")]
    ro_kernel_sections: bool,

    //#[rename("Read-only kernel modules")]
    ro_kernel_modules: bool,

    //#[rename("Kernel Stack Protector")]
    kernel_stack_protector: bool,
}

impl KernelCheck for LinuxKernelChecker {
    fn check() -> BinResult<Self> {
        // check if path exists to determine if AppArmor is loaded in kernel
        let apparmor: bool = Path::new("/sys/kernel/security/apparmor").exists();

        // get ptrace permissions from sysctl settings
        let ps_ctl = sysctl::Ctl::new("kernel.yama.ptrace_scope").unwrap();
        let ptrace_scope: PtraceScope = match ps_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => match val {
                0 => PtraceScope::Classic,
                1 => PtraceScope::Restricted,
                2 => PtraceScope::AdminOnly,
                3 => PtraceScope::NoAttach,
                _ => PtraceScope::None,
            },
            sysctl::CtlValue::String(val) => match val.as_str() {
                "0" => PtraceScope::Classic,
                "1" => PtraceScope::Restricted,
                "2" => PtraceScope::AdminOnly,
                "3" => PtraceScope::NoAttach,
                _ => PtraceScope::None,
            },
            _ => PtraceScope::None,
        };

        // check if ASLR is enabled
        let aslr_ctl = sysctl::Ctl::new("kernel.randomize_va_space").unwrap();
        let aslr: bool = match aslr_ctl.value().unwrap() {
            sysctl::CtlValue::Int(val) => matches!(val, 1 | 2),
            sysctl::CtlValue::String(val) => matches!(val.as_str(), "1" | "2"),
            _ => false,
        };

        // check if kASLR is enabled through `/proc/cmdline`
        let kernel_params: String = fs::read_to_string("/proc/cmdline")?;

        // check if `kaslr` was configured for boot
        let kaslr: bool = kernel_params.contains("kaslr");

        // TODO: make following code more efficient?

        // check if /dev/mem protection is enabled
        let dev_mem: String = String::from("CONFIG_STRICT_DEVMEM");
        let dev_mem_protected: bool = LinuxKernelChecker::kernel_config_set(dev_mem)?;

        // check if /dev/kmem virtual device is enabled, which is a potential attack surface
        let dev_kmem: String = String::from("CONFIG_DEVKMEM");
        let dev_kmem_access: bool = LinuxKernelChecker::kernel_config_set(dev_kmem)?;

        // check if kernel data sections are read-only
        let ro_sections: String = String::from("CONFIG_DEBUG_RODATA");
        let ro_kernel_sections: bool = LinuxKernelChecker::kernel_config_set(ro_sections)?;

        // check if kernel linux modules are read-only
        let ro_modules: String = String::from("CONFIG_DEBUG_MODULE_RONX");
        let ro_kernel_modules: bool = LinuxKernelChecker::kernel_config_set(ro_modules)?;

        let kern_protect: String = String::from("CONFIG_CC_STACKPROTECTOR");
        let kernel_stack_protector: bool = LinuxKernelChecker::kernel_config_set(kern_protect)?;

        Ok(Self {
            apparmor,
            ptrace_scope,
            aslr,
            kaslr,
            dev_mem_protected,
            dev_kmem_access,
            ro_kernel_sections,
            ro_kernel_modules,
            kernel_stack_protector,
        })
    }
}
