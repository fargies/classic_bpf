//! # classic_bpf
//! see <https://github.com/freebsd/freebsd-src/blob/main/share/man/man4/bpf.4>

mod bpf_base;
pub use bpf_base::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod bsd;
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub use bsd::*;
