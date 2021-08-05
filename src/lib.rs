mod bpf_base;
pub use bpf_base::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "freebsd")]
mod bsd;
#[cfg(target_os = "freebsd")]
pub use bsd::*;
