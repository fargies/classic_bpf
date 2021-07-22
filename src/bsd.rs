use crate::bpf_base::*;
use std::os::unix::io::RawFd;

impl AttachFilter for BPFFProg {
    fn attach_filter(self, socket_raw_fd: RawFd) -> Result<(), i32> {
        match unsafe {
            libc::ioctl(
                socket_raw_fd,
                libc::BIOCSETF,
                &self as *const _ as *const libc::c_void,
            )
        } {
            0 => Ok(()),
            errno => Err(errno),
        }
    }
}

// test
