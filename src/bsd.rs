use crate::bpf_base::*;
use std::os::unix::io::AsRawFd;

impl AttachFilter for BPFFProg {
    fn attach_filter<T>(self, socket_raw_fd<T>: impl AsRawFd) -> Result<(), i32> {
        match unsafe {
            libc::ioctl(
                socket.as_raw_fd(),
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
