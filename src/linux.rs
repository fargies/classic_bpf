use crate::bpf_base::*;
use std::os::unix::io::RawFd;
use std::mem::size_of;

impl BPFOperations for BPFFProg {
    fn attach_filter(self, socket_raw_fd: RawFd) -> Result<(), i32> {
        match unsafe {
            libc::setsockopt(
                socket_raw_fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &self as *const _ as *const libc::c_void,
                size_of::<BPFFProg>() as u32,
            )
        } {
            0 => Ok(()),
            errno => Err(errno),
        }
    }
}

// test