use crate::bpf_base::*;
use std::mem::size_of;
use std::os::unix::io::AsRawFd;

impl BPFOperations for BPFFProg<'_> {
    fn attach_filter<T>(self, socket: &T) -> Result<(), i32>
    where
        T: AsRawFd,
    {
        match unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
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

/// remove the classic BPF program attached to a socket
pub fn detach_filter<T>(socket: &T) -> Result<(), i32>
where
    T: AsRawFd,
{
    match unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_DETACH_FILTER,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    } {
        0 => Ok(()),
        errno => Err(errno),
    }
}
// test
