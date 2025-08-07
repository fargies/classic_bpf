/*
 * quoted from openbsd/src: sys/net/bpf.h
 *
 * seems it is compatible with MIT
 */

use std::os::unix::io::AsRawFd;

/// element of a classic BPF program
///
/// it is `libc::sock_filter` for Linux systems
///
/// it is `bf_insn` for FreeBSD systems
///
/// # Example
///
/// ```
/// use classic_bpf::*;
/// // a filter that will drop all contents of the incoming packet
/// let filter1 = BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, 0);
///
/// // a filter that will check the value in the register
/// // and execute the next command of the BPF program (when it matches libc::IPPROTO_ICMPV6)
/// // or execute the command after the next (when does not match)
/// let filter2 = BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, libc::IPPROTO_ICMPV6 as u32, 0, 1);
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct BPFFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BPFFilter {
    /// #define BPF_STMT(code, k) { (u_int16_t)(code), 0, 0, k }
    #[inline]
    pub fn bpf_stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// #define BPF_JUMP(code, k, jt, jf) { (u_int16_t)(code), jt, jf, k }
    #[inline]
    pub fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// represents a classic BPF program
///
/// # Example
///
/// ```
/// use classic_bpf::*;
///
/// // filter the ICMPv6 packets
/// let filters = [
///     BPFFilter::bpf_stmt((BPF_LD | BPF_B | BPF_ABS) as u16, 6),
///     BPFFilter::bpf_jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, libc::IPPROTO_ICMPV6 as u32, 0, 1),
///     BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, u32::MAX),
///     BPFFilter::bpf_stmt((BPF_RET | BPF_K) as u16, 0),
/// ];
///
/// let program = BPFFProg::new(&filters);
///
/// // do not forget to attach it to a socket
/// // let socket = socket2::Socket::new(...);
/// // program.attach_filter(socket);
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct BPFFProg<'a> {
    len: u16,
    filters: &'a BPFFilter,
}

impl<'a> BPFFProg<'a> {
    pub fn new(filters: &'a [BPFFilter]) -> Self {
        Self {
            len: filters.len() as u16,
            filters: unsafe { &*(filters.as_ptr()) },
        }
    }
}

/// safe wrapper for some operations related to BPFProg
pub trait BPFOperations {
    /// attach the classic BPF program to a socket
    fn attach_filter<T>(self, socket: &T) -> Result<(), i32>
    where
        T: AsRawFd;
}

// TODO: more documentation
/* instruction classes */
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

/* ld/ldx fields */
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;
pub const BPF_RND: u16 = 0xc0;

/* alu/jmp fields */
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

/* ret - BPF_K and BPF_X also apply */
pub const BPF_A: u16 = 0x10;

/* misc */
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;

#[test]
fn test_bpf_stmt() {
    let item = BPFFilter::bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 6);
    let reference = BPFFilter {
        code: 0x30,
        jt: 0,
        jf: 0,
        k: 0x6,
    };
    assert_eq!(item.code, reference.code);
    assert_eq!(item.jt, reference.jt);
    assert_eq!(item.jf, reference.jf);
    assert_eq!(item.k, reference.k);
}

#[test]
fn test_bpf_jump() {
    let item = BPFFilter::bpf_jump(
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        libc::IPPROTO_ICMPV6 as u32,
        0,
        3,
    );
    let reference = BPFFilter {
        code: 0x15,
        jt: 0,
        jf: 0x3,
        k: 0x3a,
    };
    assert_eq!(item.code, reference.code);
    assert_eq!(item.jt, reference.jt);
    assert_eq!(item.jf, reference.jf);
    assert_eq!(item.k, reference.k);
}
