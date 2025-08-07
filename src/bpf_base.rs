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
/// let filter1 = BPFFilter::bpf_stmt(bpf::RET | bpf::K, 0);
///
/// // a filter that will check the value in the register
/// // and execute the next command of the BPF program (when it matches libc::IPPROTO_ICMPV6)
/// // or execute the command after the next (when does not match)
/// let filter2 = BPFFilter::bpf_jump(bpf::JMP | bpf::JEQ | bpf::K, libc::IPPROTO_ICMPV6 as u32, 0, 1);
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
    pub fn bpf_stmt<T>(code: T, k: u32) -> Self
    where
        T: BPFCode,
    {
        Self {
            code: code.value(),
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// #define BPF_JUMP(code, k, jt, jf) { (u_int16_t)(code), jt, jf, k }
    #[inline]
    pub fn bpf_jump(code: bpf::BPFJmp, k: u32, jt: u8, jf: u8) -> Self {
        Self {
            code: code.value(),
            jt,
            jf,
            k,
        }
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
///     BPFFilter::bpf_stmt(bpf::LD | bpf::B | bpf::ABS, 6),
///     BPFFilter::bpf_jump(bpf::JMP | bpf::JEQ | bpf::K, libc::IPPROTO_ICMPV6 as u32, 0, 1),
///     BPFFilter::bpf_stmt(bpf::RET | bpf::K, u32::MAX),
///     BPFFilter::bpf_stmt(bpf::RET | bpf::K, 0),
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

pub trait BPFCode {
    fn value(&self) -> u16;
}

pub mod bpf {
    use super::BPFCode;
    use std::ops::BitOr;

    macro_rules! add_inst {
        ($inst:ty) => {
            impl BPFCode for $inst {
                fn value(&self) -> u16 {
                    self.0
                }
            }
        };
    }

    macro_rules! add_op {
        ($inst:ty, $opt:ty) => {
            impl BitOr<$opt> for $inst {
                type Output = Self;

                fn bitor(self, rhs: $opt) -> Self::Output {
                    Self(self.0 | rhs.0)
                }
            }
        };
    }

    pub struct BPFLd(u16);
    add_inst!(BPFLd);
    add_op!(BPFLd, BPFSize);
    add_op!(BPFLd, BPFMode);

    pub struct BPFSt(u16);
    add_inst!(BPFSt);

    pub struct BPFAlu(u16);
    add_inst!(BPFAlu);
    add_op!(BPFAlu, BPFOp);
    add_op!(BPFAlu, BPFSrc);

    pub struct BPFJmp(u16);
    add_inst!(BPFJmp);
    add_op!(BPFJmp, BPFJmpOp);
    add_op!(BPFJmp, BPFSrc);

    pub struct BPFRet(u16);
    add_inst!(BPFRet);
    add_op!(BPFRet, BPFSrc);
    add_op!(BPFRet, BPFRetSrc);

    pub struct BPFMisc(u16);
    add_inst!(BPFMisc);
    add_op!(BPFMisc, BPFMiscOp);

    pub struct BPFSize(u16);
    pub struct BPFMode(u16);

    pub struct BPFOp(u16);
    pub struct BPFJmpOp(u16);
    pub struct BPFSrc(u16);
    pub struct BPFRetSrc(u16);
    pub struct BPFMiscOp(u16);

    pub const LD: BPFLd = BPFLd(0x00);
    pub const LDX: BPFLd = BPFLd(0x01);
    pub const ST: BPFSt = BPFSt(0x02);
    pub const STX: BPFSt = BPFSt(0x03);
    pub const ALU: BPFAlu = BPFAlu(0x04);
    pub const JMP: BPFJmp = BPFJmp(0x05);
    pub const RET: BPFRet = BPFRet(0x06);
    pub const MISC: BPFMisc = BPFMisc(0x07);

    pub const W: BPFSize = BPFSize(0x0);
    pub const H: BPFSize = BPFSize(0x8);
    pub const B: BPFSize = BPFSize(0x10);
    pub const IMM: BPFMode = BPFMode(0x00);
    pub const ABS: BPFMode = BPFMode(0x20);
    pub const IND: BPFMode = BPFMode(0x40);
    pub const MEM: BPFMode = BPFMode(0x60);
    pub const LEN: BPFMode = BPFMode(0x80);
    pub const MSH: BPFMode = BPFMode(0xA0);

    pub const ADD: BPFOp = BPFOp(0x00);
    pub const SUB: BPFOp = BPFOp(0x10);
    pub const MUL: BPFOp = BPFOp(0x20);
    pub const DIV: BPFOp = BPFOp(0x30);
    pub const OR: BPFOp = BPFOp(0x40);
    pub const AND: BPFOp = BPFOp(0x50);
    pub const LSH: BPFOp = BPFOp(0x60);
    pub const RSH: BPFOp = BPFOp(0x70);
    pub const NEG: BPFOp = BPFOp(0x80);

    pub const JA: BPFJmpOp = BPFJmpOp(0x00);
    pub const JEQ: BPFJmpOp = BPFJmpOp(0x10);
    pub const JGT: BPFJmpOp = BPFJmpOp(0x20);
    pub const JGE: BPFJmpOp = BPFJmpOp(0x30);
    pub const JSET: BPFJmpOp = BPFJmpOp(0x40);

    pub const K: BPFSrc = BPFSrc(0x00);
    pub const X: BPFSrc = BPFSrc(0x08);
    pub const A: BPFRetSrc = BPFRetSrc(0x08);

    pub const TAX: BPFMiscOp = BPFMiscOp(0x00);
    pub const TXA: BPFMiscOp = BPFMiscOp(0x80);
}

#[test]
fn test_bpf_stmt() {
    let item = BPFFilter::bpf_stmt(bpf::LD | bpf::B | bpf::ABS, 6);
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
        bpf::JMP | bpf::JEQ | bpf::K,
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
