#![no_std]

// 以太网头
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

// IP 头
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
}

// TCP 头
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_off: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
}

// UDP 头
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub checksum: u16,
}

// ICMP 头
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IcmpHdr {
    pub type_: u8,
    pub code: u8,
    pub checksum: u16,
}

// 协议常量
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;

// 以太网类型
pub const ETH_P_IP: u16 = 0x0800;

// 过滤配置
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FilterConfig {
    pub filter_mode: u8,      // 0=none, 1=protocol, 2=port, 3=protocol+port, 4=ip
    pub protocol: u8,         // 0=all, 6=TCP, 17=UDP, 1=ICMP
    pub port: u16,            // 0=any
    pub src_ip: u32,          // 0=any
    pub dst_ip: u32,          // 0=any
    pub _pad: [u8; 4],
}
