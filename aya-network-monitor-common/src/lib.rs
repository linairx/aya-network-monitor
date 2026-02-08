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

// Payload 大小限制（考虑 eBPF 栈大小 512 字节）
pub const MAX_PAYLOAD_SIZE: usize = 128;

// 网络事件（通过 Perf Event Array 发送到用户空间）
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NetworkEvent {
    pub protocol: u8,           // IPPROTO_TCP/UDP/ICMP
    pub src_ip: u32,            // 源 IP（网络字节序）
    pub dst_ip: u32,            // 目标 IP（网络字节序）
    pub src_port: u16,          // 源端口（网络字节序）
    pub dst_port: u16,          // 目标端口（网络字节序）
    pub packet_size: u32,       // 包大小
    pub tcp_flags: u8,          // TCP 标志位（仅 TCP 有效）
    pub payload_len: u8,        // 实际捕获的 payload 长度
    pub _pad: [u8; 2],
    pub payload: [u8; MAX_PAYLOAD_SIZE],  // 数据包内容
}

// 用户空间过滤配置（通过共享 map 传递到 eBPF）
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FilterConfig {
    pub enabled: u8,            // 是否启用过滤
    pub protocol: u8,           // 0=所有, 6=TCP, 17=UDP, 1=ICMP
    pub src_ip: u32,            // 0=任意
    pub dst_ip: u32,            // 0=任意
    pub src_port: u16,          // 0=任意
    pub dst_port: u16,          // 0=任意
    pub min_packet_size: u32,   // 最小包大小过滤
    pub max_packet_size: u32,   // 最大包大小过滤
}
