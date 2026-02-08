#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use aya_network_monitor_common::{
    EthHdr, Ipv4Hdr, TcpHdr, UdpHdr, IcmpHdr,
    ETH_P_IP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP,
};

#[xdp]
pub fn aya_network_monitor(ctx: XdpContext) -> u32 {
    match try_aya_network_monitor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_aya_network_monitor(ctx: XdpContext) -> Result<u32, u32> {
    let data_ptr = ctx.data();
    let data_end = ctx.data_end();

    if data_ptr == 0 || data_end == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 解析以太网头
    let eth_hdr = unsafe {
        let ptr = data_ptr as *const EthHdr;
        if (ptr as usize + core::mem::size_of::<EthHdr>()) > data_end as usize {
            return Ok(xdp_action::XDP_PASS);
        }
        &*ptr
    };

    // 检查是否为 IP 包
    let ether_type = u16::from_be(eth_hdr.ether_type);
    if ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // 解析 IP 头
    let ip_hdr_ptr = unsafe {
        (data_ptr as usize + core::mem::size_of::<EthHdr>()) as *const Ipv4Hdr
    };

    if (ip_hdr_ptr as usize + core::mem::size_of::<Ipv4Hdr>()) > data_end as usize {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = unsafe { &*ip_hdr_ptr };
    let protocol = ip_hdr.protocol;
    let src_ip = u32::from_be(ip_hdr.src_ip);
    let dst_ip = u32::from_be(ip_hdr.dst_ip);

    let ip_hdr_len = (ip_hdr.version_ihl & 0x0F) * 4;

    // 解析传输层头
    match protocol {
        IPPROTO_TCP => {
            let tcp_hdr_ptr = unsafe {
                (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const TcpHdr
            };

            if (tcp_hdr_ptr as usize + core::mem::size_of::<TcpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let tcp_hdr = unsafe { &*tcp_hdr_ptr };
            let src_port = u16::from_be(tcp_hdr.src_port);
            let dst_port = u16::from_be(tcp_hdr.dst_port);

            let size = data_end - data_ptr;
            let ack = if (tcp_hdr.flags & 0x10) != 0 { 1u8 } else { 0u8 };
            let syn = if (tcp_hdr.flags & 0x02) != 0 { 1u8 } else { 0u8 };
            let fin = if (tcp_hdr.flags & 0x01) != 0 { 1u8 } else { 0u8 };

            let (a, b, c, d) = format_ip(src_ip);
            let (e, f, g, h) = format_ip(dst_ip);

            info!(&ctx,
                "TCP {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} ({}b) A={} S={} F={}",
                a, b, c, d, src_port,
                e, f, g, h, dst_port,
                size, ack, syn, fin
            );
        }
        IPPROTO_UDP => {
            let udp_hdr_ptr = unsafe {
                (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const UdpHdr
            };

            if (udp_hdr_ptr as usize + core::mem::size_of::<UdpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let udp_hdr = unsafe { &*udp_hdr_ptr };
            let src_port = u16::from_be(udp_hdr.src_port);
            let dst_port = u16::from_be(udp_hdr.dst_port);

            let size = data_end - data_ptr;
            let (a, b, c, d) = format_ip(src_ip);
            let (e, f, g, h) = format_ip(dst_ip);

            info!(&ctx,
                "UDP {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} ({}b)",
                a, b, c, d, src_port,
                e, f, g, h, dst_port,
                size
            );
        }
        IPPROTO_ICMP => {
            let icmp_hdr_ptr = unsafe {
                (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const IcmpHdr
            };

            if (icmp_hdr_ptr as usize + core::mem::size_of::<IcmpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let icmp_hdr = unsafe { &*icmp_hdr_ptr };
            let size = data_end - data_ptr;

            let (a, b, c, d) = format_ip(src_ip);
            let (e, f, g, h) = format_ip(dst_ip);

            info!(&ctx,
                "ICMP {}.{}.{}.{} -> {}.{}.{}.{} (t={} {}b)",
                a, b, c, d,
                e, f, g, h,
                icmp_hdr.type_,
                size
            );
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

fn format_ip(ip: u32) -> (u8, u8, u8, u8) {
    (
        (ip >> 24) as u8,
        (ip >> 16) as u8,
        (ip >> 8) as u8,
        ip as u8,
    )
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
