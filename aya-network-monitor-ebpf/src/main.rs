#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use aya_network_monitor_common::{
    NetworkEvent, EthHdr, Ipv4Hdr, TcpHdr, UdpHdr, IcmpHdr,
    ETH_P_IP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, MAX_PAYLOAD_SIZE,
};

// Perf Event Array - 用于向用户空间发送结构化网络事件
#[map]
static mut EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

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
    let ip_hdr_ptr = (data_ptr as usize + core::mem::size_of::<EthHdr>()) as *const Ipv4Hdr;

    if (ip_hdr_ptr as usize + core::mem::size_of::<Ipv4Hdr>()) > data_end as usize {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr = unsafe { &*ip_hdr_ptr };
    let protocol = ip_hdr.protocol;
    let src_ip = ip_hdr.src_ip;
    let dst_ip = ip_hdr.dst_ip;
    let ip_hdr_len = (ip_hdr.version_ihl & 0x0F) * 4;

    let size = data_end - data_ptr;

    // 解析传输层头并发送事件到用户空间
    match protocol {
        IPPROTO_TCP => {
            let tcp_hdr_ptr = (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const TcpHdr;

            if (tcp_hdr_ptr as usize + core::mem::size_of::<TcpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let tcp_hdr = unsafe { &*tcp_hdr_ptr };

            // 计算 TCP payload 的起始位置
            let tcp_hdr_len = ((tcp_hdr.data_off >> 4) as u8) * 4;
            let payload_ptr = (tcp_hdr_ptr as usize + tcp_hdr_len as usize) as *const u8;

            // 捕获 payload（使用 eBPF 友好的方式）
            let mut payload = [0u8; MAX_PAYLOAD_SIZE];
            let mut payload_len = 0u16;

            // 检查是否有 payload 可用
            if (payload_ptr as usize) < (data_end as usize) {
                let available = (data_end as usize - payload_ptr as usize) as usize;
                let to_copy = core::cmp::min(available, MAX_PAYLOAD_SIZE);

                // 手动复制，避免 eBPF 验证器问题
                let mut i = 0usize;
                loop {
                    if i >= to_copy {
                        break;
                    }
                    let src_ptr = unsafe { payload_ptr.add(i) };
                    // 确保不会越界
                    if src_ptr as usize >= data_end as usize {
                        break;
                    }
                    let byte = unsafe { *src_ptr };
                    payload[i] = byte;
                    i += 1;
                }
                payload_len = i as u16;
            }

            // 创建网络事件并通过 Perf Event Array 发送
            let event = NetworkEvent {
                protocol: IPPROTO_TCP,
                src_ip,
                dst_ip,
                src_port: tcp_hdr.src_port,
                dst_port: tcp_hdr.dst_port,
                packet_size: size as u32,
                tcp_flags: tcp_hdr.flags,
                payload_len,
                payload,
            };

            unsafe {
                EVENTS.output(&ctx, &event, 0);
            }
        }
        IPPROTO_UDP => {
            let udp_hdr_ptr = (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const UdpHdr;

            if (udp_hdr_ptr as usize + core::mem::size_of::<UdpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let udp_hdr = unsafe { &*udp_hdr_ptr };

            // 计算 UDP payload 的起始位置
            let payload_ptr = (udp_hdr_ptr as usize + core::mem::size_of::<UdpHdr>()) as *const u8;

            // 捕获 payload（使用 eBPF 友好的方式）
            let mut payload = [0u8; MAX_PAYLOAD_SIZE];
            let mut payload_len = 0u16;

            // 检查是否有 payload 可用
            if (payload_ptr as usize) < (data_end as usize) {
                let available = (data_end as usize - payload_ptr as usize) as usize;
                let to_copy = core::cmp::min(available, MAX_PAYLOAD_SIZE);

                // 手动复制，避免 eBPF 验证器问题
                let mut i = 0usize;
                loop {
                    if i >= to_copy {
                        break;
                    }
                    let src_ptr = unsafe { payload_ptr.add(i) };
                    // 确保不会越界
                    if src_ptr as usize >= data_end as usize {
                        break;
                    }
                    let byte = unsafe { *src_ptr };
                    payload[i] = byte;
                    i += 1;
                }
                payload_len = i as u16;
            }

            // 创建网络事件并通过 Perf Event Array 发送
            let event = NetworkEvent {
                protocol: IPPROTO_UDP,
                src_ip,
                dst_ip,
                src_port: udp_hdr.src_port,
                dst_port: udp_hdr.dst_port,
                packet_size: size as u32,
                tcp_flags: 0,
                payload_len,
                payload,
            };

            unsafe {
                EVENTS.output(&ctx, &event, 0);
            }
        }
        IPPROTO_ICMP => {
            let icmp_hdr_ptr = (ip_hdr_ptr as usize + ip_hdr_len as usize) as *const IcmpHdr;

            if (icmp_hdr_ptr as usize + core::mem::size_of::<IcmpHdr>()) > data_end as usize {
                return Ok(xdp_action::XDP_PASS);
            }

            let icmp_hdr = unsafe { &*icmp_hdr_ptr };

            // 计算 ICMP payload 的起始位置
            let payload_ptr = (icmp_hdr_ptr as usize + core::mem::size_of::<IcmpHdr>()) as *const u8;

            // 捕获 payload（使用 eBPF 友好的方式）
            let mut payload = [0u8; MAX_PAYLOAD_SIZE];
            let mut payload_len = 0u16;

            // 检查是否有 payload 可用
            if (payload_ptr as usize) < (data_end as usize) {
                let available = (data_end as usize - payload_ptr as usize) as usize;
                let to_copy = core::cmp::min(available, MAX_PAYLOAD_SIZE);

                // 手动复制，避免 eBPF 验证器问题
                let mut i = 0usize;
                loop {
                    if i >= to_copy {
                        break;
                    }
                    let src_ptr = unsafe { payload_ptr.add(i) };
                    // 确保不会越界
                    if src_ptr as usize >= data_end as usize {
                        break;
                    }
                    let byte = unsafe { *src_ptr };
                    payload[i] = byte;
                    i += 1;
                }
                payload_len = i as u16;
            }

            // 创建网络事件并通过 Perf Event Array 发送
            let event = NetworkEvent {
                protocol: IPPROTO_ICMP,
                src_ip,
                dst_ip,
                src_port: 0,
                dst_port: 0,
                packet_size: size as u32,
                tcp_flags: 0,
                payload_len,
                payload,
            };

            unsafe {
                EVENTS.output(&ctx, &event, 0);
            }
        }
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
