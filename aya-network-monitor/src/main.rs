use anyhow::Context as _;
use aya::{
    maps::perf::PerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use aya_network_monitor_common::NetworkEvent;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use std::net::Ipv4Addr;
use tokio::{signal, task};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// 网络接口名称
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// 过滤协议: tcp, udp, icmp 或 all
    #[clap(long, default_value = "all")]
    protocol: String,

    /// 过滤源 IP 地址
    #[clap(long)]
    src_ip: Option<String>,

    /// 过滤目标 IP 地址
    #[clap(long)]
    dst_ip: Option<String>,

    /// 过滤源端口
    #[clap(long)]
    src_port: Option<u16>,

    /// 过滤目标端口
    #[clap(long)]
    dst_port: Option<u16>,

    /// 显示统计信息
    #[clap(long)]
    stats: bool,
}

#[derive(Debug, Clone)]
struct Filter {
    protocol: Option<u8>,
    src_ip: Option<u32>,
    dst_ip: Option<u32>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

impl Filter {
    fn from_opt(opt: &Opt) -> Self {
        let protocol = match opt.protocol.to_lowercase().as_str() {
            "tcp" => Some(6),
            "udp" => Some(17),
            "icmp" => Some(1),
            "all" | _ => None,
        };

        let src_ip = opt.src_ip.as_ref().and_then(|ip| {
            ip.parse::<Ipv4Addr>()
                .ok()
                .map(|addr| u32::to_be(addr.into())) // 转换为网络字节序
        });

        let dst_ip = opt.dst_ip.as_ref().and_then(|ip| {
            ip.parse::<Ipv4Addr>()
                .ok()
                .map(|addr| u32::to_be(addr.into())) // 转换为网络字节序
        });

        Filter {
            protocol,
            src_ip,
            dst_ip,
            src_port: opt.src_port.map(|p| p.to_be()), // 转换为网络字节序
            dst_port: opt.dst_port.map(|p| p.to_be()), // 转换为网络字节序
        }
    }

    fn matches(&self, event: &NetworkEvent) -> bool {
        if let Some(proto) = self.protocol {
            if event.protocol != proto {
                return false;
            }
        }

        if let Some(src_ip) = self.src_ip {
            if event.src_ip != src_ip {
                return false;
            }
        }

        if let Some(dst_ip) = self.dst_ip {
            if event.dst_ip != dst_ip {
                return false;
            }
        }

        if let Some(src_port) = self.src_port {
            if event.src_port != src_port {
                return false;
            }
        }

        if let Some(dst_port) = self.dst_port {
            if event.dst_port != dst_port {
                return false;
            }
        }

        true
    }
}

fn format_ip(ip: u32) -> String {
    // IP 地址在网络上是大端序，需要转换为主机字节序
    let ip = u32::from_be(ip);
    let a = (ip >> 24) as u8;
    let b = (ip >> 16) as u8;
    let c = (ip >> 8) as u8;
    let d = ip as u8;
    format!("{}.{}.{}.{}", a, b, c, d)
}

fn format_protocol(protocol: u8) -> &'static str {
    match protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "UNKNOWN",
    }
}

fn format_event(event: &NetworkEvent) -> String {
    let proto = format_protocol(event.protocol);
    let src_ip = format_ip(event.src_ip);
    let dst_ip = format_ip(event.dst_ip);

    match event.protocol {
        6 | 17 => {
            format!(
                "{} {}:{} -> {}:{} ({}b)",
                proto,
                src_ip,
                u16::from_be(event.src_port),
                dst_ip,
                u16::from_be(event.dst_port),
                event.packet_size
            )
        }
        1 => {
            format!(
                "{} {} -> {} ({}b)",
                proto, src_ip, dst_ip, event.packet_size
            )
        }
        _ => format!("{} {} -> {} ({}b)", proto, src_ip, dst_ip, event.packet_size),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let filter = Filter::from_opt(&opt);

    info!("═══════════════════════════════════════");
    info!("     Aya eBPF 网络流量监控工具");
    info!("═══════════════════════════════════════");
    info!("网卡: {}", opt.iface);
    info!("架构: eBPF (内核) → Perf Event → 用户空间 Rust 过滤");
    info!("");
    info!("过滤配置:");
    info!("  协议: {}", opt.protocol);
    if let Some(ref ip) = opt.src_ip {
        info!("  源 IP: {}", ip);
    }
    if let Some(ref ip) = opt.dst_ip {
        info!("  目标 IP: {}", ip);
    }
    if let Some(port) = opt.src_port {
        info!("  源端口: {}", port);
    }
    if let Some(port) = opt.dst_port {
        info!("  目标端口: {}", port);
    }
    info!("═══════════════════════════════════════");
    info!("");

    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aya-network-monitor"
    )))?;

    let program: &mut Xdp = ebpf.program_mut("aya_network_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("开始监控...");
    info!("按 Ctrl-C 停止");
    info!("");

    // 获取 Perf Event Array
    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // 为每个 CPU 创建处理任务
    let online_cpus = online_cpus().map_err(|(_, e)| e).context("获取在线 CPU 失败")?;

    let mut handles = vec![];

    for cpu_id in online_cpus {
        let buf = perf_array.open(cpu_id, None)?;

        let mut buf = tokio::io::unix::AsyncFd::with_interest(
            buf,
            tokio::io::Interest::READABLE,
        )?;

        let filter_clone = filter.clone();

        let handle = task::spawn(async move {
            let mut counters = std::collections::HashMap::new();
            let mut total = 0usize;
            let mut filtered = 0usize;
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<NetworkEvent>()))
                .collect::<Vec<_>>();

            loop {
                match buf.readable_mut().await {
                    Ok(mut guard) => {
                        let events = guard.get_inner_mut().read_events(&mut buffers);

                        match events {
                            Ok(events) => {
                                for buf in buffers.iter_mut().take(events.read) {
                                    if buf.len() >= core::mem::size_of::<NetworkEvent>() {
                                        let ptr = buf.as_ptr() as *const NetworkEvent;
                                        let network_event = unsafe {
                                            ptr.read_unaligned()
                                        };

                                        total += 1;

                                        // 应用过滤
                                        if filter_clone.matches(&network_event) {
                                            filtered += 1;
                                            println!("{}", format_event(&network_event));

                                            // 统计
                                            *counters.entry(network_event.protocol).or_insert(0) += 1;
                                        }
                                    }
                                }

                                if events.read != buffers.len() {
                                    guard.clear_ready();
                                }
                            }
                            Err(e) => {
                                warn!("CPU {}: 读取事件失败: {}", cpu_id, e);
                                guard.clear_ready();
                            }
                        }
                    }
                    Err(e) => {
                        warn!("CPU {}: 等待可读失败: {}", cpu_id, e);
                        break;
                    }
                }
            }

            (cpu_id, total, filtered, counters)
        });

        handles.push(handle);
    }

    // 等待 Ctrl-C
    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;

    // 取消所有任务
    for handle in handles {
        handle.abort();
    }

    println!("\n退出...");

    Ok(())
}
