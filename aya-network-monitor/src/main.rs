use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// 网络接口名称
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("═══════════════════════════════════════");
    info!("     Aya 网络流量监控工具");
    info!("═══════════════════════════════════════");
    info!("网卡: {}", opt.iface);
    info!("格式: 协议 源IP:端口 -> 目标IP:端口 (大小)");
    info!("");
    info!("💡 过滤技巧:");
    info!("   只看 TCP:    | grep TCP");
    info!("   只看 UDP:    | grep UDP");
    info!("   只看 ICMP:   | grep ICMP");
    info!("   只看端口 22: | grep \":22 \"");
    info!("   只看某 IP:   | grep \"192.168.8.34\"");
    info!("   排除某 IP:   | grep -v \"192.168.8.34\"");
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

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aya-network-monitor"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = ebpf.program_mut("aya_network_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("开始监控...");
    info!("按 Ctrl-C 停止");
    info!("");

    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("\n退出...");

    Ok(())
}
