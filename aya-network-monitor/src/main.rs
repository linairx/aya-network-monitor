use anyhow::Context as _;
use aya::{
    maps::perf::PerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Ebpf,
};
use aya_network_monitor_common::{NetworkEvent, MAX_PAYLOAD_SIZE};
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use serde::Serialize;
use std::net::Ipv4Addr;
use tokio::{signal, task};

/// 显示模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayMode {
    /// 基础模式：只显示头部信息
    #[default]
    Basic,
    /// 十六进制模式：显示 hex dump + ASCII
    Hex,
    /// 文本模式：智能文本检测
    Text,
    /// 协议模式：解析常见协议
    Protocol,
    /// JSON 模式：为 Web 界面提供结构化数据
    Json,
}

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// 网络接口名称
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// XDP 模式: drv (驱动模式) 或 skb (SKB 模式)
    #[clap(long, default_value = "drv")]
    xdp_mode: String,

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

    /// 显示模式：basic, hex, text, protocol, json
    #[clap(long, default_value = "basic")]
    mode: String,

    /// 显示 payload 的最大字节数（用于 hex/text 模式，最大512）
    #[clap(long, default_value = "128")]
    payload_bytes: usize,

    /// 捕获完整 payload（512字节），忽略 --payload-bytes 设置
    #[clap(long)]
    payload_full: bool,

    /// 分页显示，每页显示的行数（用于 hex 模式）
    #[clap(long, default_value = "0")]
    page_lines: usize,

    /// 显示调试信息
    #[clap(long)]
    debug: bool,
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

// ========== 显示模式相关函数 ==========

/// 解析显示模式
fn parse_display_mode(mode: &str) -> DisplayMode {
    match mode.to_lowercase().as_str() {
        "hex" => DisplayMode::Hex,
        "text" => DisplayMode::Text,
        "protocol" => DisplayMode::Protocol,
        "json" => DisplayMode::Json,
        "basic" | _ => DisplayMode::Basic,
    }
}

/// 十六进制转储
fn format_hex_dump(payload: &[u8], bytes_to_show: usize) -> String {
    let mut output = String::new();
    let bytes_to_show = core::cmp::min(bytes_to_show, payload.len());

    for (i, chunk) in payload[..bytes_to_show].chunks(16).enumerate() {
        let offset = i * 16;
        output.push_str(&format!("{:04x}: ", offset));

        // 十六进制部分
        for (j, byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                output.push(' ');
            }
        }

        // 填充空格
        for j in chunk.len()..16 {
            output.push_str("   ");
            if j == 7 {
                output.push(' ');
            }
        }

        output.push_str("  ");

        // ASCII 部分
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                output.push(*byte as char);
            } else {
                output.push('.');
            }
        }
        output.push('\n');
    }

    output
}

/// 十六进制转储（带分页）
fn format_hex_dump_paged(payload: &[u8], bytes_to_show: usize, page_lines: usize) -> String {
    let mut output = String::new();
    let bytes_to_show = core::cmp::min(bytes_to_show, payload.len());

    if page_lines == 0 {
        // 不分页，显示全部
        return format_hex_dump(payload, bytes_to_show);
    }

    let total_lines = (bytes_to_show + 15) / 16;
    let pages = (total_lines + page_lines - 1) / page_lines;

    for page in 0..pages {
        let start_line = page * page_lines;
        let end_line = core::cmp::min((page + 1) * page_lines, total_lines);
        let start_byte = start_line * 16;
        let end_byte = core::cmp::min(end_line * 16, bytes_to_show);

        output.push_str(&format!("--- 页 {} ({}-{} 字节) ---\n", page + 1, start_byte, end_byte - 1));

        for line in start_line..end_line {
            let line_start = line * 16;
            let line_end = core::cmp::min(line_start + 16, bytes_to_show);
            let chunk = &payload[line_start..line_end];

            output.push_str(&format!("{:04x}: ", line_start));

            // 十六进制部分
            for (j, byte) in chunk.iter().enumerate() {
                output.push_str(&format!("{:02x} ", byte));
                if j == 7 {
                    output.push(' ');
                }
            }

            // 填充空格
            for j in chunk.len()..16 {
                output.push_str("   ");
                if j == 7 {
                    output.push(' ');
                }
            }

            output.push_str("  ");

            // ASCII 部分
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    output.push(*byte as char);
                } else {
                    output.push('.');
                }
            }
            output.push('\n');
        }

        if page < pages - 1 {
            output.push('\n');
        }
    }

    output
}

/// 检测并显示文本内容
fn format_text_payload(payload: &[u8]) -> String {
    // 检查是否主要是可打印 ASCII
    let printable_count = payload.iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    let ratio = printable_count as f64 / payload.len() as f64;

    // 如果超过 80% 是可打印字符，显示为文本
    if ratio > 0.8 && payload.len() > 0 {
        let text = String::from_utf8_lossy(payload);
        return text.lines()
            .take(10) // 最多显示 10 行
            .map(|line| format!("  {}", line))
            .collect::<Vec<_>>()
            .join("\n");
    }

    // 否则显示十六进制
    format_hex_dump(payload, payload.len())
}

/// 解析 HTTP 请求
fn parse_http(payload: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(payload);
    let lines: Vec<&str> = text.lines().collect();

    if lines.is_empty() {
        return None;
    }

    let first_line = lines[0].trim();

    // 检查是否是 HTTP 请求
    if first_line.starts_with("GET ") || first_line.starts_with("POST ") ||
       first_line.starts_with("PUT ") || first_line.starts_with("DELETE ") ||
       first_line.starts_with("HEAD ") || first_line.starts_with("OPTIONS ") ||
       first_line.starts_with("PATCH ") {
        let mut output = String::from("HTTP Request:\n");
        output.push_str(&format!("  {}\n", first_line));

        // 解析头部
        for line in lines.iter().skip(1).take(20) {
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            output.push_str(&format!("  {}\n", line));
        }

        return Some(output);
    }

    // 检查是否是 HTTP 响应
    if first_line.starts_with("HTTP/") {
        let mut output = String::from("HTTP Response:\n");
        output.push_str(&format!("  {}\n", first_line));

        for line in lines.iter().skip(1).take(20) {
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            output.push_str(&format!("  {}\n", line));
        }

        return Some(output);
    }

    None
}

/// 解析 DNS 查询/响应
fn parse_dns(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let question_count = u16::from_be_bytes([payload[4], payload[5]]) as usize;

    let mut output = String::new();
    output.push_str(if is_response { "DNS Response" } else { "DNS Query" });
    output.push_str(&format!(" ({} questions)\n", question_count));

    // 简单的域名解析（跳过复杂的压缩指针处理）
    let mut pos = 12;
    for i in 0..question_count {
        if pos >= payload.len() {
            break;
        }

        output.push_str(&format!("  Query {}: ", i + 1));

        // 解析域名
        let mut domain = String::new();
        loop {
            if pos >= payload.len() {
                break;
            }
            let len = payload[pos] as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            if pos + len > payload.len() {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            let label = String::from_utf8_lossy(&payload[pos..pos + len]);
            domain.push_str(&label);
            pos += len;
        }

        output.push_str(&domain);

        // 跳过 QTYPE 和 QCLASS
        if pos + 4 > payload.len() {
            break;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        pos += 4;

        let type_str = match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            28 => "AAAA",
            _ => "UNKNOWN",
        };
        output.push_str(&format!(" (type: {})\n", type_str));
    }

    Some(output)
}

/// 协议解析
fn format_protocol_parse(event: &NetworkEvent) -> String {
    let proto = format_protocol(event.protocol);
    let src_ip = format_ip(event.src_ip);
    let dst_ip = format_ip(event.dst_ip);

    let header = match event.protocol {
        6 | 17 => {
            format!(
                "{} {}:{} -> {}:{} ({}b)\n",
                proto,
                src_ip,
                u16::from_be(event.src_port),
                dst_ip,
                u16::from_be(event.dst_port),
                event.packet_size
            )
        }
        _ => {
            format!(
                "{} {} -> {} ({}b)\n",
                proto, src_ip, dst_ip, event.packet_size
            )
        }
    };

    let payload = &event.payload[..event.payload_len as usize];

    // 尝试解析协议
    if event.protocol == 6 && (u16::from_be(event.dst_port) == 80 || u16::from_be(event.src_port) == 80) {
        // HTTP
        if let Some(http) = parse_http(payload) {
            return format!("{}{}", header, http);
        }
    }

    if event.protocol == 17 && (u16::from_be(event.dst_port) == 53 || u16::from_be(event.src_port) == 53) {
        // DNS
        if let Some(dns) = parse_dns(payload) {
            return format!("{}{}", header, dns);
        }
    }

    // 无法解析，显示文本或十六进制
    format!("{}{}", header, format_text_payload(payload))
}

/// JSON 输出的结构体
#[derive(Serialize)]
struct JsonEvent {
    timestamp: i64,
    protocol: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    packet_size: u32,
    tcp_flags: u8,
    payload_len: usize,
    payload_hex: String,
}

/// 转换为 JSON
fn format_json(event: &NetworkEvent) -> String {
    let json_event = JsonEvent {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        protocol: format_protocol(event.protocol).to_string(),
        src_ip: format_ip(event.src_ip),
        dst_ip: format_ip(event.dst_ip),
        src_port: u16::from_be(event.src_port),
        dst_port: u16::from_be(event.dst_port),
        packet_size: event.packet_size,
        tcp_flags: event.tcp_flags,
        payload_len: event.payload_len as usize,
        payload_hex: {
            let bytes = &event.payload[..event.payload_len as usize];
            bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        },
    };

    serde_json::to_string(&json_event).unwrap_or_else(|_| "{}".to_string())
}

/// 根据显示模式格式化事件
fn format_event_with_mode(
    event: &NetworkEvent,
    mode: DisplayMode,
    payload_bytes: usize,
    payload_full: bool,
    page_lines: usize,
) -> String {
    // 确定 payload 显示大小
    let effective_bytes = if payload_full {
        event.payload_len as usize
    } else {
        core::cmp::min(payload_bytes, event.payload_len as usize)
    };

    match mode {
        DisplayMode::Basic => format_event(event),
        DisplayMode::Hex => {
            let mut output = format_event(event);
            output.push_str(&format!("\nPayload ({} bytes, 显示 {} bytes):\n", event.payload_len, effective_bytes));

            // 根据是否分页选择格式化函数
            if page_lines > 0 && effective_bytes > page_lines * 16 {
                output.push_str(&format_hex_dump_paged(
                    &event.payload[..event.payload_len as usize],
                    effective_bytes,
                    page_lines,
                ));
            } else {
                output.push_str(&format_hex_dump(
                    &event.payload[..event.payload_len as usize],
                    effective_bytes,
                ));
            }
            output
        }
        DisplayMode::Text => {
            let mut output = format_event(event);
            if event.payload_len > 0 {
                output.push_str("\nContent:\n");
                let bytes = &event.payload[..effective_bytes];
                output.push_str(&format_text_payload(bytes));
            }
            output
        }
        DisplayMode::Protocol => format_protocol_parse(event),
        DisplayMode::Json => format_json(event),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let filter = Filter::from_opt(&opt);
    let display_mode = parse_display_mode(&opt.mode);

    info!("═══════════════════════════════════════");
    info!("     Aya eBPF 网络流量监控工具");
    info!("═══════════════════════════════════════");
    info!("网卡: {}", opt.iface);
    info!("架构: eBPF (内核) → Perf Event → 用户空间 Rust 过滤");
    info!("");
    info!("显示模式: {}", opt.mode);
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
    if opt.mode != "basic" {
        if opt.payload_full {
            info!("  Payload 显示: 完整 (192 字节)");
        } else {
            info!("  Payload 显示: {} 字节", opt.payload_bytes);
        }
        if opt.page_lines > 0 {
            info!("  分页显示: 每页 {} 行", opt.page_lines);
        }
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

    // 根据 XDP 模式选择标志
    let xdp_flags = match opt.xdp_mode.as_str() {
        "skb" => XdpFlags::SKB_MODE,
        "drv" | _ => XdpFlags::default(),
    };

    program.attach(&opt.iface, xdp_flags)
        .context(format!("failed to attach the XDP program with {} mode - try the other mode (drv/skb)", opt.xdp_mode))?;

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
        let display_mode_clone = display_mode;
        let payload_bytes_clone = opt.payload_bytes;
        let payload_full_clone = opt.payload_full;
        let page_lines_clone = opt.page_lines;
        let opt_clone = opt.clone(); // Clone for debug use

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

                                        // 调试输出（如果启用）
                                        if opt_clone.debug {
                                            eprintln!("[DEBUG] Total events: {}", total);
                                            eprintln!("[DEBUG] Event: {}:{} -> {}:{} ({}b)",
                                                format_ip(network_event.src_ip),
                                                u16::from_be(network_event.src_port),
                                                format_ip(network_event.dst_ip),
                                                u16::from_be(network_event.dst_port),
                                                network_event.packet_size
                                            );
                                            eprintln!("[DEBUG] Filter: src_port={:?}, dst_port={:?}",
                                                filter_clone.src_port, filter_clone.dst_port);
                                        }

                                        // 应用过滤
                                        if filter_clone.matches(&network_event) {
                                            filtered += 1;

                                            // 根据显示模式格式化输出
                                            let output = format_event_with_mode(
                                                &network_event,
                                                display_mode_clone,
                                                payload_bytes_clone,
                                                payload_full_clone,
                                                page_lines_clone
                                            );
                                            println!("{}", output);

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
