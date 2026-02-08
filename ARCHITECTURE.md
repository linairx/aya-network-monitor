# 网络监控架构说明

## 当前架构（Perf Event 方案）✅ 已实现

```
┌─────────────┐
│  eBPF 内核  │ ─→ Perf Event Array ─→ Rust 结构体 ──→ Rust 过滤逻辑
│ (捕获数据包)  │                               (高性能二进制)
└─────────────┘
```

### 优点
- 🚀 **高性能**：二进制数据传输，零拷贝
- 🎯 **可编程**：Rust 代码实现复杂过滤逻辑
- 📊 **结构化**：直接处理 `NetworkEvent` 结构体
- 🔄 **实时性**：通过 perf buffer 高效传递
- 💪 **灵活**：所有过滤在用户空间完成，易于修改

### 实现细节

#### eBPF 内核层 (`aya-network-monitor-ebpf/src/main.rs`)

捕获所有网络数据包，解析协议头，并通过 Perf Event Array 发送到用户空间：

```rust
#[map]
static mut EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

#[xdp]
pub fn aya_network_monitor(ctx: XdpContext) -> u32 {
    // 解析以太网头 → IP 头 → 传输层头
    // 创建 NetworkEvent 并发送
    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }
}
```

#### 用户空间层 (`aya-network-monitor/src/main.rs`)

从 Perf Event Array 接收事件并应用过滤：

```rust
let mut perf_array = PerfEventArray::try_from(ebpf.take_map("EVENTS")?)?;

for cpu_id in online_cpus {
    let buf = perf_array.open(cpu_id, None)?;
    // 异步读取事件
    let events = buf.read_events(&mut buffers)?;
    // 应用过滤逻辑
    if filter.matches(&network_event) {
        println!("{}", format_event(&network_event));
    }
}
```

## Rust 2024 兼容性警告

编译时会看到以下警告：

```
warning: creating a shared reference to mutable static
  --> aya-network-monitor-ebpf/src/main.rs:89:17
   |
89 |                 EVENTS.output(&ctx, &event, 0);
   |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ shared reference to mutable static
```

**原因**：Rust 2024 edition 引入了更严格的静态可变变量检查。

**影响**：这只是警告，代码可以正常工作。eBPF 程序运行在内核空间，与用户空间 Rust 的安全模型不同。

**解决方案**：
- 当前：使用 Rust 2021 edition（已在 Cargo.toml 中配置）
- 未来：等待 Aya 框架更新以完全支持 Rust 2024

## 使用示例

### 基本使用
```bash
# 监控所有流量
sudo ./target/release/aya-network-monitor -i ens18
```

### 协议过滤
```bash
# 只监控 TCP
sudo ./target/release/aya-network-monitor -i ens18 --protocol tcp

# 只监控 UDP
sudo ./target/release/aya-network-monitor -i ens18 --protocol udp

# 只监控 ICMP
sudo ./target/release/aya-network-monitor -i ens18 --protocol icmp
```

### IP 地址过滤
```bash
# 只看来自某个 IP 的流量
sudo ./target/release/aya-network-monitor -i ens18 --src-ip 192.168.1.100

# 只看发往某个 IP 的流量
sudo ./target/release/aya-network-monitor -i ens18 --dst-ip 8.8.8.8
```

### 端口过滤
```bash
# 只看源端口为 22 的流量
sudo ./target/release/aya-network-monitor -i ens18 --src-port 22

# 只看目标端口为 443 的流量
sudo ./target/release/aya-network-monitor -i ens18 --dst-port 443
```

### 组合过滤
```bash
# 监控 TCP 流量，目标端口为 443，目标 IP 为 1.1.1.1
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp \
  --dst-port 443 \
  --dst-ip 1.1.1.1
```

## 性能对比

| 方案 | 数据传输 | 解析开销 | 过滤灵活性 | 实现难度 | 当前状态 |
|------|---------|---------|-----------|---------|---------|
| 日志方案 | 中等 | 高（文本） | ⭐⭐⭐⭐⭐ | 简单 | 已废弃 |
| Perf Event | 低 | 低（二进制） | ⭐⭐⭐⭐⭐ | 中等 | ✅ 已实现 |
| eBPF 内核过滤 | 极低 | 无 | ⭐⭐ | 复杂 | 不推荐 |

## 架构演进历史

```
阶段 1 (已废弃): 日志 + 外部工具
     ❌ 性能开销大，需要文本解析

阶段 2 (当前): eBPF → Perf Event → Rust
     ✅ 已实现，生产就绪
     ├─→ 结构化数据传输
     ├─→ 用户空间 Rust 过滤
     └─→ 高性能实时处理

阶段 3 (未来): 高级特性
     └─→ 统计信息
     └─→ 流量聚合
     └─→ 告警功能
```

## 核心数据结构

### NetworkEvent (eBPF → 用户空间)

```rust
#[repr(C)]
pub struct NetworkEvent {
    pub protocol: u8,           // IPPROTO_TCP/UDP/ICMP
    pub src_ip: u32,            // 源 IP（网络字节序）
    pub dst_ip: u32,            // 目标 IP（网络字节序）
    pub src_port: u16,          // 源端口（网络字节序）
    pub dst_port: u16,          // 目标端口（网络字节序）
    pub packet_size: u32,       // 包大小
    pub tcp_flags: u8,          // TCP 标志位（仅 TCP 有效）
    pub _pad: [u8; 3],
}
```

### 过滤配置

```rust
struct Filter {
    protocol: Option<u8>,       // None = 所有协议
    src_ip: Option<u32>,        // None = 任意源 IP
    dst_ip: Option<u32>,        // None = 任意目标 IP
    src_port: Option<u16>,      // None = 任意源端口
    dst_port: Option<u16>,      // None = 任意目标端口
}
```

## 技术栈

- **eBPF 框架**: [Aya](https://github.com/aya-rs/aya) - 纯 Rust eBPF 框架
- **程序类型**: XDP (eXpress Data Path) - 高性能数据包处理
- **数据传输**: Perf Event Array - 内核到用户空间的高效通道
- **异步运行时**: Tokio - 异步事件处理
- **CLI 解析**: Clap - 命令行参数解析

## 参考资源

- [Aya Book](https://aya-rs.dev/book/)
- [XDP 指南](https://www.iovisor.org/technology/xdp)
- [eBPF 社区](https://ebpf.io/)
- [Rust Edition Guide 2024](https://doc.rust-lang.org/nightly/edition-guide/rust-2024/index.html)
