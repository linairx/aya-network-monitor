# Aya 网络流量监控

一个使用 [Aya](https://github.com/aya-rs/aya) 框架编写的高性能 eBPF 网络流量监控程序。

## 特性

- 🚀 **高性能**：使用 XDP (eXpress Data Path) 在内核层面拦截网络数据包
- 📊 **详细信息**：解析以太网、IP、TCP、UDP、ICMP 协议头
- 🎯 **灵活过滤**：在用户空间使用 Rust 实现强大的过滤逻辑
- 🔄 **实时监控**：通过 Perf Event Array 高效传输数据
- ⚡ **零拷贝**：二进制数据传输，避免文本解析开销

## 架构

```
┌─────────────┐
│  eBPF 内核  │ ─→ Perf Event Array ─→ Rust 结构体 ──→ Rust 过滤逻辑
│ (捕获数据包)  │                               (高性能二进制)
└─────────────┘
```

详细的架构说明请参考 [ARCHITECTURE.md](ARCHITECTURE.md)

## 前置要求

1. **Linux 内核版本** >= 5.8
2. **Rust 工具链** (nightly)
   ```bash
   rustup toolchain install nightly --component rust-src
   rustup default nightly
   ```

3. **bpf-linker**: `cargo install bpf-linker`
4. **cargo-generate**: `cargo install cargo-generate`

## 编译

```bash
cargo build --release
```

编译后的二进制文件位于: `target/release/aya-network-monitor`

## 使用方法

⚠️ **注意**: 运行 eBPF 程序需要 **root 权限**

### 基本使用

```bash
# 监控所有流量（使用默认网卡 eth0）
sudo ./target/release/aya-network-monitor

# 监控指定网卡
sudo ./target/release/aya-network-monitor -i ens18
```

### 协议过滤

```bash
# 只监控 TCP 流量
sudo ./target/release/aya-network-monitor -i ens18 --protocol tcp

# 只监控 UDP 流量
sudo ./target/release/aya-network-monitor -i ens18 --protocol udp

# 只监控 ICMP 流量
sudo ./target/release/aya-network-monitor -i ens18 --protocol icmp

# 监控所有协议（默认）
sudo ./target/release/aya-network-monitor -i ens18 --protocol all
```

### IP 地址过滤

```bash
# 只看来自某个 IP 的流量
sudo ./target/release/aya-network-monitor -i ens18 --src-ip 192.168.1.100

# 只看发往某个 IP 的流量
sudo ./target/release/aya-network-monitor -i ens18 --dst-ip 8.8.8.8

# 组合源和目标 IP
sudo ./target/release/aya-network-monitor -i ens18 \
  --src-ip 192.168.1.100 \
  --dst-ip 8.8.8.8
```

### 端口过滤

```bash
# 只看源端口为 22 的流量（SSH）
sudo ./target/release/aya-network-monitor -i ens18 --src-port 22

# 只看目标端口为 443 的流量（HTTPS）
sudo ./target/release/aya-network-monitor -i ens18 --dst-port 443

# 只看目标端口为 80 的流量（HTTP）
sudo ./target/release/aya-network-monitor -i ens18 --dst-port 80
```

### 组合过滤

```bash
# 监控 TCP 流量，目标端口为 443，目标 IP 为 1.1.1.1
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp \
  --dst-port 443 \
  --dst-ip 1.1.1.1

# 监控来自 192.168.1.100 的 SSH 连接
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp \
  --src-ip 192.168.1.100 \
  --dst-port 22
```

### 查看所有选项

```bash
sudo ./target/release/aya-network-monitor --help
```

### 查看系统网卡

```bash
ip addr show
```

## 输出示例

### 监控所有流量

```
═══════════════════════════════════════
     Aya eBPF 网络流量监控工具
═══════════════════════════════════════
网卡: ens18
架构: eBPF (内核) → Perf Event → 用户空间 Rust 过滤

过滤配置:
  协议: all
═══════════════════════════════════════

开始监控...
按 Ctrl-C 停止

TCP 192.168.1.100:54321 -> 93.184.216.34:443 (1248b)
UDP 192.168.1.100:54321 -> 8.8.8.8:53 (64b)
TCP 192.168.1.100:54322 -> 142.250.185.78:80 (1514b)
ICMP 192.168.1.100 -> 192.168.1.1 (84b)
```

### 只监控 TCP 端口 443

```
sudo ./target/release/aya-network-monitor -i ens18 --protocol tcp --dst-port 443

═══════════════════════════════════════
     Aya eBPF 网络流量监控工具
═══════════════════════════════════════
网卡: ens18
架构: eBPF (内核) → Perf Event → 用户空间 Rust 过滤

过滤配置:
  协议: tcp
  目标端口: 443
═══════════════════════════════════════

开始监控...
按 Ctrl-C 停止

TCP 192.168.1.100:54321 -> 93.184.216.34:443 (1248b)
TCP 192.168.1.100:54322 -> 142.250.185.78:443 (1514b)
```

## 工作原理

### XDP (eXpress Data Path)

XDP 是 Linux 内核的高性能数据包处理框架：

```
Network Card
     ↓
  XDP Hook  ← eBPF 程序在这里拦截数据包
     ↓
Perf Event Array  ← 结构化数据传输到用户空间
     ↓
Userspace Rust  ← 过滤、格式化、显示
     ↓
Kernel Stack  ← 数据包继续正常处理
```

### eBPF 内核程序

位于 `aya-network-monitor-ebpf/src/main.rs`:
- 在内核空间运行
- 拦截每个网络包
- 解析以太网、IP、TCP/UDP/ICMP 头
- 创建 `NetworkEvent` 结构体并通过 Perf Event Array 发送
- 返回 `XDP_PASS` 让包继续正常处理

### 用户空间程序

位于 `aya-network-monitor/src/main.rs`:
- 加载 eBPF 程序到内核
- 将程序附加到网络接口
- 从 Perf Event Array 读取事件
- 应用过滤逻辑
- 格式化并显示匹配的数据包

## 性能对比

| 方案 | 数据传输 | 解析开销 | 实现难度 |
|------|---------|---------|---------|
| 日志 + grep/awk | 中等（文本） | 高 | 简单 |
| **Perf Event + Rust** | **低（二进制）** | **低** | 中等 |
| eBPF 内核过滤 | 极低 | 无 | 复杂 |

## 部署到 PVE 宿主机

### 方案一：直接部署二进制

```bash
# 在 Arch 上编译
cargo build --release

# 传输到 PVE
scp target/release/aya-network-monitor root@pve-ip:/root/

# 在 PVE 上运行
ssh root@pve-ip
sudo /root/aya-network-monitor -i vmbr0
```

### 方案二：在 PVE 上编译

```bash
# 在 PVE 上安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 安装依赖
apt install -y build-essential llvm clang libelf-dev
cargo install bpf-linker

# 克隆项目并编译
git clone <your-repo>
cd aya-network-monitor
cargo build --release
sudo ./target/release/aya-network-monitor -i vmbr0
```

## 故障排查

### 1. 权限不足
使用 `sudo` 运行

### 2. 网卡不存在
检查网卡名称: `ip addr show`

### 3. XDP 模式问题
如果默认模式失败，修改代码使用 SKB 模式:
```rust
program.attach(&iface, XdpFlags::SKB_MODE)
```

### 4. 编译警告
编译时可能会看到 Rust 2024 兼容性警告，这是正常的。程序使用 Rust 2021 edition 以确保与 Aya 框架的兼容性。

## 相关文档

- [ARCHITECTURE.md](ARCHITECTURE.md) - 架构详细说明
- [Aya 官方文档](https://aya-rs.dev/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [eBPF Library](https://ebpf.io/)

## License

MIT OR Apache-2.0
