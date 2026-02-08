# Aya 网络流量监控 Demo

这是一个使用 [Aya](https://github.com/aya-rs/aya) 框架编写的简单 eBPF 网络流量监控程序。

## 功能

- 使用 XDP (eXpress Data Path) 在内核层面拦截网络数据包
- 记录每个网络包的大小到日志
- 零性能损耗，所有处理都在内核空间完成

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

## 运行

⚠️ **注意**: 运行 eBPF 程序需要 **root 权限**

### 基本用法

```bash
# 监控 eth0 网卡（默认）
sudo ./target/release/aya-network-monitor

# 监控指定网卡
sudo ./target/release/aya-network-monitor -i ens33

# 或者使用接口全名
sudo RUST_LOG=info ./target/release/aya-network-monitor --iface wlp3s0
```

### 查看系统网卡

```bash
ip addr show
```

### 日志级别

```bash
# 只显示 info 及以上
sudo RUST_LOG=info ./target/release/aya-network-monitor

# 显示详细信息
sudo RUST_LOG=debug ./target/release/aya-network-monitor
```

## 输出示例

```
[2024-02-08T12:34:56Z INFO aya_network_monitor] XDP program attached to interface: eth0
[2024-02-08T12:34:56Z INFO aya_network_monitor] Monitoring network traffic...
[2024-02-08T12:34:56Z INFO aya_network_monitor] Press Ctrl-C to exit
[2024-02-08T12:35:01Z INFO aya_log_ebpf] network packet: 1514 bytes
[2024-02-08T12:35:01Z INFO aya_log_ebpf] network packet: 60 bytes
[2024-02-08T12:35:02Z INFO aya_log_ebpf] network packet: 1024 bytes
```

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

## 工作原理

### XDP (eXpress Data Path)

XDP 是 Linux 内核的高性能数据包处理框架：

```
Network Card
     ↓
  XDP Hook  ← 我们在这里！
     ↓
Kernel Stack
```

### eBPF 程序

位于 `aya-network-monitor-ebpf/src/main.rs`:
- 在内核空间运行
- 拦截每个网络包
- 记录包大小
- 返回 `XDP_PASS` 让包继续正常处理

### 用户空间程序

位于 `aya-network-monitor/src/main.rs`:
- 加载 eBPF 程序到内核
- 将程序附加到网络接口
- 读取 eBPF 日志并显示

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

## 相关资源

- [Aya 官方文档](https://aya-rs.dev/)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [eBPF Library](https://ebpf.io/)

## License

MIT OR Apache-2.0
