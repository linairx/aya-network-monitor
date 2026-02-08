# 数据包内容捕获功能

## 功能概述

本工具支持 5 种显示模式，可以查看网络数据包的详细内容：

1. **basic（基础模式）**：只显示头部信息（默认）
2. **hex（十六进制模式）**：显示 hex dump + ASCII
3. **text（文本模式）**：智能检测并显示可读文本
4. **protocol（协议模式）**：解析 HTTP、DNS 等协议
5. **json（JSON 模式）**：结构化数据输出（为 Web 界面准备）

## 使用方法

### 基础模式（默认）

只显示协议、IP、端口和数据包大小：

```bash
sudo ./target/release/aya-network-monitor -i ens18
```

输出示例：
```
TCP 192.168.1.100:54321 -> 93.184.216.34:443 (1248b)
UDP 192.168.1.100:54321 -> 8.8.8.8:53 (64b)
```

### 十六进制模式（--mode hex）

显示数据包内容的十六进制和 ASCII 表示：

```bash
sudo ./target/release/aya-network-monitor -i ens18 --mode hex
```

输出示例：
```
TCP 192.168.1.100:54321 -> 93.184.216.34:80 (512b)
Payload (128 bytes):
0000: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
0010: 48 6f 73 74 3a 20 77 77 77 2e 65 78 61 6d 70 6c   Host: www.exampl
0020: 65 2e 63 6f 6d 0d 0a 55 73 65 72 2d 41 67 65 6e   e.com..User-Agen
0030: 74 3a 20 63 75 72 6c 2f 37 2e 36 38 2e 30 0d 0a   t: curl/7.68.0..
...
```

### 文本模式（--mode text）

智能检测可读文本并显示：

```bash
sudo ./target/release/aya-network-monitor -i ens18 --mode text
```

输出示例：
```
TCP 192.168.1.100:54321 -> 93.184.216.34:80 (512b)
Content:
  GET / HTTP/1.1
  Host: www.example.com
  User-Agent: curl/7.68.0
  Accept: */*
```

### 协议模式（--mode protocol）

自动解析常见协议（HTTP、DNS）：

```bash
sudo ./target/release/aya-network-monitor -i ens18 --mode protocol
```

输出示例：

**HTTP 请求：**
```
TCP 192.168.1.100:54321 -> 93.184.216.34:80 (512b)
HTTP Request:
  GET /index.html HTTP/1.1
  Host: www.example.com
  User-Agent: Mozilla/5.0
  Accept: text/html
```

**DNS 查询：**
```
UDP 192.168.1.100:54321 -> 8.8.8.8:53 (64b)
DNS Query (1 questions)
  Query 1: www.google.com (type: A)
```

### JSON 模式（--mode json）

输出 JSON 格式，便于 Web 界面解析：

```bash
sudo ./target/release/aya-network-monitor -i ens18 --mode json
```

输出示例：
```json
{"timestamp":1738992000,"protocol":"TCP","src_ip":"192.168.1.100","dst_ip":"93.184.216.34","src_port":54321,"dst_port":80,"packet_size":512,"tcp_flags":24,"payload_len":128,"payload_hex":"47 45 54 20 2f ..."}
```

### 组合使用

显示模式可以与过滤条件组合使用：

```bash
# 只查看 HTTP 流量的十六进制内容
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp --dst-port 80 --mode hex

# 查看特定 IP 的 DNS 查询
sudo ./target/release/aya-network-monitor -i ens18 \
  --dst-ip 8.8.8.8 --mode protocol --src-port 53

# 查看 SSH 协议的文本内容
sudo ./target/release/aya-network-monitor -i ens18 \
  --dst-port 22 --mode text
```

### 自定义 Payload 大小

控制显示的数据包内容长度（默认 128 字节）：

```bash
# 只显示前 64 字节
sudo ./target/release/aya-network-monitor -i ens18 \
  --mode hex --payload-bytes 64

# 显示更多字节（最多 256 字节）
sudo ./target/release/aya-network-monitor -i ens18 \
  --mode hex --payload-bytes 256
```

## 实际应用场景

### 1. 调试 HTTP 请求

```bash
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp --dst-port 80 --mode protocol
```

### 2. 查看 DNS 查询

```bash
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol udp --dst-port 53 --mode protocol
```

### 3. 捕获网络流量取证

```bash
# 保存所有流量到文件（JSON 格式）
sudo ./target/release/aya-network-monitor -i ens18 \
  --mode json > traffic.json

# 查看特定 IP 的所有通信
sudo ./target/release/aya-network-monitor -i ens18 \
  --src-ip 192.168.1.100 --mode hex
```

### 4. 学习网络协议

```bash
# 查看 TCP 握手过程
sudo ./target/release/aya-network-monitor -i ens18 \
  --protocol tcp --dst-port 443 --mode hex
```

## Web 界面集成

JSON 模式专门为 Web 界面设计，包含以下字段：

```json
{
  "timestamp": 1738992000,           // Unix 时间戳
  "protocol": "TCP",                 // 协议类型
  "src_ip": "192.168.1.100",        // 源 IP
  "dst_ip": "93.184.216.34",        // 目标 IP
  "src_port": 54321,                // 源端口
  "dst_port": 443,                  // 目标端口
  "packet_size": 1248,              // 数据包大小（字节）
  "tcp_flags": 24,                  // TCP 标志位
  "payload_len": 128,               // Payload 长度
  "payload_hex": "16 03 01 ..."     // Payload 十六进制
}
```

### 前端集成示例

```rust
// 使用 cargo-leptos 创建 Web 界面
// leptos/src/app.rs

use leptos::*;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
struct NetworkEvent {
    timestamp: i64,
    protocol: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    packet_size: u32,
    payload_hex: String,
}

#[component]
fn NetworkMonitor() -> impl IntoView {
    // 从后端 WebSocket 接收 JSON 数据
    // 使用 leptos 渲染流量统计图表
    view! {
        <div class="monitor">
            <h1>"网络流量监控"</h1>
            // 实时流量图表
            // 协议分布统计
            // Top IP 地址
        </div>
    }
}
```

## 性能说明

- **Payload 大小**：默认 128 字节，可配置最多 256 字节
- **捕获开销**：启用 payload 捕获会增加约 10-20% 的 CPU 使用率
- **内存使用**：每个 CPU 核心约 10-15MB 额外内存
- **建议**：生产环境可使用 `--mode basic` 或 `--mode json` 以获得最佳性能

## 安全提醒

⚠️ **重要提示：**

1. **隐私风险**：数据包内容可能包含敏感信息
   - 密码、token
   - Session ID、Cookie
   - 应用数据

2. **合法使用**：
   - 只在**自己拥有的网络**上使用
   - 不要在未经授权的网络中使用
   - 遵守当地法律法规

3. **数据保护**：
   - 捕获的数据要妥善保管
   - 使用完毕及时删除
   - 不要在公开场合展示敏感数据

4. **加密流量**：
   - HTTPS/TLS 流量是加密的，看不到明文内容
   - 只能看到握手信息（SNI、证书等）
