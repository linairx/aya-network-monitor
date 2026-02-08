# 网络流量过滤指南

## 基本使用

```bash
sudo ./target/release/aya-network-monitor -i ens18
```

## 过滤技巧

### 1. 协议过滤

**只看 TCP:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep TCP
```

**只看 UDP:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep UDP
```

**只看 ICMP (ping):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ICMP
```

**组合多个协议:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -E "TCP|UDP"
```

### 2. 端口过滤

**只看 SSH (端口 22):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ":22 "
```

**只看 HTTP (端口 80):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ":80 "
```

**只看 HTTPS (端口 443):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ":443 "
```

**查看多个端口:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -E ":(22|80|443) "
```

### 3. IP 地址过滤

**只看某个 IP 的流量:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "192.168.8.34"
```

**只看某个源 IP:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "192.168.8.34 ->"
```

**只看某个目标 IP:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "-> 192.168.8.34"
```

**排除某个 IP:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -v "192.168.8.34"
```

### 4. 高级过滤

**查看大包 (>1000 字节):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -E "\([0-9]{4,}b\)"
```

**查看小包 (<100 字节):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -E "\([0-9]{1,3}b\)"
```

**只看有 SYN 标志的 TCP 连接:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "S=1"
```

**只看已建立的连接 (有 ACK):**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "A=1"
```

### 5. 组合过滤

**查看特定 IP 的 SSH 流量:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "192.168.8.34" | grep ":22 "
```

**查看 TCP 但排除 SSH:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep TCP | grep -v ":22 "
```

**查看来自特定 IP 的 HTTP 和 HTTPS:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep "192.168.8.34" | grep -E ":(80|443) "
```

## 实用示例

### 监控 SSH 登录
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ":22 "
```

### 监控 Web 流量
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -E ":(80|443|8080) "
```

### 监控 DNS 查询
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep ":53 "
```

### 排除本地回环
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep -v "127.0.0.1"
```

### 统计流量来源
```bash
sudo ./target/release/aya-network-monitor -i ens18 | awk '{print $3}' | sort | uniq -c | sort -rn
```

### 实时流量统计（每秒更新）
```bash
watch -n 1 'sudo ./target/release/aya-network-monitor -i ens18 | head -20'
```

## 保存到文件

**保存所有日志:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 > traffic.log
```

**保存过滤后的日志:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | grep TCP > tcp_traffic.log
```

**后台运行并保存:**
```bash
sudo nohup ./target/release/aya-network-monitor -i ens18 > traffic.log 2>&1 &
```

## 性能优化

**降低日志级别（减少输出）:**
```bash
sudo RUST_LOG=warn ./target/release/aya-network-monitor -i ens18
```

**只统计包数量（不显示详情）:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | wc -l
```

## 与其他工具结合

**实时流量图表（需要 tcpdump）:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | while read line; do
    echo "$line" | grep -oP '\d+(?=b)' | awk '{sum+=$1} END {print sum}'
done
```

**按协议分组统计:**
```bash
sudo ./target/release/aya-network-monitor -i ens18 | awk '{print $1}' | sort | uniq -c
```
