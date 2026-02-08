#!/bin/bash
# Aya 网络监控运行脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Aya 网络流量监控 ===${NC}"

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 请使用 sudo 运行此脚本${NC}"
    echo "用法: sudo ./run.sh [网卡名称]"
    exit 1
fi

# 获取网卡名称
IFACE=${1:-eth0}

echo -e "${YELLOW}网卡: $IFACE${NC}"

# 检查网卡是否存在
if ! ip link show "$IFACE" &>/dev/null; then
    echo -e "${RED}错误: 网卡 $IFACE 不存在${NC}"
    echo ""
    echo "可用网卡:"
    ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':'
    exit 1
fi

# 检查二进制文件
BIN="./target/release/aya-network-monitor"

if [ ! -f "$BIN" ]; then
    echo -e "${YELLOW}二进制文件不存在，正在编译...${NC}"
    cargo build --release
fi

echo -e "${GREEN}启动监控...${NC}"
echo -e "${YELLOW}按 Ctrl-C 停止${NC}"
echo ""

# 运行程序
RUST_LOG=info "$BIN" -i "$IFACE"
