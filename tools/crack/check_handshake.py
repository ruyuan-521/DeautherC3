#!/usr/bin/env python3
"""
检查握手包质量并估算破解时间
用法: python3 check_handshake.py [handshake.pcap]
"""

import subprocess
import sys
import os

PCAP = sys.argv[1] if len(sys.argv) > 1 else "handshake.pcap"

def run_check():
    if not os.path.exists(PCAP):
        print(f"[!] 找不到 {PCAP}")
        return

    print("=" * 50)
    print(f"[1/3] 用 aircrack-ng 检查握手包...")
    print("=" * 50)
    try:
        r = subprocess.run(
            ["aircrack-ng", PCAP],
            capture_output=True, text=True, timeout=30
        )
        print(r.stdout)
    except FileNotFoundError:
        print("[!] 未安装 aircrack-ng")
        print("    安装: apt install aircrack-ng")

    print("=" * 50)
    print("[2/3] 尝试提取 hashcat 格式 hash...")
    print("=" * 50)
    try:
        r = subprocess.run(
            ["hcxpcapngtool", "-o", "hash.hc22000", PCAP],
            capture_output=True, text=True, timeout=30
        )
        print(r.stdout)
        if os.path.exists("hash.hc22000"):
            sz = os.path.getsize("hash.hc22000")
            print(f"[+] hash.hc22000 生成成功 ({sz} bytes)")
    except FileNotFoundError:
        print("[!] 未安装 hcxpcapngtool，跳过 hashcat 格式提取")
        print("    安装: apt install hcxtools")

    print("=" * 50)
    print("[3/3] 破解时间估算")
    print("=" * 50)
    print("格式: 6小写字母 + 1数字 + 1小写字母 = 26^6 * 10 * 26 = 803 亿\n")
    print(f"  500 H/s  ->  1859 天  (5.1 年)")
    print(f"  1000 H/s  ->  930 天  (2.5 年)")
    print(f"  2000 H/s  ->  465 天  (1.3 年)")
    print(f"  1万 H/s   ->  93 天   (3 个月)")
    print(f"  10万 H/s  ->  9 天")
    print(f"  100万 H/s ->  22 小时")
    print(f"  1000万 H/s -> 2 小时")
    print()
    print("如果知道数字或末位字母，搜索空间会缩小 10~26 倍。")
    print("建议: 先用定向字典，再考虑 GPU 爆破。")

if __name__ == "__main__":
    run_check()
