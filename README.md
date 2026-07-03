# ESP32-C3 WiFi 抓包 & Deauth 工具包

一个基于 ESP32-C3 的 WiFi 抓包与安全测试项目，包含固件端和 Python 服务器端。

> ⚠️ 仅供学习和授权测试使用。请遵守当地法律法规，仅对自己拥有或已获得授权的网络进行测试。

## 功能

- **ESP32-C3 固件**：WiFi 抓包（Monitor 模式）、Deauth 攻击
- **TCP 实时上传**：抓到的包通过 TCP 实时发送到服务器
- **Python 服务器**：接收、解析、保存 pcap 文件
- **Web 管理界面**：实时查看抓包统计、配置 ESP32
- **破解工具**：握手包检查、定向字典生成、分片暴力破解

## 项目结构

```
.
├── firmware/
│   ├── DeautherC3/          # Arduino 版固件（MicroPython + C 混合）
│   └── deauther_pio/        # PlatformIO 版固件（纯 C/C++）
├── server/
│   ├── server.py            # Python 服务器（抓包接收 + Web 管理）
│   ├── requirements.txt     # Python 依赖
│   └── install.sh           # 一键安装脚本
├── tools/
│   └── crack/               # WPA/WPA2 破解工具
│       ├── check_handshake.py    # 握手包检查
│       ├── gen_targeted_dict.py  # 定向字典生成
│       ├── crack_with_dict.sh    # 定向字典破解
│       └── crack_split.sh        # 分片暴力破解
└── docs/
    └── CRACK_GUIDE.md       # 破解详细指南
```

## 快速开始

### 1. 硬件准备

- ESP32-C3 Super Mini（或其他 ESP32-C3 开发板）
- USB 数据线

### 2. 编译固件

**Arduino IDE 版：**
- 打开 `firmware/DeautherC3/DeautherC3.ino`
- 选择开发板：`ESP32C3 Dev Module`
- 上传

**PlatformIO 版：**
```bash
cd firmware/deauther_pio
pio run
pio run --target upload
```

### 3. 启动服务器

```bash
cd server
pip install -r requirements.txt
python3 server.py --host 0.0.0.0 --port 8000 --tcp-port 9999
```

浏览器访问 `http://<服务器IP>:8000` 查看管理界面。

### 4. 配置 ESP32

ESP32 启动后，通过串口或 Web 配置：
- 服务器 IP 和端口
- 目标 BSSID / SSID
- 工作模式（抓包 / Deauth）

## 破解 WPA/WPA2

详细步骤见 [docs/CRACK_GUIDE.md](docs/CRACK_GUIDE.md)。

快速命令：

```bash
# 检查握手包
python3 check_handshake.py handshake.pcap

# 定向字典破解
./crack_with_dict.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" handshake.pcap

# 暴力破解（按首字母分片）
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" -d 2 -l f a
```

## 法律声明

本项目仅用于**学习研究**和**授权的安全测试**。

- ✅ 对自己的网络进行测试
- ✅ 在获得书面授权的前提下测试
- ❌ 对任何未授权的网络进行攻击或监听

使用者需自行承担使用本软件所产生的一切法律责任。

## License

MIT
