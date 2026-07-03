# ESP32-C3 WiFi Packet Capture & Deauther Toolkit

A WiFi packet capture and security testing project based on ESP32-C3, including firmware and a Python server.

> ⚠️ For learning and authorized testing only. Comply with local laws and regulations. Only test networks you own or have explicit permission to test.

## Features

- **ESP32-C3 Firmware**: WiFi packet capture (Monitor mode), Deauth attack
- **Real-time TCP Upload**: Captured packets are sent to the server in real-time via TCP
- **Python Server**: Receive, parse, and save pcap files
- **Web Management Interface**: Real-time capture statistics, ESP32 configuration
- **Cracking Tools**: Handshake verification, targeted dictionary generation, split brute-force

## Project Structure

```
.
├── firmware/
│   ├── DeautherC3/          # Arduino version firmware (MicroPython + C hybrid)
│   └── deauther_pio/        # PlatformIO version firmware (pure C/C++)
├── server/
│   ├── server.py            # Python server (packet capture + Web management)
│   ├── requirements.txt     # Python dependencies
│   └── install.sh           # One-click install script
├── tools/
│   └── crack/               # WPA/WPA2 cracking tools
│       ├── check_handshake.py    # Handshake verification
│       ├── gen_targeted_dict.py  # Targeted dictionary generation
│       ├── crack_with_dict.sh    # Dictionary-based cracking
│       └── crack_split.sh        # Split brute-force
└── docs/
    └── CRACK_GUIDE.md       # Cracking detailed guide
```

## Quick Start

### 1. Hardware Requirements

- ESP32-C3 Super Mini (or other ESP32-C3 dev board)
- USB data cable

### 2. Build Firmware

**Arduino IDE:**
- Open `firmware/DeautherC3/DeautherC3.ino`
- Select board: `ESP32C3 Dev Module`
- Upload

**PlatformIO:**
```bash
cd firmware/deauther_pio
pio run
pio run --target upload
```

### 3. Start Server

```bash
cd server
pip install -r requirements.txt
python3 server.py --host 0.0.0.0 --port 8000 --tcp-port 9999
```

Visit `http://<server-ip>:8000` in your browser to access the management interface.

### 4. Configure ESP32

After ESP32 boots, configure via serial or web interface:
- Server IP and port
- Target BSSID / SSID
- Working mode (capture / Deauth)

## Cracking WPA/WPA2

See [docs/CRACK_GUIDE.md](docs/CRACK_GUIDE.md) for detailed steps.

Quick commands:

```bash
# Check handshake
python3 check_handshake.py handshake.pcap

# Dictionary-based cracking
./crack_with_dict.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" handshake.pcap

# Brute-force (split by first letter)
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" -d 2 -l f a
```

## Legal Notice

This project is for **learning and research** and **authorized security testing** only.

- ✅ Test your own networks
- ✅ Test with written authorization
- ❌ Attack or monitor any unauthorized network

Users assume all legal responsibility for the use of this software.

## License

MIT
