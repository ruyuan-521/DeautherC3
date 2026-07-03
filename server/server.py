#!/usr/bin/env python3
"""
DeautherC3 Packet Server - Remote WiFi packet decoder & viewer
===============================================================
Receives raw 802.11 frames from ESP32-C3 via TCP, decodes them with Scapy,
and serves a real-time web interface for packet viewing.

Architecture:
    ESP32-C3 (sniffer) --> TCP:9999 --> This Server (decode+store) --> Web UI (SSE)

Usage:
    python3 server.py [--host 0.0.0.0] [--port 8000] [--tcp-port 9999]

Dependencies:
    pip install scapy flask scapy-python3
"""

import argparse
import struct
import time
import json
import threading
import queue
import os
import sys
from collections import deque
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Optional
import socket
import select

# ─── Version ─────────────────────────────────────────────────
SERVER_VERSION = "2026-07-02d"
# After uploading server.py, verify via:
#   Web UI footer:  shows version string
#   API:           curl http://<server>:8000/api/version
#   SSH:           journalctl -u deauthc3-server | grep "DeautherC3"
# ─────────────────────────────────────────────────────────────

# ─── Configuration ──────────────────────────────────────────────

DEFAULT_TCP_PORT = 9999      # Port for receiving ESP32 packets
DEFAULT_WEB_PORT = 8000       # Port for web interface
DEFAULT_HOST = "0.0.0.0"     # Bind address

# Ring buffer size (max packets kept in memory)
MAX_PACKETS = 500
MAX_HANDSHAKES = 200  # Max EAPOL handshake frames stored

CST = timezone(timedelta(hours=8))  # China Standard Time


# ─── Packet Data Structure ──────────────────────────────────────

@dataclass
class DecodedPacket:
    """A decoded 802.11 packet entry."""
    index: int = 0
    timestamp_ms: float = 0.0          # Device uptime ms
    capture_time: str = ""             # ISO format local time
    channel: int = 0
    rssi: int = 0
    frame_type: str = ""               # Management / Control / Data
    frame_subtype: str = ""            # Beacon / Probe Req / Deauth / etc.
    src_mac: str = ""
    dst_mac: str = ""
    bssid: str = ""
    ssid: str = ""                     # For beacon/probe frames
    frame_len: int = 0
    raw_hex: str = ""                  # First 64 bytes as hex (for debugging)
    is_wds: bool = False
    is_frag: bool = False
    is_retry: bool = False
    is_protected: bool = False
    is_pwr_mgmt: bool = False
    seq_num: int = 0

    def to_dict(self):
        return asdict(self)


# ─── Frame Type Decoder ─────────────────────────────────────────

FRAME_TYPES = {
    0: "管理帧",
    1: "控制帧",
    2: "数据帧",
    3: "扩展帧"
}

MGMT_SUBTYPES = {
    0:  "关联请求",
    1:  "关联响应",
    2:  "重新关联请求",
    3:  "重新关联响应",
    4:  "探测请求",
    5:  "探测响应",
    8:  "信标帧",
    9:  "ATIM",
    10: "取消关联",
    11: "身份认证",
    12: "取消认证",
    13: "Action帧",
    14: "Action No Ack",
}

CTRL_SUBTYPES = {
    8:  "Block Ack 请求",
    9:  "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End+CF-Ack",
}

DATA_SUBTYPES = {
    0:  "数据",
    1:  "数据+CF-Ack",
    2:  "数据+CF-Poll",
    3:  "数据+CF-Ack+CF-Poll",
    4:  "空数据",
    5:  "CF-Ack (无数据)",
    6:  "CF-Poll (无数据)",
    7:  "CF-Ack+CF-Poll (无数据)",
}


def is_eapol_key_frame(raw_bytes: bytes) -> Optional[dict]:
    """Check if a raw 802.11 frame contains an EAPOL-Key (WPA handshake) message.
    
    Returns dict with bssid/sta_mac/key_info if EAPOL-Key, None otherwise.
    
    802.11 Data frame layout after MAC header (24 bytes):
      [optional 2B QoS Control] + LLC/SNAP (AA:AA:03:00:00:00:88:8E) + EAPOL
    """
    if len(raw_bytes) < 40:
        return None
    
    fc0 = raw_bytes[0]
    fc1 = raw_bytes[1]
    subtype = (fc0 & 0xF0) >> 4
    
    # Must be Data frame
    if (fc0 & 0x0C) != 0x08:
        return None
    
    # Calculate LLC offset: skip QoS Control (2 bytes) if subtype bit3 is set
    llc_offset = 26 if (subtype & 0x08) else 24
    
    if len(raw_bytes) < llc_offset + 12:
        return None
    
    # Check LLC/SNAP: AA AA 03 00 00 00
    if raw_bytes[llc_offset:llc_offset + 6] != b'\xaa\xaa\x03\x00\x00\x00':
        return None
    
    # Check EtherType = 0x888E (EAPOL)
    ethertype = struct.unpack(">H", raw_bytes[llc_offset + 6:llc_offset + 8])[0]
    if ethertype != 0x888E:
        return None
    
    # EAPOL header: Version(1) + Type(1) + Length(2)
    eapol_start = llc_offset + 8
    if len(raw_bytes) < eapol_start + 4:
        return None
    
    eapol_type = raw_bytes[eapol_start + 1]
    if eapol_type != 3:  # 3 = EAPOL-Key
        return None
    
    # Extract BSSID and STA MAC based on ToDS/FromDS
    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    
    if to_ds and not from_ds:
        # To AP: addr1 = BSSID(RA), addr2 = STA(SA)
        bssid = ":".join(f"{b:02X}" for b in raw_bytes[4:10])
        sta_mac = ":".join(f"{b:02X}" for b in raw_bytes[10:16])
    elif from_ds and not to_ds:
        # From AP: addr1 = STA(DA), addr2 = BSSID(TA)
        sta_mac = ":".join(f"{b:02X}" for b in raw_bytes[4:10])
        bssid = ":".join(f"{b:02X}" for b in raw_bytes[10:16])
    else:
        return None  # WDS or ad-hoc EAPOL - unusual
    
    # Parse Key Info field (EAPOL-Key byte offset 5-6)
    if len(raw_bytes) < eapol_start + 7:
        return None
    key_info = struct.unpack(">H", raw_bytes[eapol_start + 5:eapol_start + 7])[0]
    
    return {"bssid": bssid, "sta_mac": sta_mac, "key_info": key_info}


def decode_frame(raw_bytes: bytes, channel: int, rssi: int, ts_ms: int,
                 pkt_index: int) -> Optional[DecodedPacket]:
    """Decode a raw 802.11 frame into a structured packet record."""
    if len(raw_bytes) < 24:
        return None

    pkt = DecodedPacket()
    pkt.index = pkt_index
    pkt.timestamp_ms = ts_ms
    pkt.capture_time = datetime.now(CST).isoformat(sep=" ", timespec="milliseconds")
    pkt.channel = channel
    pkt.rssi = rssi
    pkt.frame_len = len(raw_bytes)
    pkt.raw_hex = raw_bytes[:2048].hex()  # Full frame (up to 2048B) for PCAP export

    # Parse 802.11 MAC header
    fc0 = raw_bytes[0]
    fc1 = raw_bytes[1]

    pkt.frame_type = FRAME_TYPES.get((fc0 & 0x0C) >> 2, f"Reserved({(fc0 & 0x0C) >> 2})")
    subtype = (fc0 & 0xF0) >> 4

    # Parse flags
    pkt.is_protected = bool(fc1 & 0x40)
    pkt.is_pwr_mgmt = bool(fc1 & 0x10)
    pkt.is_retry = bool(fc1 & 0x20)
    pkt.is_frag = bool(fc1 & 0x04)

    # Sequence number (12 bits)
    if len(raw_bytes) >= 24:
        seq_ctl = struct.unpack(">H", raw_bytes[22:24])[0]
        pkt.seq_num = seq_ctl >> 4
        pkt.is_frag = pkt.is_frag or bool(seq_ctl & 0x000F)

    # MAC addresses depend on frame type
    try:
        # addr1 (bytes 4-9): always present -> DA/RA/BSSID
        pkt.dst_mac = ":".join(f"{b:02X}" for b in raw_bytes[4:10])
        # addr2 (bytes 10-15): SA/TA/BSSID
        pkt.src_mac = ":".join(f"{b:02X}" for b in raw_bytes[10:16])

        # Determine BSSID based on ToDS/FromDS flags
        to_ds = bool(fc1 & 0x01)
        from_ds = bool(fc1 & 0x02)

        if to_ds and from_ds:
            # WDS - 4 addresses
            if len(raw_bytes) >= 30:
                pkt.bssid = ":".join(f"{b:02X}" for b in raw_bytes[16:22])
                pkt.is_wds = True
        elif to_ds:
            # To DS: addr1=BSSID(DA), addr2=SA, addr3=DA
            pkt.bssid = pkt.dst_mac
        elif from_ds:
            # From DS: addr1=DA(RA), addr2=BSSID(TA), addr3=SA
            pkt.bssid = pkt.src_mac
        else:
            # Neither: IBSS/ad-hoc, addr3=BSSID
            if len(raw_bytes) >= 24:
                pkt.bssid = ":".join(f"{b:02X}" for b in raw_bytes[16:22])
                # In ad-hoc, addr2 is source
    except Exception:
        pass

    # Frame sub-type specific decode
    type_val = (fc0 & 0x0C) >> 2

    if type_val == 0:  # Management
        pkt.frame_subtype = MGMT_SUBTYPES.get(subtype, f"MGMT({subtype})")

        # Calculate the correct tagged-parameters start offset for each subtype.
        # 802.11 management frame body = fixed fields (varies by subtype) + tagged params.
        # MAC header is always 24 bytes, so body starts at offset 24.
        _MGMT_FIXED_LEN = {
            0: 4,   # Association Request: Capability(2) + Listen Interval(2)
            1: 6,   # Association Response: Capability(2) + Status(2) + AID(2)
            2: 10,  # Reassociation Request: Capability(2) + Listen Interval(2) + Current AP(6)
            3: 6,   # Reassociation Response: Capability(2) + Status(2) + AID(2)
            4: 0,   # Probe Request: no fixed fields
            5: 12,  # Probe Response: Timestamp(8) + Beacon Interval(2) + Capability(2)
            8: 12,  # Beacon: Timestamp(8) + Beacon Interval(2) + Capability(2)
            9: 0,   # ATIM: no fixed fields
            10: 2,  # Disassociation: Reason Code(2)
            11: 6,  # Authentication: Algorithm(2) + SEQ(2) + Status(2)
            12: 2,  # Deauthentication: Reason Code(2)
        }
        tag_start = 24 + _MGMT_FIXED_LEN.get(subtype, 0)
        if len(raw_bytes) > tag_start + 2:
            ssid = extract_ssid(raw_bytes, tag_start, len(raw_bytes))
            if ssid is not None:
                pkt.ssid = ssid

    elif type_val == 1:  # Control
        pkt.frame_subtype = CTRL_SUBTYPES.get(subtype, f"CTRL({subtype})")

    elif type_val == 2:  # Data
        pkt.frame_subtype = DATA_SUBTYPES.get(subtype, f"Data({subtype})")

        # Some data frames have tagged parameters after LLC header
        if len(raw_bytes) > 40:
            # Try to find QoS or other tags
            pass

    return pkt


def _decode_ssid_bytes(data: bytes) -> str:
    """Try to decode SSID bytes with multiple encodings.
    
    WiFi SSIDs can be encoded in different ways:
    - ASCII (7-bit, most common for English)
    - UTF-8 (modern routers)
    - GBK/GB2312 (Chinese routers)
    - Latin-1 or raw bytes (some IoT/legacy devices)
    
    Returns the best decoded string, falling back to hex dump.
    """
    if not data:
        return ""
    
    # Fast path: pure ASCII
    if all(0x20 <= b <= 0x7E for b in data):
        return data.decode("ascii")
    
    # Try UTF-8 first (catch common modern encoding)
    try:
        decoded = data.decode("utf-8")
        # Check for replacement characters (U+FFFD) indicating decode failure
        if "\ufffd" not in decoded:
            return decoded
    except UnicodeDecodeError:
        pass
    
    # Try GBK (common for Chinese SSIDs)
    try:
        decoded = data.decode("gbk")
        # GBK decode almost never fails (covers most byte sequences), so check quality:
        # Must have at least 1 Chinese character or >70% printable
        printable = sum(1 for c in decoded if c.isprintable() or c in " \t")
        has_cjk = any(0x4E00 <= ord(c) <= 0x9FFF for c in decoded)
        if has_cjk or (len(decoded) > 0 and printable / len(decoded) > 0.7):
            return decoded
    except (UnicodeDecodeError, LookupError):
        pass
    
    # Try GB18030 (superset of GBK)
    try:
        decoded = data.decode("gb18030")
        printable = sum(1 for c in decoded if c.isprintable() or c in " \t")
        has_cjk = any(0x4E00 <= ord(c) <= 0x9FFF for c in decoded)
        if has_cjk or (len(decoded) > 0 and printable / len(decoded) > 0.7):
            return decoded
    except (UnicodeDecodeError, LookupError):
        pass
    
    # Last resort: require >80% printable for Latin-1 (avoid binary garbage)
    decoded = data.decode("latin-1")
    printable = sum(1 for c in decoded if c.isprintable() or c in " \t")
    if len(decoded) > 0 and printable / len(decoded) >= 0.8:
        return decoded
    
    # Fallback: hex representation
    return data.hex()


def extract_ssid(raw: bytes, start: int, end: int) -> Optional[str]:
    """Extract SSID from tagged parameters in a management frame."""
    offset = start
    while offset + 2 <= end:
        tag_id = raw[offset]
        tag_len = raw[offset + 1]
        if tag_id == 0:  # SSID tag
            if tag_len > 0 and offset + 2 + tag_len <= end:
                ssid_data = raw[offset + 2 : offset + 2 + tag_len]
                return _decode_ssid_bytes(ssid_data)
            elif tag_len == 0:
                return "(hidden)"
        offset += 2 + tag_len
        if tag_len == 0 and tag_id != 0:
            break
    return None


# ─── Packet Buffer (Thread-safe ring buffer) ─────────────────────

class PacketBuffer:
    """Thread-safe circular buffer for decoded packets."""

    def __init__(self, max_size: int = MAX_PACKETS):
        self.max_size = max_size
        self.packets = deque(maxlen=max_size)  # O(1) append, auto-evict
        self.lock = threading.Lock()
        self.total_received = 0
        self.total_dropped = 0
        self.subscribers: List[queue.Queue] = []   # SSE subscribers
        # Batch SSE: accumulate packets, flush every 200ms
        self._sse_batch: List[dict] = []
        self._sse_last_flush = time.time()
        self._sse_flush_interval = 0.2  # 200ms

    def push(self, pkt: DecodedPacket):
        """Add a packet to the buffer."""
        pkt_dict = None  # lazy init
        with self.lock:
            self.total_received += 1
            if len(self.packets) >= self.max_size:
                self.total_dropped += 1
            self.packets.append(pkt)

            # Batch SSE notifications — accumulate and flush periodically
            if self.subscribers:
                pkt_dict = pkt.to_dict()
                self._sse_batch.append(pkt_dict)
                now = time.time()
                if now - self._sse_last_flush >= self._sse_flush_interval:
                    self._flush_sse()

    def _flush_sse(self):
        """Flush batched packets to all SSE subscribers. Must hold lock."""
        if not self._sse_batch or not self.subscribers:
            return
        batch = self._sse_batch
        self._sse_batch = []
        self._sse_last_flush = time.time()
        for q in self.subscribers:
            try:
                q.put_nowait(batch)
            except queue.Full:
                pass  # subscriber is too slow, drop batch

    def get_recent(self, count: int = 50) -> List[dict]:
        """Get the most recent N packets."""
        with self.lock:
            result = [p.to_dict() for p in list(self.packets)[-count:]]
            return list(reversed(result))  # newest first

    def get_stats(self) -> dict:
        """Get buffer statistics."""
        with self.lock:
            return {
                "total_received": self.total_received,
                "in_buffer": len(self.packets),
                "max_size": self.max_size,
                "dropped": self.total_dropped,
                "subscribers": len(self.subscribers),
            }

    def subscribe(self) -> queue.Queue:
        """Subscribe to new packets (for SSE)."""
        q = queue.Queue(maxsize=200)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Unsubscribe from new packets."""
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)


# ─── Handshake Buffer (EAPOL WPA handshake capture) ────────────

@dataclass
class HandshakeEntry:
    """A captured EAPOL-Key frame from a WPA handshake."""
    bssid: str = ""
    sta_mac: str = ""
    key_info: int = 0
    capture_time: str = ""
    frame_len: int = 0
    raw_hex: str = ""  # Full frame as hex (for pcap export)


class HandshakeBuffer:
    """Thread-safe storage for captured WPA EAPOL handshake frames."""
    
    def __init__(self, max_size: int = MAX_HANDSHAKES):
        self.max_size = max_size
        self.entries: List[HandshakeEntry] = []
        self.lock = threading.Lock()
    
    def push(self, raw_frame: bytes, bssid: str, sta_mac: str, key_info: int):
        """Store an EAPOL-Key frame."""
        entry = HandshakeEntry(
            bssid=bssid,
            sta_mac=sta_mac,
            key_info=key_info,
            capture_time=datetime.now(CST).isoformat(sep=" ", timespec="milliseconds"),
            frame_len=len(raw_frame),
            raw_hex=raw_frame.hex(),
        )
        with self.lock:
            self.entries.append(entry)
            if len(self.entries) > self.max_size:
                self.entries.pop(0)
    
    def get_all(self) -> List[dict]:
        """Get all captured handshake entries grouped by BSSID."""
        with self.lock:
            return [asdict(e) for e in self.entries]
    
    def get_grouped(self) -> List[dict]:
        """Get handshake entries grouped by BSSID+STA pair."""
        with self.lock:
            groups = {}
            for e in self.entries:
                key = f"{e.bssid}|{e.sta_mac}"
                if key not in groups:
                    groups[key] = {
                        "bssid": e.bssid,
                        "sta_mac": e.sta_mac,
                        "count": 0,
                        "latest_time": e.capture_time,
                        "messages": [],  # key_info for each message
                    }
                groups[key]["count"] += 1
                groups[key]["latest_time"] = e.capture_time
                groups[key]["messages"].append(e.key_info)
            # Sort by latest time, newest first
            result = sorted(groups.values(), key=lambda g: g["latest_time"], reverse=True)
            return result
    
    def export_pcap(self, bssid_filter: str = "") -> bytes:
        """Export captured EAPOL frames as PCAP file (for aircrack/hashcat)."""
        import io
        pcap_data = bytearray()
        
        # PCAP global header
        pcap_data += struct.pack("<IHHiIII",
            0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)  # Link type 105 = IEEE 802.11
        
        with self.lock:
            for e in self.entries:
                if bssid_filter and e.bssid != bssid_filter:
                    continue
                try:
                    raw = bytes.fromhex(e.raw_hex)
                except ValueError:
                    continue
                ts_sec = int(time.time())
                pcap_data += struct.pack("<IIII", ts_sec, 0, len(raw), len(raw))
                pcap_data += raw
        
        return bytes(pcap_data)
    
    def get_stats(self) -> dict:
        """Get handshake buffer stats."""
        with self.lock:
            return {
                "total_handshakes": len(self.entries),
                "unique_pairs": len(set((e.bssid, e.sta_mac) for e in self.entries)),
            }


# ─── TCP Receiver (ESP32 connection) ─────────────────────────────

class TCPServer:
    """TCP server that receives raw 802.11 frames from ESP32-C3."""

    MAGIC = b"DEAUTHC3"
    VERSION = 1

    def __init__(self, host: str, port: int, buffer: PacketBuffer,
                 handshake_buffer: HandshakeBuffer = None):
        self.host = host
        self.port = port
        self.buffer = buffer
        self.handshake_buffer = handshake_buffer
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.client_addr: Optional[str] = None
        self.connected_at: Optional[float] = None
        self.bytes_received = 0
        self.packets_received = 0
        self.last_packet_time: Optional[float] = None

    def start(self):
        """Start the TCP listener in a background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True, name="TCPReceiver")
        self.thread.start()
        print(f"[TCP] Listening on {self.host}:{self.port}")

    def stop(self):
        """Stop the TCP server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=3)
        print("[TCP] Stopped")

    def _run(self):
        """Main TCP accept loop."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        self.server_socket.settimeout(1.0)

        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                print(f"[TCP] Client connected: {addr}")
                self.client_addr = f"{addr[0]}:{addr[1]}"
                self.connected_at = time.time()
                self._handle_client(client_sock, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                if self.running:
                    print(f"[TCP] Accept error: {e}")

        self.client_addr = None

    def _handle_client(self, sock: socket.socket, addr):
        """Handle an ESP32 client connection."""
        sock.settimeout(5.0)

        # Read handshake magic (8 bytes)
        try:
            handshake = sock.recv(8)
            if not handshake.startswith(self.MAGIC):
                print(f"[TCP] Invalid handshake from {addr}: {handshake.hex()}")
                sock.close()
                return
            version = handshake[7] if len(handshake) > 7 else 0
            print(f"[TCP] Handshake OK, version={version}")
        except socket.timeout:
            print(f"[TCP] Handshake timeout from {addr}")
            sock.close()
            return

        # Read packets in a loop
        buf = b""
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    print(f"[TCP] Client disconnected: {addr}")
                    break

                self.bytes_received += len(data)
                buf += data

                # Parse all complete packets from buffer
                buf = self._parse_buffer(buf)

                self.last_packet_time = time.time()

            except socket.timeout:
                continue
            except ConnectionResetError:
                print(f"[TCP] Connection reset by {addr}")
                break
            except Exception as e:
                if self.running:
                    print(f"[TCP] Receive error: {e}")
                break

        sock.close()
        self.client_addr = None
        print(f"[TCP] Connection closed from {addr}")

    def _parse_buffer(self, buf: bytes) -> bytes:
        """Parse complete packets from receive buffer, return remaining bytes."""
        while len(buf) >= 8:  # Need at least header (8 bytes)
            # Parse header: [4B timestamp][1B channel][1B rssi][2B frame_len]
            ts_ms = struct.unpack("<I", buf[0:4])[0]
            channel = buf[4]
            rssi = buf[5] if buf[5] < 128 else buf[5] - 256  # signed byte
            frame_len = struct.unpack("<H", buf[6:8])[0]

            total_pkt_size = 8 + frame_len

            if len(buf) < total_pkt_size:
                break  # Incomplete packet, wait for more data

            # Extract raw frame
            raw_frame = buf[8:total_pkt_size]
            buf = buf[total_pkt_size:]

            # Decode and store
            pkt = decode_frame(raw_frame, channel, rssi, ts_ms,
                               self.buffer.total_received + 1)
            if pkt:
                self.buffer.push(pkt)
                self.packets_received += 1

                # Check for EAPOL handshake frames
                if self.handshake_buffer is not None:
                    eapol_info = is_eapol_key_frame(raw_frame)
                    if eapol_info:
                        self.handshake_buffer.push(
                            raw_frame,
                            eapol_info["bssid"],
                            eapol_info["sta_mac"],
                            eapol_info["key_info"],
                        )

                # Log first few and periodic
                if self.packets_received <= 10 or self.packets_received % 100 == 0:
                    print(f"[PKT #{pkt.index}] {pkt.frame_type}/{pkt.frame_subtype} "
                          f"{pkt.src_mac[:17]} -> {pkt.dst_mac[:17]} "
                          f"ch={pkt.channel} rssi={pkt.rssi}")

        return buf

    def get_status(self) -> dict:
        """Get current server status."""
        return {
            "listening": self.running,
            "client_connected": self.client_addr is not None,
            "client_addr": self.client_addr,
            "connected_since": (
                datetime.fromtimestamp(self.connected_at, CST).isoformat()
                if self.connected_at else None
            ),
            "packets_received": self.packets_received,
            "bytes_received": self.bytes_received,
            "last_packet": (
                datetime.fromtimestamp(self.last_packet_time, CST).isoformat()
                if self.last_packet_time else None
            ),
        }


# ─── Web Server (Flask) ─────────────────────────────────────────

WEB_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DeautherC3 数据包查看器</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',system-ui,sans-serif; }
.header { background:#161b22; padding:16px 20px; border-bottom:1px solid #30363d;
           display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; }
.header h1 { color:#58a6ff; font-size:1.3em; }
.stats-bar { display:flex; gap:16px; flex-wrap:wrap; font-size:0.85em; }
.stat { background:#21262d; padding:6px 12px; border-radius:6px; border:1px solid #30363d; }
.stat .label { color:#8b949e; font-size:0.85em; }
.stat .value { color:#7ee787; font-weight:600; }
.toolbar { padding:10px 20px; background:#161b22; border-bottom:1px solid #30363d;
             display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.toolbar select, .toolbar button { background:#21262d; color:#c9d1d9; border:1px solid #30363d;
                                       padding:6px 12px; border-radius:6px; cursor:pointer; font-size:0.85em; }
.toolbar select:hover, .toolbar button:hover { border-color:#58a6ff; }
.toolbar button.primary { background:#238636; border-color:#238636; color:#fff; }
.toolbar button.danger { background:#da3633; border-color:#da3633; color:#fff; }
.toolbar button:disabled { opacity:0.5; cursor:not-allowed; }
#packet-list { height:calc(100vh - 180px); overflow-y:auto; padding:8px 20px; }
.packet-row { display:grid; grid-template-columns:140px 110px 90px 60px 170px 170px auto;
              padding:6px 10px; border-bottom:1px solid #21262d; font-size:0.82em;
              align-items:center; transition:background 0.15s; }
.packet-row:hover { background:#161b22; }
.packet-row.new { animation:fadein 0.3s; }
@keyframes fadein { from{background:#1a3a2a;} to{background:transparent;} }
.row-header { background:#161b22; font-weight:600; color:#8b949e; position:sticky; top:0; z-index:1;
               font-size:0.78em; text-transform:uppercase; letter-spacing:0.03em; }
.type-mgmt { color:#a371f7; }
.type-ctrl { color:#f778ba; }
.type-data { color:#79c0ff; }
.type-ext { color:#ffa657; }
.mac { font-family:monospace; font-size:0.9em; }
.ssid { color:#ffd33d; max-width:200px; overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
.rssi-good { color:#7ee787; } .rssi-med { color:#d29922; } .rssi-bad { color:#f85149; }
.conn-dot { width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px; }
.conn-ok { background:#238636; } .conn-warn { background:#d29922; animation:pulse 1.5s infinite; }
.conn-off { background:#da3633; }
@keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }
.empty-msg { text-align:center; padding:80px 20px; color:#484f58; font-size:1.1em; }
.footer { position:fixed; bottom:0;left:0;right:0;background:#161b22;padding:6px 20px;
           border-top:1px solid #30363d;font-size:0.75em;color:#484f58;display:flex;justify-content:space-between; }
</style>
</head>
<body>

<div class="header">
  <h1>📡 DeautherC3 数据包查看器</h1>
  <div class="stats-bar">
    <div class="stat"><span class="label">已接收</span> <span class="value" id="stat-total">0</span></div>
    <div class="stat"><span class="label">缓冲区</span> <span class="value" id="stat-buffer">0</span></div>
    <div class="stat"><span class="label">ESP32</span> <span id="stat-client"><span class="conn-dot conn-off"></span>未连接</span></div>
    <div class="stat"><span class="label">速率</span> <span class="value" id="stat-rate">0/秒</span></div>
    <div class="stat" id="stat-hs" style="display:none"><span class="label">握手</span> <span class="value" id="stat-handshake" style="color:#ffa657">0</span></div>
  </div>
</div>

<div class="toolbar">
  <select id="filter-type" title="按帧类型过滤">
    <option value="">所有类型</option>
    <option value="管理帧">仅管理帧</option>
    <option value="控制帧">仅控制帧</option>
    <option value="数据帧">仅数据帧</option>
  </select>
  <select id="filter-subtype" title="按子类型过滤">
    <option value="">所有子类型</option>
  </select>
  <input id="search-mac" placeholder="MAC 过滤..." style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;
         padding:6px 12px;border-radius:6px;font-size:0.85em;width:150px;" />
  <button onclick="toggleAutoScroll()" id="btn-scroll">自动滚动: 开</button>
  <button class="primary" onclick="clearPackets()">清空</button>
  <button class="danger" id="btn-export" onclick="exportPcap()" disabled>导出 PCAP</button>
  <button class="danger" id="btn-export-hs" onclick="exportHandshakePcap()" disabled>导出握手</button>
</div>

<div id="packet-list">
    <div class="packet-row row-header">
      <div>时间</div><div>类型</div><div>子类型</div><div>信道</div><div>源 MAC</div><div>目的 MAC</div><div>SSID</div>
    </div>
    <div id="packet-body">
      <div class="empty-msg">等待 ESP32-C3 数据包...</div>
  </div>
</div>

<div class="footer">
  <span>DeautherC3 数据包服务器 v{{SERVER_VERSION}} | TCP 端口: 9999</span>
  <span id="last-update"></span>
</div>

<script>
let packets = [];
let autoScroll = true;
let scrollEnabled = true;
let rateCount = 0;
let lastRateTime = Date.now();
const MAX_DISPLAY = 300;

// ─── SSE Connection ──────────────────────────────────────────
let eventSource = null;

function connectSSE() {
  const url = window.location.protocol + '//' + window.location.host + '/api/events';
  eventSource = new EventSource(url);

  eventSource.onopen = () => console.log('SSE 已连接');
  eventSource.onerror = () => {
    console.log('SSE 错误，重新连接中...');
    setTimeout(connectSSE, 3000);
  };
  eventSource.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // data can be: single packet dict, list of packets (batch), or stats dict
    if (Array.isArray(data)) {
      // Batch of packets
      data.forEach(pkt => {
        packets.push(pkt);
        if (packets.length > MAX_DISPLAY) packets.shift();
      });
      renderPackets();
      // Throttle stats update to avoid spamming
      if (!window._statsTimer) {
        window._statsTimer = setTimeout(() => { updateStats(); window._statsTimer = null; }, 1000);
      }
    } else if (data && data.total_received !== undefined) {
      // Initial stats object, ignore
    } else {
      // Single packet
      addPacket(data);
    }
  };
}

// ─── Packet Display ──────────────────────────────────────────
function addPacket(pkt) {
  packets.push(pkt);
  if (packets.length > MAX_DISPLAY) packets.shift();
  // Throttle rendering to avoid lag under high packet rate
  if (!window._renderTimer) {
    window._renderTimer = setTimeout(() => { renderPackets(); window._renderTimer = null; }, 300);
  }
}

function renderPackets() {
  const body = document.getElementById('packet-body');
  const filterType = document.getElementById('filter-type').value;
  const filterSub = document.getElementById('filter-subtype').value;
  const searchMac = document.getElementById('search-mac').value.toUpperCase();

  let filtered = packets.filter(p => {
    if (filterType && p.frame_type !== filterType) return false;
    if (filterSub && p.frame_subtype !== filterSub) return false;
    if (searchMac && !p.src_mac.includes(searchMac) && !p.dst_mac.includes(searchMac) &&
                 !p.bssid.includes(searchMac)) return false;
    return true;
  });

  if (filtered.length === 0) {
    body.innerHTML = '<div class="empty-msg">No matching packets</div>';
    return;
  }

  let html = '';
  // Show newest first
  for (let i = filtered.length - 1; i >= Math.max(0, filtered.length - 200); i--) {
    const p = filtered[i];
    const isNew = (i === filtered.length - 1);
    const typeCls = 'type-' + (p.frame_type === '管理帧' ? 'mgmt' :
                                p.frame_type === '控制帧' ? 'ctrl' :
                                p.frame_type === '数据帧' ? 'data' : 'ext');
    const rssiCls = (p.rssi >= -50) ? 'rssi-good' : (p.rssi >= -70) ? 'rssi-med' : 'rssi-bad';
    const timeStr = p.capture_time ? p.capture_time.split(' ')[1].split('.')[0] : '';
    const ssidHtml = p.ssid ? `<span class="ssid">${escHtml(p.ssid)}</span>` : '';

    html += `<div class="packet-row ${isNew?'new':''}">
      <div>${timeStr}</div>
      <div class="${typeCls}">${escHtml(p.frame_type)}</div>
      <div>${escHtml(p.frame_subtype)}</div>
      <div class="${rssiCls}">${p.rssi}</div>
      <div class="mac">${escHtml(p.src_mac)}</div>
      <div class="mac">${escHtml(p.dst_mac)}</div>
      <div>${ssidHtml}</div>
    </div>`;
  }
  body.innerHTML = html;

  if (autoScroll && scrollEnabled) {
    const list = document.getElementById('packet-list');
    list.scrollTop = list.scrollHeight;
  }
}

// ─── Stats Update ────────────────────────────────────────────
function updateStats() {
  rateCount++;
  const now = Date.now();
  if (now - lastRateTime >= 1000) {
    document.getElementById('stat-rate').textContent = rateCount + '/秒';
    rateCount = 0;
    lastRateTime = now;
  }
  document.getElementById('stat-total').textContent = packets.length;

  fetch('/api/stats').then(r=>r.json()).then(s=>{
    document.getElementById('stat-buffer').textContent = s.in_buffer;
    const cliEl = document.getElementById('stat-client');
    const tcp = s.tcp || {};
    if (tcp.client_connected) {
      cliEl.innerHTML = '<span class="conn-dot conn-ok"></span>' +
                        (tcp.client_addr || 'Connected') +
                        ` (${tcp.packets_received})`;
    } else {
      cliEl.innerHTML = '<span class="conn-dot conn-off"></span>Disconnected';
    }

    // Enable export button if we have ANY packets (total_received or in_buffer)
    if (s.total_received > 0 || s.in_buffer > 0) {
      document.getElementById('btn-export').disabled = false;
    }
  });

  // Fetch handshake stats
  fetch('/api/handshakes').then(r=>r.json()).then(hs=>{
    const hsEl = document.getElementById('stat-hs');
    const countEl = document.getElementById('stat-handshake');
    const btnHs = document.getElementById('btn-export-hs');
    if (hs && hs.length > 0) {
      hsEl.style.display = '';
      let totalFrames = 0;
      hs.forEach(g => totalFrames += g.count);
      countEl.textContent = totalFrames;
      btnHs.disabled = false;
    } else {
      hsEl.style.display = 'none';
      btnHs.disabled = true;
    }
  });

  document.getElementById('last-update').textContent =
    '更新于：' + new Date().toLocaleTimeString();
}

// ─── Controls ─────────────────────────────────────────────────
function toggleAutoScroll() {
  autoScroll = !autoScroll;
  document.getElementById('btn-scroll').textContent = '自动滚动: ' + (autoScroll ? '开' : '关');
}
function clearPackets() { packets = []; renderPackets(); }
function exportPcap() {
  if (packets.length === 0) { alert('没有数据包可导出'); return; }
  window.location.href = '/api/export?format=pcap';
}
function exportHandshakePcap() {
  fetch('/api/handshakes/export')
    .then(r => {
      if (!r.ok) {
        return r.json().then(e => { throw new Error(e.error || '导出失败'); });
      }
      return r.blob();
    })
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'handshake.pcap';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })
    .catch(err => alert('导出握手失败: ' + err.message));
}
function escHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
           .replace(/"/g,'&quot;');
}

// ─── Init ─────────────────────────────────────────────────────
connectSSE();
setInterval(updateStats, 5000);
updateStats();
</script>
</body>
</html>"""


# ─── Web API Routes ───────────────────────────────────────────

def create_app(buffer: PacketBuffer, tcp_server: TCPServer,
                handshake_buffer: HandshakeBuffer = None):
    """Create the Flask application."""
    try:
        from flask import Flask, Response, jsonify, send_file, request
        import io
    except ImportError:
        print("[ERROR] Flask not installed! Run: pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    app.config['JSON_AS_ASCII'] = False

    @app.route("/")
    def index():
        html = WEB_HTML.replace("{{SERVER_VERSION}}", SERVER_VERSION)
        return html, 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/api/version")
    def api_version():
        """Return server version info."""
        return jsonify({
            "version": SERVER_VERSION,
            "server": "DeautherC3 Packet Server",
        })

    @app.route("/api/packets")
    def api_packets():
        count = min(int(request.args.get("count", 50)), 200)
        return jsonify(buffer.get_recent(count))

    @app.route("/api/stats")
    def api_stats():
        stats = buffer.get_stats()
        stats["tcp"] = tcp_server.get_status()
        return jsonify(stats)

    @app.route("/api/events")
    def api_events():
        """Server-Sent Events endpoint for real-time packet updates."""
        def generate():
            q = buffer.subscribe()
            try:
                # Send initial stats
                yield f"data: {json.dumps(buffer.get_stats())}\n\n"
                while True:
                    try:
                        data = q.get(timeout=30)
                        # data can be a single dict or a list of dicts (batch)
                        if isinstance(data, list):
                            yield f"data: {json.dumps(data)}\n\n"
                        else:
                            yield f"data: {json.dumps(data)}\n\n"
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            finally:
                buffer.unsubscribe(q)

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @app.route("/api/export")
    def api_export():
        """Export captured packets as PCAP file."""
        fmt = request.args.get("format", "pcap")
        if fmt != "pcap":
            return jsonify({"error": "Only pcap format supported"}), 400

        # Check if we have any packets
        with buffer.lock:
            pkt_count = len(buffer.packets)
        if pkt_count == 0:
            return jsonify({"error": "No packets to export"}), 400

        # Generate PCAP file
        pcap_data = bytearray()

        # PCAP global header (24 bytes)
        pcap_data += struct.pack("<IHHiIII",
            0xa1b2c3d4,   # Magic
            2, 4,         # Version major/minor
            0,            # Timezone
            0,            # Sigfigs
            65535,        # Snaplen
            105           # Link type: IEEE 802.11
        )

        # Write each packet
        with buffer.lock:
            for pkt in buffer.packets:
                # Convert hex string back to bytes
                raw = bytes.fromhex(pkt.raw_hex) if pkt.raw_hex else b""
                if len(raw) < 24:
                    continue

                ts_sec = int(time.time())
                ts_usec = 0
                incl_len = len(raw)
                orig_len = len(raw)

                pcap_data += struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
                pcap_data += raw

        bio = io.BytesIO(bytes(pcap_data))
        filename = f"deautherc3_{datetime.now(CST).strftime('%Y%m%d_%H%M%S')}.pcap"

        return send_file(
            bio,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/api/handshakes")
    def api_handshakes():
        """Get all captured WPA handshake frames, grouped by BSSID+STA."""
        if handshake_buffer is None:
            return jsonify([])
        return jsonify(handshake_buffer.get_grouped())

    @app.route("/api/handshakes/export")
    def api_handshakes_export():
        """Export captured EAPOL handshake frames as PCAP (for aircrack/hashcat)."""
        if handshake_buffer is None:
            return jsonify({"error": "handshake capture disabled"}), 400

        bssid_filter = request.args.get("bssid", "")
        pcap_data = handshake_buffer.export_pcap(bssid_filter)

        # Check if PCAP only contains the 24-byte global header (no frames)
        if len(pcap_data) <= 24:
            return jsonify({"error": "No EAPOL handshake frames captured yet"}), 400

        filename = f"handshake_{datetime.now(CST).strftime('%Y%m%d_%H%M%S')}.pcap"
        bio = io.BytesIO(pcap_data)
        return send_file(
            bio,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


# ─── Main Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DeautherC3 Packet Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Web bind address (127.0.0.1 if behind Nginx)")
    parser.add_argument("--port", type=int, default=DEFAULT_WEB_PORT, help="Web interface port")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT, help="TCP receiver port")
    parser.add_argument("--tcp-host", default="0.0.0.0", help="TCP bind address (must be 0.0.0.0 for ESP32 access)")
    args = parser.parse_args()

    print("=" * 56)
    print(f"  DeautherC3 Packet Server v{SERVER_VERSION}")
    print("=" * 56)
    print(f"  Web Interface:  http://{args.host}:{args.port}")
    print(f"  TCP Receiver:  {args.tcp_host}:{args.tcp_port}")
    print(f"  Max Packets:   {MAX_PACKETS}")
    print(f"  Verify:  curl http://{args.host}:{args.port}/api/version")
    print("=" * 56)

    # Shared packet buffer
    buffer = PacketBuffer(max_size=MAX_PACKETS)

    # Handshake buffer for WPA EAPOL capture
    handshake_buffer = HandshakeBuffer(max_size=MAX_HANDSHAKES)

    # Start TCP receiver (must bind to 0.0.0.0 so ESP32 can reach it)
    tcp_server = TCPServer(args.tcp_host, args.tcp_port, buffer, handshake_buffer)
    tcp_server.start()

    # Create and start web app
    app = create_app(buffer, tcp_server, handshake_buffer)

    # Flask dev server — waitress buffers SSE responses, breaking real-time push.
    # The real perf fixes (deque, batch SSE, render throttle) are in PacketBuffer.
    print("[WEB] Using Flask dev server (SSE compatible)")
    try:
        app.run(host=args.host, port=args.port, threaded=True, debug=False)
    except KeyboardInterrupt:
        print("\n[MAIN] Shutting down...")
    finally:
        tcp_server.stop()


if __name__ == "__main__":
    main()
