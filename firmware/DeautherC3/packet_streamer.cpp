// packet_streamer.cpp - TCP streamer implementation for captured 802.11 packets
#include "packet_streamer.h"
#include <WiFi.h>
#include <esp_wifi.h>

PacketStreamer::PacketStreamer()
  : head_(0), tail_(0), count_(0), total_pushed_(0), dropped_(0),
    server_port_(SERVER_PORT), connected_(false), wifi_connected_(false),
    sent_count_(0), sta_ssid_(NULL), sta_password_(NULL),
    filter_enabled_(false)
{
  memset(server_ip_, 0, sizeof(server_ip_));
  memset(filter_bssid_, 0, sizeof(filter_bssid_));
  for (int i = 0; i < PACKET_RING_SIZE; i++) {
    buffer_[i].valid = false;
    buffer_[i].frame_len = 0;
  }
}

void PacketStreamer::setServer(const char* ip, uint16_t port)
{
  strncpy(server_ip_, ip, sizeof(server_ip_) - 1);
  server_ip_[sizeof(server_ip_) - 1] = '\0';
  server_port_ = port;
}

void PacketStreamer::setWiFi(const char* ssid, const char* password)
{
  sta_ssid_ = ssid;
  sta_password_ = password;
}

bool PacketStreamer::pushPacket(const uint8_t* data, uint16_t len,
                                 uint8_t channel, int8_t rssi)
{
  if (len == 0 || len > MAX_FRAME_SIZE) return false;

  // BSSID filter: only keep frames involving the target AP
  if (filter_enabled_ && len >= 24) {
    // Check addr1 (bytes 4-9), addr2 (bytes 10-15), addr3 (bytes 16-21)
    // BSSID can be in any of these depending on frame type + ToDS/FromDS
    bool match = (memcmp(&data[4],  filter_bssid_, 6) == 0) ||
                 (memcmp(&data[10], filter_bssid_, 6) == 0) ||
                 (memcmp(&data[16], filter_bssid_, 6) == 0);
    if (!match) return false;  // Skip frames not from target network
  }

  // Check if buffer is full
  if (count_ >= PACKET_RING_SIZE) {
    dropped_++;
    // Overwrite oldest
    tail_ = (tail_ + 1) % PACKET_RING_SIZE;
    count_--;
  }

  PacketEntry& entry = buffer_[head_];
  memcpy(entry.frame_data, data, len);
  entry.frame_len = len;
  entry.channel = channel;
  entry.rssi = rssi;
  entry.timestamp_ms = millis();
  entry.valid = true;

  head_ = (head_ + 1) % PACKET_RING_SIZE;
  count_++;
  total_pushed_++;

  return true;
}

int PacketStreamer::getBufferCount()
{
  return count_;
}

bool PacketStreamer::connectToServer()
{
  if (connected_ && client_.connected()) return true;

  // Must have WiFi STA connection before attempting TCP
  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long last_sta_warn = 0;
    if (millis() - last_sta_warn >= 10000) {
      last_sta_warn = millis();
      Serial.println("[STREAMER] WiFi STA not connected - cannot reach server!");
      Serial.println("[STREAMER] Configure WiFi at: 192.168.4.1/config");
    }
    connected_ = false;
    return false;
  }

  // Resolve server IP to avoid DNS delay during connect
  IPAddress server_addr;
  if (!server_addr.fromString(server_ip_)) {
    Serial.printf("[STREAMER] Invalid server IP: %s\n", server_ip_);
    connected_ = false;
    return false;
  }

  Serial.printf("[STREAMER] WiFi OK (IP:%s), connecting to %s:%d ...\n",
                WiFi.localIP().toString().c_str(), server_ip_, server_port_);

  // Set TCP connect timeout to 3 seconds (prevents 10-30s main loop freeze)
  client_.setTimeout(3);

  if (!client_.connect(server_addr, server_port_)) {
    Serial.println("[STREAMER] Connection failed!");
    connected_ = false;
    return false;
  }

  connected_ = true;
  Serial.println("[STREAMER] Connected to server!");

  // Send handshake header: "DEAUTHC3" magic + version
  const char* header = "DEAUTHC3\x01";  // Version 1
  client_.write((const uint8_t*)header, 8);

  return true;
}

void PacketStreamer::disconnect()
{
  if (client_.connected()) client_.stop();
  connected_ = false;
  Serial.println("[STREAMER] Disconnected");
}

bool PacketStreamer::isConnected()
{
  return connected_ && client_.connected();
}

bool PacketStreamer::ensureConnected()
{
  if (isConnected()) return true;
  return connectToServer();
}

void PacketStreamer::sendPacket(const PacketEntry& pkt)
{
  if (!pkt.valid || pkt.frame_len == 0) return;

  // Packet format sent to server:
  // [4 bytes] timestamp_ms (little-endian)
  // [1 byte]  channel
  // [1 byte]  rssi (signed)
  // [2 bytes] frame_len (little-endian)
  // [N bytes] raw frame data

  uint8_t header[8];
  header[0] = pkt.timestamp_ms & 0xFF;
  header[1] = (pkt.timestamp_ms >> 8) & 0xFF;
  header[2] = (pkt.timestamp_ms >> 16) & 0xFF;
  header[3] = (pkt.timestamp_ms >> 24) & 0xFF;
  header[4] = pkt.channel;
  header[5] = (uint8_t)pkt.rssi;
  header[6] = pkt.frame_len & 0xFF;
  header[7] = (pkt.frame_len >> 8) & 0xFF;

  client_.write(header, 8);
  client_.write(pkt.frame_data, pkt.frame_len);
  sent_count_++;
}

void PacketStreamer::loop()
{
  // Don't do anything if buffer is empty
  if (count_ == 0) return;

  // Ensure we're connected to the server
  // CRITICAL: Only attempt connection if we haven't tried recently,
  // because client_.connect() is a BLOCKING call with 10-30s timeout
  // that would freeze the entire main loop!
  static unsigned long last_connect_attempt = 0;
  static bool last_connect_failed = false;
  unsigned long now = millis();

  // If last connect failed, wait 30 seconds before retrying
  if (last_connect_failed) {
    if (now - last_connect_attempt < 30000) {
      return;  // Skip - don't block the loop with another connect attempt
    }
    last_connect_failed = false;
    Serial.println("[STREAMER] Retrying server connection...");
  }

  if (!ensureConnected()) {
    // Connection failed - mark it and DON'T retry for 30s
    if (!last_connect_failed) {
      last_connect_failed = true;
      last_connect_attempt = now;
      Serial.println("[STREAMER] Server unreachable, will retry in 30s");
    }
    return;
  }

  // Connected successfully - reset flags
  last_connect_failed = false;

  // Send all buffered packets (burst mode - send up to 20 per loop call)
  int burst = min(count_, 20);
  for (int i = 0; i < burst; i++) {
    if (!buffer_[tail_].valid) {
      tail_ = (tail_ + 1) % PACKET_RING_SIZE;
      count_--;
      continue;
    }

    sendPacket(buffer_[tail_]);
    buffer_[tail_].valid = false;
    tail_ = (tail_ + 1) % PACKET_RING_SIZE;
    count_--;

    // Check if still connected after each packet
    if (!client_.connected()) {
      connected_ = false;
      Serial.println("[STREAMER] Connection lost during send!");
      break;
    }

    delay(1);  // Small delay between packets
  }

  // Periodic stats output
  static unsigned long last_stats = 0;
  if (millis() - last_stats >= 10000 && sent_count_ > 0) {
    last_stats = millis();
    Serial.printf("[STREAMER] Stats: sent=%lu dropped=%lu buf=%d\n",
                  sent_count_, dropped_, count_);
  }
}

uint32_t PacketStreamer::getPacketsSent() { return sent_count_; }
uint32_t PacketStreamer::getPacketsDropped() { return dropped_; }

// ─── BSSID Filter ─────────────────────────────────────────────

void PacketStreamer::setFilterBSSID(const uint8_t* bssid) {
  memcpy(filter_bssid_, bssid, 6);
  filter_enabled_ = true;
  Serial.printf("[STREAMER] BSSID filter set: %02X:%02X:%02X:%02X:%02X:%02X\n",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

void PacketStreamer::clearFilter() {
  filter_enabled_ = false;
  Serial.println("[STREAMER] BSSID filter cleared - streaming all packets");
}

bool PacketStreamer::isFilterActive() {
  return filter_enabled_;
}
