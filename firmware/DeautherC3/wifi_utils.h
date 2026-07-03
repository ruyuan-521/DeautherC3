// wifi_utils.h - Expanded WiFi utilities for DeautherC3
// Includes: Sniffer, Beacon Flood, Probe Request Sniffer, Channel Hopper, Packet Streaming
#ifndef WIFI_UTILS_H
#define WIFI_UTILS_H

#include <WiFi.h>
#include <esp_wifi.h>
#include <string>
#include <vector>

// Forward declaration for packet streaming
class PacketStreamer;

struct wifiData
{
  int num;
  std::vector<std::string> ssid;
  std::vector<std::string> bssid;
  std::vector<uint32_t> channel;
  std::vector<float> signal;
};

struct snifferStats
{
  uint32_t total_frames = 0;
  uint32_t mgmt_frames = 0;
  uint32_t data_frames = 0;
  uint32_t ctrl_frames = 0;
  uint32_t probe_req_frames = 0;
  std::string last_src_mac = "";
  std::string last_dst_mac = "";
  uint8_t last_frame_type = 0;
  uint8_t last_frame_subtype = 0;
};

struct probeData
{
  int num = 0;
  std::vector<std::string> client_mac;
  std::vector<std::string> ssid;
  std::vector<uint32_t> channel;
  std::vector<int> count;
};

#define BEACON_NAMES_COUNT 16

class WiFi_Utils
{
public:
  WiFi_Utils(bool random_mac);
  bool isInit = false;

  // Original methods
  wifiData scanWifiList();
  bool init();
  bool connectToWifi(std::string SSID, std::string PASSWORD, std::string HOSTNAME, const int MAX_ATTEMPTS,
                     const int TRIAL_DELAY);
  void sendDeauthPacket(const uint8_t* bssid, const uint8_t* sta);
  bool scanSinglePort(IPAddress ip, int port, int timeout_ms);
  std::vector<int> scanPortsInRange(IPAddress ip, int startPort, int endPort, int timeout_ms);
  std::string macAddress();
  wifiData wifi_list;

  // Sniffer
  void startSniffer(uint8_t channel);
  void stopSniffer();
  bool isSniffing();
  snifferStats getSnifferStats();
  void resetSnifferStats();

  // Probe Request Sniffer
  void startProbeSniffer(uint8_t channel);
  void stopProbeSniffer();
  bool isProbeSniffing();
  probeData getProbeData();
  void resetProbeData();

  // Beacon Flood
  void sendBeaconFrame(const char* ssid, const uint8_t* bssid, uint8_t channel);
  void startBeaconFlood(uint8_t channel);
  void stopBeaconFlood();
  bool isBeaconFlooding();
  uint32_t getBeaconFloodCount();
  void incrementBeaconFloodCount();

  // Channel Control
  void setChannel(uint8_t channel);
  void startChannelHopper();
  void stopChannelHopper();
  bool isChannelHopping();
  uint8_t getCurrentChannel();
  void hopChannel();  // Called in main loop for auto-hop

  // Packet streaming (to remote server)
  void setPacketStreamer(PacketStreamer* streamer);
  PacketStreamer* getPacketStreamer();

  // Sniffer MAC filter (only capture frames from/to specific device)
  void setSnifferFilter(const uint8_t* mac);
  void setSnifferFilterFromStr(const char* mac_str);
  void clearSnifferFilter();
  bool isSnifferFiltered();
  const uint8_t* getSnifferFilterMac();
  void getSnifferFilterMacStr(char* out, size_t len);

private:
  std::string mac_address;
  bool random_mac_enable = false;
  bool changeMACAddress();

  // Static instance for callback access
  static WiFi_Utils* instance_;
  static void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
  static void probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

  // Sniffer state
  bool sniffer_active_ = false;
  uint8_t sniffer_channel_ = 1;
  snifferStats sniffer_stats_;

  // Probe sniffer state
  bool probe_sniffer_active_ = false;
  probeData probe_data_;

  // Channel hopper state
  bool channel_hopping_ = false;
  uint8_t current_channel_ = 1;
  unsigned long last_hop_time_ = 0;

  // Beacon flood state
  bool beacon_flood_active_ = false;
  uint8_t beacon_flood_channel_ = 1;
  uint32_t beacon_flood_count_ = 0;

  // Packet streamer (for remote server streaming)
  PacketStreamer* packet_streamer_ = NULL;

  // MAC filter (sniffer only captures frames involving this MAC)
  uint8_t filter_mac_[6];
  bool    filter_enabled_ = false;
};

#endif  // WIFI_UTILS_H
