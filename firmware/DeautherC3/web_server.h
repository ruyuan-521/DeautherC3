// web_server.h - Web control panel for DeautherC3 (expanded)
// No filename conflict with system <WebServer.h>
#ifndef DEAUTHER_WEB_SERVER_H
#define DEAUTHER_WEB_SERVER_H

#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include "wifi_utils.h"

#define AP_SSID     "DeautherC3"
#define AP_PASSWORD "12345678"
#define AP_CHANNEL  1

// WiFi config keys (stored in Preferences)
#define WIFI_PREFS_NS "wifi_cfg"
#define WIFI_PREFS_SSID "ssid"
#define WIFI_PREFS_PASS "pass"
#define WIFI_PREFS_VALID "valid"

class WebServerCtrl
{
public:
  WebServerCtrl(WiFi_Utils* w_utils);
  ~WebServerCtrl();
  void init();
  void handleClient();
  void loop();  // 新增：处理 WiFi 重连等后台任务

  // Attack state
  void setAttackRunning(bool running);
  void setAttackPacketCount(int count);
  void setSelectedTarget(int target_idx);
  int getSelectedTarget();
  bool getAttackRunning();
  int getAttackPacketCount();

  // Sniffer state
  void setSnifferRunning(bool running);
  void setSnifferChannel(uint8_t ch);
  bool getSnifferRunning();
  uint8_t getSnifferChannel();

  // Beacon flood state
  void setBeaconRunning(bool running);
  void setBeaconChannel(uint8_t ch);
  bool getBeaconRunning();
  uint8_t getBeaconChannel();

  // Probe sniffer state
  void setProbeRunning(bool running);
  void setProbeChannel(uint8_t ch);
  bool getProbeRunning();
  uint8_t getProbeChannel();

  // Channel hopper state
  void setChannelHopping(bool hopping);
  bool getChannelHopping();

  // Stream to server state
  void setStreamingRunning(bool running);
  bool getStreamingRunning();
  void setStreamingPackets(uint32_t count);
  uint32_t getStreamingPackets();

  // Sniffer MAC filter
  void setSnifferFilterMac(const String& mac);
  void clearSnifferFilterMac();
  String getSnifferFilterMacStr();

  // WiFi config
  bool loadWiFiConfig(String& ssid, String& pass);
  bool saveWiFiConfig(const String& ssid, const String& pass);
  void clearWiFiConfig();
  bool isWiFiConnected();
  void tryConnectWiFi();
  void disconnectWiFiSTA();

private:
  WebServer server;
  WiFi_Utils* w_utils_;

  // Attack state
  bool attack_running_ = false;
  int attack_packet_count_ = 0;
  int selected_target_ = -1;

  // Sniffer state
  bool sniffer_running_ = false;
  uint8_t sniffer_channel_ = 6;

  // Beacon flood state
  bool beacon_running_ = false;
  uint8_t beacon_channel_ = 1;

  // Probe sniffer state
  bool probe_running_ = false;
  uint8_t probe_channel_ = 6;

  // Channel hopper state
  bool channel_hopping_ = false;

  // Stream to server state
  bool streaming_running_ = false;
  uint32_t streaming_packets_ = 0;

  // Sniffer filter MAC
  String filter_mac_str_ = "";

  // WiFi STA state
  bool wifi_sta_connected_ = false;
  unsigned long last_wifi_check_ = 0;
  static const unsigned long WIFI_CHECK_INTERVAL = 5000;  // 每5秒检查一次

  // HTTP handlers
  void handleRoot();
  void handleScan();
  void handleSelect();
  void handleAttack();
  void handleSniffer();
  void handleBeacon();
  void handleProbe();
  void handleStatus();
  // WiFi config handlers
  void handleConfig();
  void handleConfigSave();
  void handleConfigClear();
  void handleConfigStatus();
  // Sniffer filter handlers
  void handleSnifferFilter();
  void handleSnifferFilterSet();
  void handleSnifferFilterClear();
  void handleSnifferFilterUseTarget();

  // Stream handlers
  void handleStreamStart();
  void handleStreamStop();

  // HTML generators (Chinese)
  void sendDashboardHTML();
  void sendScanHTML();
  void sendAttackHTML();
  void sendSnifferHTML();
  void sendBeaconHTML();
  void sendProbeHTML();
  void sendConfigHTML(bool saved = false, bool error = false, const String& msg = "");

  // Shared CSS style
  String getCSS();
};

#endif
