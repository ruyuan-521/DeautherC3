// web_server.cpp - Full Chinese Web control panel for DeautherC3
// Features: Deauth, Beacon Flood, Packet Sniffer, Probe Sniffer
// Chinese HTML interface, mobile-friendly dark theme
#include "web_server.h"

WebServerCtrl::WebServerCtrl(WiFi_Utils* w_utils)
  : server(80), w_utils_(w_utils)
{
}

WebServerCtrl::~WebServerCtrl()
{
}

void WebServerCtrl::init()
{
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL);
  Serial.print("[WEB] AP started: ");
  Serial.print(AP_SSID);
  Serial.print(" IP: ");
  Serial.println(WiFi.softAPIP());

  // Core routes
  server.on("/", HTTP_GET, [this]() { handleRoot(); });
  server.on("/scan", HTTP_GET, [this]() { handleScan(); });
  server.on("/select", HTTP_GET, [this]() { handleSelect(); });
  server.on("/attack", HTTP_GET, [this]() { handleAttack(); });
  server.on("/status", HTTP_GET, [this]() { handleStatus(); });

  // Attack actions
  server.on("/attack/start", HTTP_GET, [this]() {
    setAttackRunning(true);
    attack_packet_count_ = 0;
    server.sendHeader("Location", "/attack");
    server.send(302);
  });
  server.on("/attack/stop", HTTP_GET, [this]() {
    setAttackRunning(false);
    server.sendHeader("Location", "/attack");
    server.send(302);
  });

  // Target selection
  server.on("/select/set", HTTP_GET, [this]() {
    if (server.hasArg("id")) {
      int id = server.arg("id").toInt();
      if (id >= 0 && id < w_utils_->wifi_list.num) {
        selected_target_ = id;
        Serial.printf("[WEB] Target set: %s\n", w_utils_->wifi_list.ssid[id].c_str());
      }
    }
    server.sendHeader("Location", "/attack");
    server.send(302);
  });

  // Sniffer routes
  server.on("/sniffer", HTTP_GET, [this]() { handleSniffer(); });
  server.on("/sniffer/start", HTTP_GET, [this]() {
    uint8_t ch = server.hasArg("ch") ? server.arg("ch").toInt() : 6;
    setSnifferRunning(true);
    setSnifferChannel(ch);
    server.sendHeader("Location", "/sniffer");
    server.send(302);
  });
  server.on("/sniffer/stop", HTTP_GET, [this]() {
    setSnifferRunning(false);
    server.sendHeader("Location", "/sniffer");
    server.send(302);
  });
  server.on("/sniffer/hop", HTTP_GET, [this]() {
    setChannelHopping(true);
    setSnifferRunning(true);
    setSnifferChannel(1);
    server.sendHeader("Location", "/sniffer");
    server.send(302);
  });
  // Sniffer filter routes
  server.on("/sniffer/filter", HTTP_GET, [this]() { handleSnifferFilter(); });
  server.on("/sniffer/filter/set", HTTP_GET, [this]() { handleSnifferFilterSet(); });
  server.on("/sniffer/filter/clear", HTTP_GET, [this]() { handleSnifferFilterClear(); });
  server.on("/sniffer/filter/use_target", HTTP_GET, [this]() { handleSnifferFilterUseTarget(); });

  // Beacon flood routes
  server.on("/beacon", HTTP_GET, [this]() { handleBeacon(); });
  server.on("/beacon/start", HTTP_GET, [this]() {
    uint8_t ch = server.hasArg("ch") ? server.arg("ch").toInt() : 1;
    setBeaconRunning(true);
    setBeaconChannel(ch);
    server.sendHeader("Location", "/beacon");
    server.send(302);
  });
  server.on("/beacon/stop", HTTP_GET, [this]() {
    setBeaconRunning(false);
    server.sendHeader("Location", "/beacon");
    server.send(302);
  });

  // Probe sniffer routes
  server.on("/probe", HTTP_GET, [this]() { handleProbe(); });
  server.on("/probe/start", HTTP_GET, [this]() {
    uint8_t ch = server.hasArg("ch") ? server.arg("ch").toInt() : 6;
    setProbeRunning(true);
    setProbeChannel(ch);
    server.sendHeader("Location", "/probe");
    server.send(302);
  });
  server.on("/probe/stop", HTTP_GET, [this]() {
    setProbeRunning(false);
    server.sendHeader("Location", "/probe");
    server.send(302);
  });
  server.on("/probe/hop", HTTP_GET, [this]() {
    setChannelHopping(true);
    setProbeRunning(true);
    setProbeChannel(1);
    server.sendHeader("Location", "/probe");
    server.send(302);
  });

  // Stream to server routes
  server.on("/stream/start", HTTP_GET, [this]() { handleStreamStart(); });
  server.on("/stream/stop", HTTP_GET, [this]() { handleStreamStop(); });

  // WiFi config routes
  server.on("/config", HTTP_GET, [this]() { handleConfig(); });
  server.on("/config/save", HTTP_POST, [this]() { handleConfigSave(); });
  server.on("/config/clear", HTTP_GET, [this]() { handleConfigClear(); });
  server.on("/config/status", HTTP_GET, [this]() { handleConfigStatus(); });
  server.on("/config/connect", HTTP_GET, [this]() { tryConnectWiFi(); server.sendHeader("Location", "/config"); server.send(302); });

  server.onNotFound([this]() {
    server.send(404, "text/plain", "404 Not Found");
  });

  server.begin();
  Serial.println("[WEB] Server started on port 80");
}

void WebServerCtrl::loop()
{
  // 后台检查 WiFi STA 连接状态 + 自动重连
  if (millis() - last_wifi_check_ >= WIFI_CHECK_INTERVAL) {
    last_wifi_check_ = millis();
    bool now_connected = (WiFi.status() == WL_CONNECTED);

    if (now_connected != wifi_sta_connected_) {
      wifi_sta_connected_ = now_connected;
      if (now_connected) {
        Serial.print("[WIFI] STA connected! IP: ");
        Serial.println(WiFi.localIP());
      } else {
        Serial.println("[WIFI] STA disconnected! Attempting reconnect...");
      }
    }

    // 如果断开连接，尝试使用已保存的凭据自动重连
    if (!now_connected) {
      String ssid, pass;
      if (loadWiFiConfig(ssid, pass)) {
        Serial.printf("[WIFI] Auto-reconnecting to %s...\n", ssid.c_str());
        WiFi.begin(ssid.c_str(), pass.c_str());
        // 注意: WiFi.begin() 是非阻塞的，下次 loop 会检测结果
      }
    }
  }
}

// ============== WIFI CONFIG ==============

bool WebServerCtrl::loadWiFiConfig(String& ssid, String& pass)
{
  Preferences prefs;
  prefs.begin(WIFI_PREFS_NS, true);  // read-only
  bool valid = prefs.getBool(WIFI_PREFS_VALID, false);
  if (valid) {
    ssid = prefs.getString(WIFI_PREFS_SSID, "");
    pass = prefs.getString(WIFI_PREFS_PASS, "");
  }
  prefs.end();
  return valid && ssid.length() > 0;
}

bool WebServerCtrl::saveWiFiConfig(const String& ssid, const String& pass)
{
  Preferences prefs;
  prefs.begin(WIFI_PREFS_NS, false);
  prefs.putString(WIFI_PREFS_SSID, ssid);
  prefs.putString(WIFI_PREFS_PASS, pass);
  prefs.putBool(WIFI_PREFS_VALID, true);
  prefs.end();
  return true;
}

void WebServerCtrl::clearWiFiConfig()
{
  Preferences prefs;
  prefs.begin(WIFI_PREFS_NS, false);
  prefs.clear();
  prefs.end();
  disconnectWiFiSTA();
}

bool WebServerCtrl::isWiFiConnected()
{
  return WiFi.status() == WL_CONNECTED;
}

void WebServerCtrl::tryConnectWiFi()
{
  String ssid, pass;
  if (!loadWiFiConfig(ssid, pass)) {
    Serial.println("[WIFI] No config found");
    return;
  }
  Serial.printf("[WIFI] Connecting to %s...\n", ssid.c_str());
  WiFi.begin(ssid.c_str(), pass.c_str());
  // 不阻塞，让 loop() 异步检查连接结果
}

void WebServerCtrl::disconnectWiFiSTA()
{
  WiFi.disconnect();
  wifi_sta_connected_ = false;
}

// ============== CONFIG HANDLERS ==============

void WebServerCtrl::handleConfig()
{
  sendConfigHTML();
}

void WebServerCtrl::handleConfigSave()
{
  String ssid = server.arg("ssid");
  String pass = server.arg("pass");

  if (ssid.length() == 0) {
    sendConfigHTML(false, true, "SSID 不能为空！");
    return;
  }

  // 保存配置
  saveWiFiConfig(ssid, pass);

  // 尝试连接
  WiFi.begin(ssid.c_str(), pass.c_str());

  // 等待最多 8 秒看是否连接成功
  int retries = 16;
  while (retries-- > 0 && WiFi.status() != WL_CONNECTED) {
    delay(500);
  }

  if (WiFi.status() == WL_CONNECTED) {
    sendConfigHTML(true, false, "连接成功！IP: " + WiFi.localIP().toString());
  } else {
    sendConfigHTML(true, true, "配置已保存，但连接失败，请检查密码或信号。");
  }
}

void WebServerCtrl::handleConfigClear()
{
  clearWiFiConfig();
  server.sendHeader("Location", "/config");
  server.send(302);
}

void WebServerCtrl::handleConfigStatus()
{
  String ssid, pass;
  bool has_config = loadWiFiConfig(ssid, pass);
  bool connected = (WiFi.status() == WL_CONNECTED);

  String json = "{";
  json += "\"has_config\":" + String(has_config ? "true" : "false") + ",";
  json += "\"ssid\":\"" + (has_config ? ssid : "") + "\",";
  json += "\"connected\":" + String(connected ? "true" : "false") + ",";
  if (connected) {
    json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI());
  } else {
    json += "\"ip\":\"\",\"rssi\":0";
  }
  json += "}";
  server.send(200, "application/json", json);
}

// ============== CONFIG HTML ==============

void WebServerCtrl::sendConfigHTML(bool saved, bool error, const String& msg)
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>WiFi 配置 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>WiFi 配置</h1>";

  // 当前状态卡片
  html += "<div class='card'>";
  html += "<h2>STA 连接状态</h2>";
  if (WiFi.status() == WL_CONNECTED) {
    html += "<p class='running'>已连接</p>";
    html += "<p>SSID: " + WiFi.SSID() + "</p>";
    html += "<p>IP: " + WiFi.localIP().toString() + "</p>";
    html += "<p>信号: " + String(WiFi.RSSI()) + " dBm</p>";
  } else {
    html += "<p class='stopped'>未连接</p>";
    String ssid, pass;
    if (loadWiFiConfig(ssid, pass)) {
      html += "<p>已保存配置: " + ssid + "</p>";
      html += "<p><a class='btn btn-green btn-sm' href='/config/connect'>重新连接</a></p>";
    } else {
      html += "<p>未保存 WiFi 配置</p>";
    }
  }
  html += "</div>";

  // 配置表单
  html += "<div class='card'>";
  html += "<h2>配置 WiFi</h2>";
  html += "<form method='POST' action='/config/save'>";
  html += "<p>SSID（WiFi 名称）:<br><input type='text' name='ssid' style='width:90%;padding:8px;border-radius:6px;border:none;background:#0f3460;color:#fff'></p>";
  html += "<p>密码:<br><input type='password' name='pass' style='width:90%;padding:8px;border-radius:6px;border:none;background:#0f3460;color:#fff'></p>";
  html += "<p><button type='submit' class='btn btn-green'>保存并连接</button></p>";
  html += "</form>";
  html += "<p><a class='btn btn-stop btn-sm' href='/config/clear'>清除配置</a></p>";
  html += "</div>";

  // 消息提示
  if (msg.length() > 0) {
    html += "<div class='card' style='border:2px solid " + String(error ? "#e94560" : "#2ecc71") + "'>";
    html += "<p>" + msg + "</p></div>";
  }

  // 服务器配置（抓包上传）
  String ssid2, pass2;
  loadWiFiConfig(ssid2, pass2);
  html += "<div class='card'>";
  html += "<h2>抓包服务器设置</h2>";
  html += "<p>ESP32 连接 WiFi 后，抓到的包会发送到云服务器。</p>";
  html += "<p>服务器: 38.244.14.175:9999</p>";
  html += "</div>";

  html += "<div class='nav'><a class='btn btn-blue' href='/'>返回主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void WebServerCtrl::handleClient()
{
  server.handleClient();
}

// ============== STATE GETTERS/SETTERS ==============

void WebServerCtrl::setAttackRunning(bool running) { attack_running_ = running; }
void WebServerCtrl::setAttackPacketCount(int count) { attack_packet_count_ = count; }
void WebServerCtrl::setSelectedTarget(int idx) { selected_target_ = idx; }
int WebServerCtrl::getSelectedTarget() { return selected_target_; }
bool WebServerCtrl::getAttackRunning() { return attack_running_; }
int WebServerCtrl::getAttackPacketCount() { return attack_packet_count_; }

void WebServerCtrl::setSnifferRunning(bool running) { sniffer_running_ = running; }
void WebServerCtrl::setSnifferChannel(uint8_t ch) { sniffer_channel_ = ch; }
bool WebServerCtrl::getSnifferRunning() { return sniffer_running_; }
uint8_t WebServerCtrl::getSnifferChannel() { return sniffer_channel_; }

void WebServerCtrl::setBeaconRunning(bool running) { beacon_running_ = running; }
void WebServerCtrl::setBeaconChannel(uint8_t ch) { beacon_channel_ = ch; }
bool WebServerCtrl::getBeaconRunning() { return beacon_running_; }
uint8_t WebServerCtrl::getBeaconChannel() { return beacon_channel_; }

void WebServerCtrl::setProbeRunning(bool running) { probe_running_ = running; }
void WebServerCtrl::setProbeChannel(uint8_t ch) { probe_channel_ = ch; }
bool WebServerCtrl::getProbeRunning() { return probe_running_; }
uint8_t WebServerCtrl::getProbeChannel() { return probe_channel_; }

void WebServerCtrl::setChannelHopping(bool hopping) { channel_hopping_ = hopping; }
bool WebServerCtrl::getChannelHopping() { return channel_hopping_; }

void WebServerCtrl::setStreamingRunning(bool running) { streaming_running_ = running; }
bool WebServerCtrl::getStreamingRunning() { return streaming_running_; }
void WebServerCtrl::setStreamingPackets(uint32_t count) { streaming_packets_ = count; }
uint32_t WebServerCtrl::getStreamingPackets() { return streaming_packets_; }

void WebServerCtrl::setSnifferFilterMac(const String& mac) {
  filter_mac_str_ = mac;
  w_utils_->setSnifferFilterFromStr(mac.c_str());
}
void WebServerCtrl::clearSnifferFilterMac() {
  filter_mac_str_ = "";
  w_utils_->clearSnifferFilter();
}
String WebServerCtrl::getSnifferFilterMacStr() { return filter_mac_str_; }

// ============== HTTP HANDLERS ==============

void WebServerCtrl::handleRoot() { sendDashboardHTML(); }
void WebServerCtrl::handleScan() { w_utils_->wifi_list = w_utils_->scanWifiList(); sendScanHTML(); }
void WebServerCtrl::handleSelect() { sendScanHTML(); }
void WebServerCtrl::handleAttack() { sendAttackHTML(); }
void WebServerCtrl::handleSniffer() { sendSnifferHTML(); }
void WebServerCtrl::handleBeacon() { sendBeaconHTML(); }
void WebServerCtrl::handleProbe() { sendProbeHTML(); }

void WebServerCtrl::handleStatus()
{
  snifferStats stats = w_utils_->getSnifferStats();
  probeData pdata = w_utils_->getProbeData();

  String json = "{";
  // Attack state
  json += "\"attack_running\":" + String(attack_running_ ? "true" : "false") + ",";
  json += "\"attack_packets\":" + String(attack_packet_count_) + ",";
  // Sniffer state
  json += "\"sniffer_running\":" + String(sniffer_running_ ? "true" : "false") + ",";
  json += "\"sniffer_channel\":" + String(sniffer_channel_) + ",";
  json += "\"sniffer_total\":" + String(stats.total_frames) + ",";
  json += "\"sniffer_mgmt\":" + String(stats.mgmt_frames) + ",";
  json += "\"sniffer_data\":" + String(stats.data_frames) + ",";
  json += "\"sniffer_ctrl\":" + String(stats.ctrl_frames) + ",";
  json += "\"sniffer_probe\":" + String(stats.probe_req_frames) + ",";
  // Beacon state
  json += "\"beacon_running\":" + String(beacon_running_ ? "true" : "false") + ",";
  json += "\"beacon_channel\":" + String(beacon_channel_) + ",";
  json += "\"beacon_count\":" + String(w_utils_->getBeaconFloodCount()) + ",";
  // Probe state
  json += "\"probe_running\":" + String(probe_running_ ? "true" : "false") + ",";
  json += "\"probe_channel\":" + String(probe_channel_) + ",";
  json += "\"probe_count\":" + String(pdata.num) + ",";
  // Channel
  json += "\"channel_hopping\":" + String(channel_hopping_ ? "true" : "false") + ",";
  json += "\"current_channel\":" + String(w_utils_->getCurrentChannel()) + ",";
  // Streaming
  json += "\"streaming_running\":" + String(streaming_running_ ? "true" : "false") + ",";
  json += "\"streaming_packets\":" + String(streaming_packets_) + ",";
  // Target
  json += "\"target_idx\":" + String(selected_target_) + ",";
  // Sniffer filter
  json += "\"sniffer_filter\":" + String(w_utils_->isSnifferFiltered() ? "true" : "false") + ",";
  if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    json += "\"sniffer_filter_mac\":\"" + String(mac_buf) + "\",";
  } else {
    json += "\"sniffer_filter_mac\":\"\",";
  }
  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    json += "\"target_ssid\":\"" + String(w_utils_->wifi_list.ssid[selected_target_].c_str()) + "\",";
    json += "\"target_bssid\":\"" + String(w_utils_->wifi_list.bssid[selected_target_].c_str()) + "\",";
    json += "\"target_channel\":" + String(w_utils_->wifi_list.channel[selected_target_]);
  } else {
    json += "\"target_ssid\":\"none\",\"target_bssid\":\"\",\"target_channel\":0";
  }
  json += "}";
  server.send(200, "application/json", json);
}

// ============== SNIFFER FILTER HANDLERS ==============

void WebServerCtrl::handleSnifferFilter()
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>抓包过滤 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>抓包设备过滤</h1>";

  html += "<div class='card'>";
  html += "<h2>当前过滤状态</h2>";
  if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    html += "<p class='running'>已启用过滤</p>";
    html += "<p>目标 MAC: <strong>" + String(mac_buf) + "</strong></p>";
    html += "<p><a class='btn btn-stop btn-sm' href='/sniffer/filter/clear'>清除过滤</a></p>";
  } else {
    html += "<p class='stopped'>未启用过滤（抓取所有设备）</p>";
  }
  html += "</div>";

  // 使用已选目标
  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    html += "<div class='card'>";
    html += "<h2>使用已选目标</h2>";
    html += "<p>目标: " + String(w_utils_->wifi_list.ssid[selected_target_].c_str()) + "</p>";
    html += "<p>BSSID: " + String(w_utils_->wifi_list.bssid[selected_target_].c_str()) + "</p>";
    html += "<p><a class='btn btn-green' href='/sniffer/filter/use_target'>使用此设备 MAC</a></p>";
    html += "</div>";
  }

  // 手动输入 MAC
  html += "<div class='card'>";
  html += "<h2>手动输入 MAC 地址</h2>";
  html += "<form method='GET' action='/sniffer/filter/set'>";
  html += "<p>格式: AA:BB:CC:DD:EE:FF</p>";
  html += "<p><input type='text' name='mac' placeholder='00:11:22:33:44:55' ";
  html += "style='width:90%;padding:8px;border-radius:6px;border:none;background:#0f3460;color:#fff'></p>";
  html += "<p><button type='submit' class='btn btn-blue'>设置过滤</button></p>";
  html += "</form>";
  html += "</div>";

  html += "<div class='nav'><a class='btn btn-blue' href='/sniffer'>返回抓包</a> ";
  html += "<a class='btn btn-blue' href='/'>主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void WebServerCtrl::handleSnifferFilterSet()
{
  if (server.hasArg("mac")) {
    String mac = server.arg("mac");
    mac.trim();
    mac.toUpperCase();
    setSnifferFilterMac(mac);
    Serial.printf("[WEB] Sniffer filter set to: %s\n", mac.c_str());
  }
  server.sendHeader("Location", "/sniffer/filter");
  server.send(302);
}

void WebServerCtrl::handleSnifferFilterClear()
{
  clearSnifferFilterMac();
  Serial.println("[WEB] Sniffer filter cleared");
  server.sendHeader("Location", "/sniffer/filter");
  server.send(302);
}

void WebServerCtrl::handleSnifferFilterUseTarget()
{
  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    String bssid = String(w_utils_->wifi_list.bssid[selected_target_].c_str());
    setSnifferFilterMac(bssid);
    Serial.printf("[WEB] Sniffer filter set to target: %s\n", bssid.c_str());
  }
  server.sendHeader("Location", "/sniffer/filter");
  server.send(302);
}

// ============== SHARED CSS ==============

String WebServerCtrl::getCSS()
{
  String css = "body{font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;";
  css += "margin:0;padding:20px;background:#1a1a2e;color:#eee}";
  css += "h1{color:#e94560;text-align:center;font-size:24px}";
  css += "h2{color:#e94560;font-size:18px}";
  css += ".card{background:#16213e;border-radius:10px;padding:15px;margin:10px 0}";
  css += "a{color:#e94560;text-decoration:none}";
  css += ".btn{display:inline-block;padding:12px 24px;border-radius:8px;text-align:center;margin:5px;color:#fff;font-size:16px}";
  css += ".btn:hover{opacity:0.85}";
  css += ".btn-red{background:#e94560}";
  css += ".btn-blue{background:#0f3460}";
  css += ".btn-green{background:#1a6b3c}";
  css += ".btn-purple{background:#533483}";
  css += ".btn-stop{background:#c0392b}";
  css += ".btn-sm{padding:8px 16px;font-size:14px}";
  css += ".grid{display:flex;flex-wrap:wrap;justify-content:center;gap:10px}";
  css += ".stat{text-align:center;font-size:20px;color:#e94560;padding:8px}";
  css += ".stat-val{font-size:28px;color:#2ecc71}";
  css += ".net{padding:10px;border-bottom:1px solid #0f3460;display:flex;justify-content:space-between;align-items:center}";
  css += ".sel{background:#533483;color:#fff;padding:6px 12px;border-radius:6px;font-size:14px}";
  css += ".sel:hover{background:#7b4db8}";
  css += ".tag{background:#0f3460;color:#eee;padding:4px 8px;border-radius:4px;font-size:12px}";
  css += ".running{color:#2ecc71;font-weight:bold}";
  css += ".stopped{color:#e94560;font-weight:bold}";
  css += "table{width:100%;border-collapse:collapse}";
  css += "td,th{padding:6px 10px;text-align:left;border-bottom:1px solid #0f3460}";
  css += "th{color:#e94560}";
  css += ".nav{display:flex;justify-content:center;gap:8px;margin:15px 0}";
  return css;
}

// ============== DASHBOARD ==============

void WebServerCtrl::sendDashboardHTML()
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>DeautherC3 控制面板</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>DeautherC3 控制面板</h1>";

  // WiFi STA 状态
  html += "<div class='card' style='border:2px solid " + String(WiFi.status() == WL_CONNECTED ? "#2ecc71" : "#e94560") + "'>";
  html += "<h2>WiFi 状态</h2>";
  if (WiFi.status() == WL_CONNECTED) {
    html += "<p class='running'>STA 已连接</p>";
    html += "<p>SSID: " + WiFi.SSID() + " | IP: " + WiFi.localIP().toString() + "</p>";
    html += "<p>信号: " + String(WiFi.RSSI()) + " dBm</p>";
  } else {
    String ssid, pass;
    if (loadWiFiConfig(ssid, pass)) {
      html += "<p class='stopped'>STA 未连接（已保存配置，正在重试...）</p>";
    } else {
      html += "<p class='stopped'>STA 未连接（未配置 WiFi）</p>";
    }
  }
  html += "<p><a class='btn btn-blue btn-sm' href='/config'>WiFi 配置</a></p>";
  html += "</div>";

  html += "<div class='card'>";
  html += "<p>ESP32-C3 WiFi 脱认证器<br>立创实战派 ESP32-C3 V1.4</p>";
  html += "<p>MAC 地址: " + String(w_utils_->macAddress().c_str()) + "</p>";
  html += "<p>当前信道: " + String(w_utils_->getCurrentChannel()) + "</p>";
  html += "</div>";

  // Status summary
  html += "<div class='card'>";
  html += "<h2>运行状态</h2>";
  html += "<table><tr><th>功能</th><th>状态</th></tr>";
  html += "<tr><td>脱认证攻击</td><td class='" + String(attack_running_ ? "running" : "stopped") + "'>";
  html += String(attack_running_ ? "运行中" : "闲置") + "</td></tr>";
  html += "<tr><td>抓包监听</td><td class='" + String(sniffer_running_ ? "running" : "stopped") + "'>";
  html += String(sniffer_running_ ? "运行中" : "闲置") + "</td></tr>";
  html += "<tr><td>信标洪泛</td><td class='" + String(beacon_running_ ? "running" : "stopped") + "'>";
  html += String(beacon_running_ ? "运行中" : "闲置") + "</td></tr>";
  html += "<tr><td>探测请求</td><td class='" + String(probe_running_ ? "running" : "stopped") + "'>";
  html += String(probe_running_ ? "运行中" : "闲置") + "</td></tr>";
  html += "<tr><td>推送到服务器</td><td class='" + String(streaming_running_ ? "running" : "stopped") + "'>";
  html += String(streaming_running_ ? "推送中(" + String(streaming_packets_) + "包)" : "闲置") + "</td></tr>";
  html += "<tr><td>抓包过滤</td><td class='" + String(w_utils_->isSnifferFiltered() ? "running" : "stopped") + "'>";
  if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    html += String(mac_buf) + "</td></tr>";
  } else {
    html += "全部设备</td></tr>";
  }
  html += "</table></div>";

  // Current target
  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    html += "<div class='card'><h2>当前目标</h2>";
    html += "<p><b>" + String(w_utils_->wifi_list.ssid[selected_target_].c_str()) + "</b><br>";
    html += "BSSID: " + String(w_utils_->wifi_list.bssid[selected_target_].c_str()) + "<br>";
    html += "信道: " + String(w_utils_->wifi_list.channel[selected_target_]) + "</p></div>";
  }

  // Navigation buttons
  html += "<div class='nav'>";
  html += "<a class='btn btn-blue' href='/scan'>扫描网络</a>";
  html += "<a class='btn btn-red' href='/attack'>攻击面板</a>";
  html += "<a class='btn btn-purple' href='/sniffer'>抓包监听</a>";
  html += "<a class='btn btn-green' href='/beacon'>信标洪泛</a>";
  html += "<a class='btn btn-blue' href='/probe'>探测请求</a>";
  html += "</div>";

  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ============== SCAN PAGE ==============

void WebServerCtrl::sendScanHTML()
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>扫描网络 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>扫描网络</h1>";
  html += "<div class='card'>";
  html += "<p>发现 " + String(w_utils_->wifi_list.num) + " 个网络</p>";
  html += "<a class='btn btn-blue btn-sm' href='/scan'>重新扫描</a></div>";

  if (w_utils_->wifi_list.num > 0) {
    html += "<div class='card'>";
    for (int i = 0; i < w_utils_->wifi_list.num; i++) {
      html += "<div class='net'>";
      html += "<div><b>" + String(w_utils_->wifi_list.ssid[i].c_str()) + "</b><br>";
      html += "<small>信道:" + String(w_utils_->wifi_list.channel[i]) + " ";
      html += "信号:" + String((int)w_utils_->wifi_list.signal[i]) + "dBm</small></div>";
      if (i == selected_target_) {
        html += "<span class='tag'>已选择</span>";
      } else {
        html += "<a class='sel' href='/select/set?id=" + String(i) + "'>选择</a>";
      }
      html += "</div>";
    }
    html += "</div>";
  }

  html += "<div class='nav'>";
  html += "<a class='btn btn-blue' href='/'>返回主页</a>";
  html += "<a class='btn btn-red' href='/attack'>攻击面板</a>";
  html += "</div></body></html>";
  server.send(200, "text/html", html);
}

// ============== ATTACK PAGE ==============

void WebServerCtrl::sendAttackHTML()
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>攻击面板 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    html += "<h1>攻击面板</h1>";
    html += "<div class='card'><h2>攻击目标</h2>";
    html += "<p><b>" + String(w_utils_->wifi_list.ssid[selected_target_].c_str()) + "</b><br>";
    html += "BSSID: " + String(w_utils_->wifi_list.bssid[selected_target_].c_str()) + "<br>";
    html += "信道: " + String(w_utils_->wifi_list.channel[selected_target_]) + "</p></div>";

    if (attack_running_) {
      html += "<div class='card stat'>脱认证攻击运行中!</div>";
      html += "<div class='card stat'>发送帧数: <span class='stat-val' id='pkts'>";
      html += String(attack_packet_count_) + "</span></div>";
      html += "<div class='nav'>";
      html += "<a class='btn btn-stop' href='/attack/stop'>停止攻击</a>";
      html += "</div>";
    } else {
      html += "<div class='card'>攻击闲置，准备启动。</div>";
      html += "<div class='nav'>";
      html += "<a class='btn btn-red' href='/attack/start'>启动脱认证</a>";
      html += "<a class='btn btn-green' href='/beacon'>信标洪泛</a>";
      html += "</div>";
    }

    // Auto-refresh when attack is running
    html += "<script>function refresh(){fetch('/status').then(r=>r.json()).then(d=>{";
    html += "if(d.attack_running){document.getElementById('pkts').textContent=d.attack_packets;";
    html += "setTimeout(refresh,1000);}})};";
    html += String(attack_running_ ? "refresh();" : "") + "</script>";
  } else {
    html += "<h1>未选择目标!</h1>";
    html += "<div class='card'><p>请先扫描并选择一个攻击目标。</p></div>";
    html += "<div class='nav'>";
    html += "<a class='btn btn-blue' href='/scan'>扫描 & 选择目标</a>";
    html += "</div>";
  }

  html += "<div class='nav'><a class='btn btn-blue' href='/'>返回主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ============== SNIFFER PAGE ==============

void WebServerCtrl::sendSnifferHTML()
{
  snifferStats stats = w_utils_->getSnifferStats();

  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>抓包监听 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>抓包监听</h1>";

  // Filter status card
  html += "<div class='card' style='border:1px solid #533483'>";
  if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    html += "<p>过滤: <span class='running'>仅抓取 " + String(mac_buf) + "</span></p>";
  } else {
    html += "<p>过滤: <span class='stopped'>全部设备</span></p>";
  }
  html += "<a class='btn btn-purple btn-sm' href='/sniffer/filter'>配置过滤</a>";
  html += "</div>";

  // ===== 推送到服务器卡片 =====
  html += "<div class='card' style='border:2px solid " + String(streaming_running_ ? "#2ecc71" : "#e94560") + "'>";
  html += "<h2>推送到服务器</h2>";
  html += "<p>服务器: 38.244.14.175:9999</p>";
  if (streaming_running_) {
    html += "<p class='running'>推送运行中</p>";
    html += "<p>已发送: <span class='stat-val'>" + String(streaming_packets_) + "</span> 包</p>";
    // Check WiFi status
    if (WiFi.status() == WL_CONNECTED) {
      html += "<p>WiFi: <span class='running'>已连接</span> (" + WiFi.localIP().toString() + ")</p>";
    } else {
      html += "<p>WiFi: <span class='stopped'>未连接！</span> 请先配置WiFi</p>";
    }
    html += "<a class='btn btn-stop' href='/stream/stop'>停止推送</a>";
  } else {
    if (WiFi.status() == WL_CONNECTED) {
      html += "<p>WiFi: <span class='running'>已连接</span> (" + WiFi.localIP().toString() + ")</p>";
      html += "<a class='btn btn-green' href='/stream/start'>推送到服务器</a>";
    } else {
      html += "<p>WiFi: <span class='stopped'>未连接</span></p>";
      html += "<a class='btn btn-blue btn-sm' href='/config'>配置WiFi</a> ";
      html += "<a class='btn btn-green' href='/stream/start'>强制推送(重试)</a>";
    }
  }
  html += "</div>";

  if (sniffer_running_) {
    html += "<div class='card stat running'>监听运行中</div>";
    html += "<div class='card'>";
    html += "<h2>帧统计</h2>";
    html += "<table><tr><th>类型</th><th>数量</th></tr>";
    html += "<tr><td>管理帧</td><td class='stat-val'>" + String(stats.mgmt_frames) + "</td></tr>";
    html += "<tr><td>数据帧</td><td class='stat-val'>" + String(stats.data_frames) + "</td></tr>";
    html += "<tr><td>控制帧</td><td class='stat-val'>" + String(stats.ctrl_frames) + "</td></tr>";
    html += "<tr><td>探测请求</td><td class='stat-val'>" + String(stats.probe_req_frames) + "</td></tr>";
    html += "<tr><td>总帧数</td><td class='stat-val'>" + String(stats.total_frames) + "</td></tr>";
    html += "</table>";
    html += "<p>当前信道: " + String(w_utils_->getCurrentChannel()) + " ";
    html += String(channel_hopping_ ? "(信道跳跃)" : "") + "</p>";
    if (stats.total_frames > 0) {
      html += "<p>最近源MAC: " + String(stats.last_src_mac.c_str()) + "</p>";
    }
    html += "</div>";

    html += "<div class='nav'>";
    html += "<a class='btn btn-stop' href='/sniffer/stop'>停止监听</a>";
    html += "</div>";

    // Auto-refresh
    html += "<script>setTimeout(function(){window.location.reload()},3000);</script>";
  } else if (!streaming_running_) {
    html += "<div class='card'>监听闲置。选择信道开始抓包。</div>";
    html += "<div class='card'>";
    html += "<h2>选择信道</h2>";
    html += "<div class='grid'>";
    for (int ch = 1; ch <= 13; ch++) {
      html += "<a class='btn btn-purple btn-sm' href='/sniffer/start?ch=" + String(ch) + "'>Ch" + String(ch) + "</a>";
    }
    html += "</div></div>";
    html += "<div class='nav'>";
    html += "<a class='btn btn-blue' href='/sniffer/hop'>全信道跳跃</a>";
    html += "</div>";
  } else {
    // streaming only (no local sniffer) - keep auto-refresh alive
    html += "<script>setTimeout(function(){window.location.reload()},3000);</script>";
    html += "<div class='card'><p>本地抓包未启动，仅推送到服务器。</p></div>";
  }

  html += "<div class='nav'><a class='btn btn-blue' href='/'>返回主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ============== BEACON PAGE ==============

void WebServerCtrl::sendBeaconHTML()
{
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>信标洪泛 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>信标洪泛</h1>";

  if (selected_target_ >= 0 && selected_target_ < w_utils_->wifi_list.num) {
    html += "<div class='card'><h2>攻击目标</h2>";
    html += "<p><b>" + String(w_utils_->wifi_list.ssid[selected_target_].c_str()) + "</b><br>";
    html += "信道: " + String(w_utils_->wifi_list.channel[selected_target_]) + "</p></div>";
  }

  if (beacon_running_) {
    html += "<div class='card stat running'>信标洪泛运行中!</div>";
    html += "<div class='card stat'>发送帧数: <span class='stat-val' id='bcount'>";
    html += String(w_utils_->getBeaconFloodCount()) + "</span></div>";

    html += "<div class='nav'>";
    html += "<a class='btn btn-stop' href='/beacon/stop'>停止洪泛</a>";
    html += "</div>";

    // Auto-refresh
    html += "<script>function refresh(){fetch('/status').then(r=>r.json()).then(d=>{";
    html += "document.getElementById('bcount').textContent=d.beacon_count;";
    html += "setTimeout(refresh,1000);})}refresh();</script>";
  } else {
    html += "<div class='card'>信标洪泛闲置。选择目标后启动。</div>";

    if (selected_target_ >= 0) {
      uint8_t ch = w_utils_->wifi_list.channel[selected_target_];
      html += "<div class='nav'>";
      html += "<a class='btn btn-red' href='/beacon/start?ch=" + String(ch) + "'>启动信标洪泛</a>";
      html += "</div>";
    }
  }

  html += "<div class='nav'><a class='btn btn-blue' href='/'>返回主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ============== PROBE PAGE ==============

void WebServerCtrl::sendProbeHTML()
{
  probeData pdata = w_utils_->getProbeData();

  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<title>探测请求 - DeautherC3</title>";
  html += "<style>" + getCSS() + "</style></head><body>";

  html += "<h1>探测请求监听</h1>";

  if (probe_running_) {
    html += "<div class='card stat running'>探测监听运行中</div>";
    html += "<div class='card'>";
    html += "<p>当前信道: " + String(w_utils_->getCurrentChannel()) + " ";
    html += String(channel_hopping_ ? "(信道跳跃)" : "") + "</p>";
    html += "<p>发现客户端: " + String(pdata.num) + "</p>";
    html += "</div>";

    if (pdata.num > 0) {
      html += "<div class='card'><h2>探测请求列表</h2>";
      html += "<table><tr><th>客户端MAC</th><th>SSID</th><th>信道</th><th>次数</th></tr>";
      for (int i = 0; i < pdata.num; i++) {
        html += "<tr>";
        html += "<td>" + String(pdata.client_mac[i].c_str()) + "</td>";
        html += "<td>" + String(pdata.ssid[i].length() > 0 ? pdata.ssid[i].c_str() : "(广播)") + "</td>";
        html += "<td>" + String(pdata.channel[i]) + "</td>";
        html += "<td>" + String(pdata.count[i]) + "</td>";
        html += "</tr>";
      }
      html += "</table></div>";
    }

    html += "<div class='nav'>";
    html += "<a class='btn btn-stop' href='/probe/stop'>停止监听</a>";
    html += "</div>";

    // Auto-refresh
    html += "<script>setTimeout(function(){window.location.reload()},3000);</script>";
  } else {
    html += "<div class='card'>探测监听闲置。选择信道开始监听。</div>";
    html += "<div class='card'>";
    html += "<h2>选择信道</h2>";
    html += "<div class='grid'>";
    for (int ch = 1; ch <= 13; ch++) {
      html += "<a class='btn btn-purple btn-sm' href='/probe/start?ch=" + String(ch) + "'>Ch" + String(ch) + "</a>";
    }
    html += "</div></div>";
    html += "<div class='nav'>";
    html += "<a class='btn btn-blue' href='/probe/hop'>全信道跳跃</a>";
    html += "</div>";
  }

  html += "<div class='nav'><a class='btn btn-blue' href='/'>返回主页</a></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ============== STREAM HANDLERS ==============

void WebServerCtrl::handleStreamStart()
{
  setStreamingRunning(true);
  streaming_packets_ = 0;
  Serial.println("[WEB] Streaming to server started via web");
  server.sendHeader("Location", "/sniffer");
  server.send(302);
}

void WebServerCtrl::handleStreamStop()
{
  setStreamingRunning(false);
  Serial.println("[WEB] Streaming to server stopped via web");
  server.sendHeader("Location", "/sniffer");
  server.send(302);
}
