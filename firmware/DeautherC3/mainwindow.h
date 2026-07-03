// mainwindow.h - Full Chinese UI with 8 pages for DeautherC3
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// Screen: ST7789 240x320 in landscape mode = 320x240 pixels
#define SCREEN_WIDTH 240
#define SCREEN_HEIGHT 320
#define TFT_RST -1
#define SET_RANDOM_MAC 1
#define BOOT_BUTTON_PIN  9

// Pages
#define PAGE_MAIN    0
#define PAGE_SELECT  1
#define PAGE_SCAN    2
#define PAGE_ATTACK  3
#define PAGE_SNIFFER 4
#define PAGE_BEACON  5
#define PAGE_PROBE   6
#define PAGE_INFO    7
#define PAGE_COUNT   8

// Attack sub-states
#define ATK_IDLE       0
#define ATK_DEAUTH     1
#define ATK_BEACON     2
#define ATK_PROBE      3

// Main menu item count
#define MAIN_MENU_COUNT 5

// Attack menu item count
#define ATK_MENU_COUNT  5

#include "buttons.h"
#include "display.h"
#include "wifi_utils.h"
#include "web_server.h"
#include "packet_streamer.h"
#include <string>

class Mainwindow
{
public:
  Mainwindow();
  ~Mainwindow();

  void init();
  void loop();

private:
  Display* display_;
  WiFi_Utils* w_utils_;
  Buttons* buttons_;
  WebServerCtrl* web_server_;

  int cursor_index = 0;
  int page = PAGE_MAIN;
  bool on_page = false;
  bool on_wifi_scan_info = false;

  // Target selection
  int selected_target = -1;

  // Attack state
  int attack_state = ATK_IDLE;
  int attack_packet_count = 0;
  bool attack_running = false;

  // Sniffer state
  bool sniffer_active = false;
  bool probe_active = false;
  bool channel_hopping = false;

  // Beacon flood state
  bool beacon_active = false;

  // Packet streamer (to remote server)
  PacketStreamer* streamer_;
  bool streaming_active = false;
  bool deauth_while_streaming = false;  // deauth running alongside streaming

  void handleBack();
  void stopAllActivities();  // Stop all attacks/sniffers before switching
  void stopDeauthOnly();     // Stop deauth but keep streaming active
  void syncWebState();       // Sync state between web and local

  // Main page (主菜单)
  void handleMainPage(int action);
  void setMainPage();
  void handleMainPageNav();
  void handleMainPageSel();

  // Select target page (选择目标)
  void handleSelectPage(int action);
  void setSelectPage();
  void handleSelectPageNav();
  void handleSelectPageSel();

  // Scan page (扫描网络)
  void handleScanPage(int action);
  void setScanPage();
  void handleScanPageNav();
  void handleScanPageSel();

  // Attack page (攻击菜单)
  void handleAttackPage(int action);
  void setAttackPage();
  void handleAttackPageNav();
  void handleAttackPageSel();
  void runDeauthAttack();
  void runBeaconFlood();

  // Sniffer page (抓包监听)
  void handleSnifferPage(int action);
  void setSnifferPage();
  void handleSnifferPageNav();
  void handleSnifferPageSel();
  void updateSnifferDisplay();

  // Beacon flood page (信标洪泛)
  void handleBeaconPage(int action);
  void setBeaconPage();
  void handleBeaconPageNav();
  void handleBeaconPageSel();
  void updateBeaconDisplay();

  // Probe request page (探测请求)
  void handleProbePage(int action);
  void setProbePage();
  void handleProbePageNav();
  void handleProbePageSel();
  void updateProbeDisplay();

  // Info page (设备信息)
  void handleInfoPage(int action);
  void setInfoPage();

  // Streamer page (流式传输到服务器)
  void handleStreamerPage(int action);
  void setStreamerPage();
  void updateStreamerDisplay();
  void updateStreamerDeauthDisplay();  // combined stream+deauth display
  void startStreaming();
  void stopStreaming();

  void parseBSSID(const std::string& bssid_str, uint8_t* out);
};

#endif
