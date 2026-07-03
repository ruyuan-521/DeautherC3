// ============================================================
//  ESP32-C3 WiFi Deauther - Arduino IDE Sketch
//  Board: LCKFB ESP32-C3 V1.4
//  Display: ST7789 240x320 Color TFT (SPI)
//  Library: Adafruit_ST7789 + Adafruit_GFX
//  Features: Deauth, Beacon Flood, Packet Sniffer, Probe Sniffer
//  UI: English on TFT, Chinese on Web interface
// ============================================================

#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include "mainwindow.h"

Mainwindow window;

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\n=== ESP32-C3 Deauther Starting ===");
  window.init();
}

void loop() {
  window.loop();
}
