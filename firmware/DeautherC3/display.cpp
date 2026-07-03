// display.cpp - Adafruit_ST7789 version (English only)
#include "display.h"

// Pin definitions for LCKFB ESP32-C3 V1.4
#define TFT_CS   4
#define TFT_DC   6
#define TFT_RST  -1
#define BACKLIGHT_PIN 2

Display::Display(int16_t width, int16_t height, int8_t reset_pin, uint8_t address, int16_t SDA_pin, int16_t SCL_pin)
  : tft(TFT_CS, TFT_DC, TFT_RST), DISPLAY_WIDTH(width), DISPLAY_HEIGHT(height)
{
}

bool Display::startDisplay()
{
  Serial.println("[DISPLAY] Initializing ST7789 TFT (Adafruit)...");

  pinMode(BACKLIGHT_PIN, OUTPUT);
  digitalWrite(BACKLIGHT_PIN, LOW);
  Serial.println("[DISPLAY] Backlight ON (GPIO2=LOW)");

  SPI.begin(3, -1, 5);  // SCLK=3, MISO=-1, MOSI=5

  tft.init(DISPLAY_WIDTH, DISPLAY_HEIGHT);
  tft.setRotation(1);   // Landscape mode: 320x240

  Serial.printf("[DISPLAY] ST7789 initialized! Size: %dx%d\n", tft.width(), tft.height());

  tft.fillScreen(ST77XX_BLACK);
  drawText("DeautherC3", 60, 4, 2, ST77XX_WHITE);
  drawText("LCKFB ESP32-C3", 70, 40, 2, ST77XX_RED);
  delay(1500);

  tft.fillScreen(ST77XX_BLACK);
  return true;
}

void Display::setWhite() { tft.fillScreen(ST77XX_WHITE); }
void Display::clear() { tft.fillScreen(ST77XX_BLACK); }

void Display::clearRect(int16_t x, int16_t y, int16_t w, int16_t h)
{
  tft.fillRect(x, y, w, h, ST77XX_BLACK);
}

void Display::setDisplayText(std::string text, int16_t x, int16_t y, float size)
{
  if (text.length() > 32) text = text.substr(0, 32);
  tft.fillScreen(ST77XX_BLACK);
  tft.setTextColor(ST77XX_WHITE, ST77XX_BLACK);
  int font_size = (int)size;
  if (font_size < 1) font_size = 1;
  else if (font_size > 4) font_size = 4;
  tft.setTextSize(font_size);
  tft.setCursor(x * 10, y * 16);
  tft.print(text.c_str());
}

void Display::setDisplayText(const char* text, int16_t x, int16_t y, float size)
{ setDisplayText(std::string(text), x, y, size); }

void Display::setDisplayText(int text, int16_t x, int16_t y, float size)
{ setDisplayText(std::to_string(text), x, y, size); }

void Display::setDisplayTextF(float text, int16_t x, int16_t y, float size)
{ setDisplayText(std::to_string(text), x, y, size); }

void Display::appendDisplayText(std::string text, int16_t x, int16_t y, float size)
{
  if (text.length() > 32) text = text.substr(0, 32);
  tft.setTextColor(ST77XX_WHITE, ST77XX_BLACK);
  int font_size = (int)size;
  if (font_size < 1) font_size = 1;
  else if (font_size > 4) font_size = 4;
  tft.setTextSize(font_size);
  tft.setCursor(x * 10, y * 16);
  tft.print(text.c_str());
}

void Display::appendDisplayText(const char* text, int16_t x, int16_t y, float size)
{ appendDisplayText(std::string(text), x, y, size); }

void Display::appendDisplayText(int text, int16_t x, int16_t y, float size)
{ appendDisplayText(std::to_string(text), x, y, size); }

void Display::appendDisplayTextF(float text, int16_t x, int16_t y, float size)
{ appendDisplayText(std::to_string(text), x, y, size); }

// Text methods (absolute pixel positions, ASCII/English)
void Display::drawText(const char* text, int16_t x, int16_t y, uint8_t font_size, uint16_t color)
{
  tft.setTextSize(font_size);
  tft.setTextColor(color, ST77XX_BLACK);
  tft.setCursor(x, y);
  tft.print(text);
}

void Display::drawTextClear(const char* title, int16_t x, int16_t y, uint8_t font_size, uint16_t color)
{
  clear();
  drawText(title, x, y, font_size, color);
}

Adafruit_ST7789& Display::getTft() { return tft; }
