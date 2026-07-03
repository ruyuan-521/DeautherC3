// display.h - Adafruit_ST7789 version (English only, no Chinese font)
#ifndef DISPLAY_H
#define DISPLAY_H

#include <string>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <SPI.h>

class Display {
public:
  Display(int16_t width, int16_t height, int8_t reset_pin, uint8_t address, int16_t SDA_pin, int16_t SCL_pin);
  bool startDisplay();
  void setWhite();
  void clear();
  void clearRect(int16_t x, int16_t y, int16_t w, int16_t h);

  // ASCII text display methods (grid-based: x*10, y*16)
  void setDisplayText(std::string text, int16_t x, int16_t y, float size);
  void setDisplayText(const char* text, int16_t x, int16_t y, float size);
  void setDisplayText(int text, int16_t x, int16_t y, float size);
  void setDisplayTextF(float text, int16_t x, int16_t y, float size);

  void appendDisplayText(std::string text, int16_t x, int16_t y, float size);
  void appendDisplayText(const char* text, int16_t x, int16_t y, float size);
  void appendDisplayText(int text, int16_t x, int16_t y, float size);
  void appendDisplayTextF(float text, int16_t x, int16_t y, float size);

  // Text display methods (absolute pixel positions, English/ASCII)
  void drawText(const char* text, int16_t x, int16_t y, uint8_t font_size, uint16_t color);
  void drawTextClear(const char* title, int16_t x, int16_t y, uint8_t font_size, uint16_t color);

  // Direct TFT access for advanced rendering
  Adafruit_ST7789& getTft();

private:
  Adafruit_ST7789 tft;
  int16_t DISPLAY_WIDTH;
  int16_t DISPLAY_HEIGHT;
};

#endif
