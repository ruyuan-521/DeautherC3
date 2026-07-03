// chinese_text.cpp - Chinese character rendering for DeautherC3
// Uses 16x16 bitmap font data from chinese_chars.h
// Supports mixed Chinese/ASCII text rendering on Adafruit_ST7789

#include "chinese_chars.h"
#include <Adafruit_GFX.h>

// Find bitmap for a UTF-8 Chinese character
// Chinese chars in UTF-8 are 3 bytes: 0xE0-0xEF + 2 continuation bytes
const uint8_t* findChineseBitmap(const char* utf8_char)
{
  if (utf8_char == NULL) return NULL;

  // Extract up to 3 bytes for matching
  uint8_t b0 = (uint8_t)utf8_char[0];
  uint8_t b1 = (uint8_t)utf8_char[1];
  uint8_t b2 = (uint8_t)utf8_char[2];

  // Only search for 3-byte UTF-8 sequences (Chinese characters)
  if (b0 < 0xE0 || b0 > 0xEF) return NULL;

  // Linear search through the font table
  for (int i = 0; i < CHINESE_FONT_COUNT; i++)
  {
    // Read entry from PROGMEM
    ChineseCharEntry entry;
    memcpy_P(&entry, &chinese_font[i], sizeof(ChineseCharEntry));

    if (entry.utf8[0] == b0 && entry.utf8[1] == b1 && entry.utf8[2] == b2)
    {
      return entry.bitmap;
    }
  }
  return NULL;  // Character not found in font
}

// Draw a string of mixed Chinese/ASCII text
// Chinese chars: 16x16 bitmap, scaled by font_size
// ASCII chars: default GFX font at given size
// font_size: 1 = 16x16 Chinese / 6x8 ASCII, 2 = 32x32 / 12x16, etc.
void drawChineseText(Adafruit_GFX& tft, int16_t x, int16_t y,
                     const char* text, uint8_t font_size, uint16_t color)
{
  if (text == NULL) return;

  int16_t cur_x = x;
  int16_t cur_y = y;

  // ASCII character dimensions at each font size
  // Default GFX font: 6x8 pixels at size 1
  int16_t ascii_w = 6 * font_size;
  int16_t ascii_h = 8 * font_size;
  int16_t chinese_w = CH_CHAR_W * font_size;
  int16_t chinese_h = CH_CHAR_H * font_size;

  // Calculate line height (use the taller of Chinese or ASCII)
  int16_t line_h = (chinese_h > ascii_h) ? chinese_h : ascii_h;
  // Add small gap between lines
  line_h += 2;

  tft.setTextSize(font_size);
  tft.setTextColor(color);

  int i = 0;
  while (text[i] != '\0')
  {
    uint8_t b = (uint8_t)text[i];

    // Check for 3-byte UTF-8 (Chinese character: 0xE0-0xEF range)
    if (b >= 0xE0 && b <= 0xEF)
    {
      // Try to find this Chinese character in our font
      const char* utf8_start = &text[i];
      const uint8_t* bitmap = findChineseBitmap(utf8_start);

      if (bitmap != NULL)
      {
        // Draw Chinese character using drawBitmap with scaling
        if (font_size == 1)
        {
          tft.drawBitmap(cur_x, cur_y, bitmap, CH_CHAR_W, CH_CHAR_H, color);
        }
        else
        {
          // For scaled Chinese, draw pixel-by-pixel scaling
          // Read source bitmap and scale up
          for (int sy = 0; sy < CH_CHAR_H; sy++)
          {
            // Read 2 bytes for this row from PROGMEM
            uint8_t row_byte0 = pgm_read_byte(&bitmap[sy * 2]);
            uint8_t row_byte1 = pgm_read_byte(&bitmap[sy * 2 + 1]);

            for (int sx = 0; sx < CH_CHAR_W; sx++)
            {
              uint8_t byte_idx = sx / 8;
              uint8_t bit_idx = sx % 8;
              uint8_t row_byte = (byte_idx == 0) ? row_byte0 : row_byte1;
              bool pixel_on = (row_byte & (0x80 >> bit_idx)) != 0;

              if (pixel_on)
              {
                // Draw scaled pixel block
                tft.fillRect(cur_x + sx * font_size, cur_y + sy * font_size,
                             font_size, font_size, color);
              }
            }
          }
        }
        cur_x += chinese_w;
        i += 3;  // Skip 3 UTF-8 bytes
      }
      else
      {
        // Character not in font - draw a placeholder box
        tft.drawRect(cur_x, cur_y, chinese_w, chinese_h, color);
        cur_x += chinese_w;
        i += 3;
      }
    }
    // Check for newline
    else if (b == '\n')
    {
      cur_x = x;
      cur_y += line_h;
      i++;
    }
    // ASCII character (0x00-0x7F or 2-byte UTF-8 which we treat as ASCII fallback)
    else
    {
      tft.setCursor(cur_x, cur_y + (chinese_h - ascii_h) / 2);  // Vertically center ASCII
      tft.print((char)b);
      cur_x += ascii_w;
      i++;
    }
  }
}
