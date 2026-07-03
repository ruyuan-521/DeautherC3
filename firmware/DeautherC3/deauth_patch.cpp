// deauth_patch.cpp - Bypass ESP32-C3 wifi driver frame type check
// The ESP32-C3 wifi firmware has a function ieee80211_raw_frame_sanity_check()
// that rejects deauth (0xC0) and disassoc (0xA0) frames at runtime,
// printing "unsupported frame type" errors.
// This override replaces that function with a no-op that always returns 0 (pass),
// allowing esp_wifi_80211_tx() to actually transmit deauth/disassoc frames.
//
// Requires -Wl,-z,muldefs in ld_flags to allow duplicate symbol definition.
// See: https://github.com/tesa-klebeband/ESP32-Deauther-ArduinoIDE

#include <stdint.h>

// Override the firmware's frame sanity check — always return 0 (success)
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
  return 0;
}
