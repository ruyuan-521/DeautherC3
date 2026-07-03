// buttons.h - Single button (BOOT on GPIO9) with click/double-click/hold actions
#ifndef BUTTONS_H
#define BUTTONS_H

#include <Arduino.h>

// Button action results
#define BTN_NONE    -1  // No action this cycle
#define BTN_NAV     0   // Single click: navigate (cycle down)
#define BTN_SEL     1   // Double click: select/confirm
#define BTN_BACK    2   // Long hold (>1.5s): back/exit

// Timing thresholds (milliseconds)
#define DOUBLE_CLICK_MS  350   // Max gap between two clicks for double-click
#define HOLD_BACK_MS     1500  // Hold duration for back action
#define MIN_PRESS_MS     50    // Minimum press duration to count as a click

// Internal state machine
enum ButtonState {
  STATE_IDLE,             // Waiting for any press
  STATE_FIRST_PRESSED,    // First press held, tracking duration
  STATE_FIRST_RELEASED,   // First click released, waiting for double-click window
  STATE_SECOND_PRESSED    // Second press held (double-click in progress)
};

class Buttons
{
public:
  Buttons(int button_pin);
  void init();
  int readButtons();  // Returns BTN_NONE, BTN_NAV, BTN_SEL, or BTN_BACK

private:
  int buttonPin;
  ButtonState state;
  unsigned long pressStartTime;
  unsigned long firstReleaseTime;
};

#endif
