// buttons.cpp - Single button with state machine for click/double-click/hold
// BOOT button (GPIO9): press=LOW, release=HIGH
// Single click = navigate, Double click = select, Long hold = back

#include "buttons.h"

Buttons::Buttons(int button_pin)
{
  buttonPin = button_pin;
  state = STATE_IDLE;
  pressStartTime = 0;
  firstReleaseTime = 0;
}

void Buttons::init()
{
  pinMode(buttonPin, INPUT_PULLUP);
}

int Buttons::readButtons()
{
  bool pressed = (digitalRead(buttonPin) == LOW);
  unsigned long now = millis();

  switch (state)
  {
    case STATE_IDLE:
      if (pressed)
      {
        // First press detected, start tracking
        pressStartTime = now;
        state = STATE_FIRST_PRESSED;
      }
      return BTN_NONE;

    case STATE_FIRST_PRESSED:
      if (!pressed)
      {
        // Released - was it a hold?
        unsigned long duration = now - pressStartTime;
        if (duration >= HOLD_BACK_MS)
        {
          // Was already a long hold (should have been caught below), but safety fallback
          state = STATE_IDLE;
          return BTN_BACK;
        }
        if (duration < MIN_PRESS_MS)
        {
          // Too short, probably noise - ignore and go idle
          state = STATE_IDLE;
          return BTN_NONE;
        }
        // Valid short click - enter double-click wait window
        firstReleaseTime = now;
        state = STATE_FIRST_RELEASED;
      }
      else
      {
        // Still holding - check if hold threshold reached for BACK
        if (now - pressStartTime >= HOLD_BACK_MS)
        {
          state = STATE_IDLE;
          return BTN_BACK;
        }
      }
      return BTN_NONE;

    case STATE_FIRST_RELEASED:
      if (pressed)
      {
        // Second press within window = double click in progress
        pressStartTime = now;
        state = STATE_SECOND_PRESSED;
      }
      else if (now - firstReleaseTime > DOUBLE_CLICK_MS)
      {
        // Window expired without second press = single click = NAV
        state = STATE_IDLE;
        return BTN_NAV;
      }
      return BTN_NONE;

    case STATE_SECOND_PRESSED:
      if (!pressed)
      {
        // Double click completed - second press released
        unsigned long duration = now - pressStartTime;
        if (duration >= MIN_PRESS_MS)
        {
          state = STATE_IDLE;
          return BTN_SEL;  // Double click = select/confirm
        }
        // Second press too short - treat as noise, still count as single click
        state = STATE_IDLE;
        return BTN_NAV;
      }
      // Still holding second press - could become a hold for BACK
      if (now - pressStartTime >= HOLD_BACK_MS)
      {
        state = STATE_IDLE;
        return BTN_BACK;
      }
      return BTN_NONE;
  }

  return BTN_NONE;
}
