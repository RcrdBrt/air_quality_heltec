#pragma once

#include <Arduino.h>

class PeriodicTimer
{
private:
    esp_timer_handle_t _timer;
    long _duration_usec;
    void (*_callback)(void *);

    PeriodicTimer(const PeriodicTimer &) = delete;
    PeriodicTimer &operator=(const PeriodicTimer &) = delete;
    PeriodicTimer(PeriodicTimer &&) = delete;

    PeriodicTimer() = default;

public:
    PeriodicTimer(String name, const uint32_t duration_usec, void (*timer_callback)(void *));

    void restart();
};
