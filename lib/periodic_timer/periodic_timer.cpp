#include "periodic_timer.h"

PeriodicTimer::PeriodicTimer(String name, const uint32_t duration_usec, void (*timer_callback)(void *))
{
    _duration_usec = duration_usec;
    _callback = timer_callback;
    ESP_ERROR_CHECK(esp_timer_create(
        &(esp_timer_create_args_t){
            .callback = _callback,
            .arg = NULL,
            .dispatch_method = ESP_TIMER_TASK,
            .name = name.c_str(),
        },
        &_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(_timer, _duration_usec));
}

void PeriodicTimer::restart()
{
    ESP_ERROR_CHECK(esp_timer_stop(_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(_timer, _duration_usec));
}