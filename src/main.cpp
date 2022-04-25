#include <Arduino.h>
#include <WiFi.h>
//#include <HTTPClient.h>
#include <SoftwareSerial.h>
#include <PMS.h>
#include <RadioLib.h>
#include <AES.h>
#include <GCM.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_GFX.h>
#include <pb_decode.h>
#include <proto_payload.pb.h>
#include <esp_timer.h>

#include "secrets.h"

#define BLUE_BTN 36
#define BUZZER 32
#define BASEMENT_TIMER_DURATION_USECS 3600 * 1e6 // 1 hour
#define PMS_TIMER_DURATION_USECS 1800 * 1e6      // 30 minutes

SoftwareSerial pms_serial;
PMS pms(pms_serial);
PMS::DATA pms_data;
esp_timer_handle_t pms_timer;
bool pms_timer_tick = false;

xTimerHandle grace_period_timer;
esp_timer_handle_t basement_timer;
bool basement_timer_tick = false, basement_in_grace_period = false;

GCM<AES256> cipher;
SX1276 radio = new Module(18, 26, 14, 35);
bool lora_interrupt_enabled = false, lora_recv_packet = false;

Adafruit_SSD1306 display(128, 64);

bool blue_btn_pressed = false;

bool got_an_alarm = false;

ICACHE_RAM_ATTR void pms_timer_callback(void *arg)
{
  pms_timer_tick = true;
}

ICACHE_RAM_ATTR void blue_btn_callback()
{
  blue_btn_pressed = true;
}

ICACHE_RAM_ATTR void lora_recv_callback()
{
  if (lora_interrupt_enabled)
  {
    lora_recv_packet = true;
  }
}

ICACHE_RAM_ATTR void basement_timer_callback(void *arg)
{
  basement_timer_tick = true;
}

ICACHE_RAM_ATTR void grace_period_timer_callback(void *arg)
{
  basement_in_grace_period = false;
}

void setup()
{
  pinMode(LED_BUILTIN, OUTPUT);    // Initialize the built-in LED
  digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
  pinMode(BUZZER, OUTPUT);
  digitalWrite(BUZZER, LOW); // Turn the BUZZER off
  pinMode(BLUE_BTN, INPUT_PULLDOWN);
  attachInterrupt(BLUE_BTN, blue_btn_callback, FALLING);

  Serial.begin(9600); // Initialize serial communications via USB

  ESP_ERROR_CHECK(display.begin(SSD1306_SWITCHCAPVCC, 0x3C) != true);
  display.dim(false);
  display.println("Air Quality Heltec");

  WiFi.mode(WIFI_STA);                  // Set the WiFi module to station mode
  WiFi.begin("NET", WIFI_PASSWORD);     // Connect to the WiFi network
  while (WiFi.status() != WL_CONNECTED) // Wait for the Wi-Fi to connect
  {
    delay(500);
    Serial.print(".");
  }
  Serial.print("IP: ");
  Serial.println(WiFi.localIP()); // Print the IP address of the ESP32

  pms.sleep(); // make sure the PMS sensor is in sleep mode

  cipher.clear();
  ESP_ERROR_CHECK(cipher.setKey(AES_KEY, 32) != true);

  ESP_ERROR_CHECK(radio.begin(868.0, 125, 12, 5, 18U, 17, 8U, 0) != 0);
  radio.setDio0Action(lora_recv_callback);
  radio.startReceive();

  esp_timer_create_args_t pms_timer_args = {
      .callback = pms_timer_callback,
      .arg = NULL,
      .dispatch_method = ESP_TIMER_TASK,
      .name = "pms_timer"};
  ESP_ERROR_CHECK(esp_timer_create(&pms_timer_args,
                                   &pms_timer));
  ESP_ERROR_CHECK(esp_timer_start_periodic(pms_timer, PMS_TIMER_DURATION_USECS));

  esp_timer_create_args_t basement_timer_args = {
      .callback = basement_timer_callback,
      .arg = NULL,
      .dispatch_method = ESP_TIMER_TASK,
      .name = "basement_timer"};
  ESP_ERROR_CHECK(esp_timer_create(&basement_timer_args,
                                   &basement_timer));
  ESP_ERROR_CHECK(esp_timer_start_periodic(basement_timer, BASEMENT_TIMER_DURATION_USECS));

  // trying a FreeRTOS software timer for the sake of it
  grace_period_timer = xTimerCreate("grace_period_timer",
                                    portTICK_PERIOD_MS * 1000 * 60 * 20, // 20 minutes
                                    pdFALSE,
                                    NULL,
                                    grace_period_timer_callback);

  display.clearDisplay();
  digitalWrite(LED_BUILTIN, LOW); // Turn the LED off
}

void loopProd()
{
  // air quality measurement
  if (pms_timer_tick)
  {
    pms_timer_tick = false;
    Serial.println("time to use the PMS sensor " + String(millis()));
  }

  if (blue_btn_pressed)
  {
    blue_btn_pressed = false;
    Serial.println("blue button pressed");

    if (got_an_alarm)
    {
      got_an_alarm = false;
    }
    else
    {
      basement_in_grace_period = true;
      ESP_ERROR_CHECK(xTimerReset(grace_period_timer, portTICK_PERIOD_MS * 10)); // wait 10 milliseconds to ensure the timer has started
      digitalWrite(BUZZER, HIGH);
    }
    delay(1000);
    digitalWrite(BUZZER, LOW);
  }

  if (lora_recv_packet)
  {
    digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
    lora_interrupt_enabled = false;
    lora_recv_packet = false;
    Serial.println("lora packet received");

    cipher.clear();

    std::vector<uint8_t> msg(radio.getPacketLength(), 0), initVector, tag, ciphertext, protoEncodedMsg(RADIOLIB_SX127X_MAX_PACKET_LENGTH, 0);
    int state = radio.readData(msg.data(), msg.size());
    if (state == RADIOLIB_ERR_NONE)
    {
      initVector = std::vector<uint8_t>(msg.begin(), msg.begin() + 12);
      tag = std::vector<uint8_t>(msg.begin() + 12, msg.begin() + 12 + 16);
      ciphertext = std::vector<uint8_t>(msg.begin() + 12 + 16, msg.end());

      cipher.setIV(initVector.data(), initVector.size());
      cipher.decrypt(protoEncodedMsg.data(), ciphertext.data(), ciphertext.size());

      if (!cipher.checkTag(tag.data(), tag.size()))
      {
        Serial.println("Failed to verify tag, message corrupted");
        goto finalize_lora_radio;
      }

      pb_istream_t stream = pb_istream_from_buffer(protoEncodedMsg.data(), protoEncodedMsg.size());
      ProtoPayload proto = ProtoPayload_init_zero;
      if (!pb_decode(&stream, ProtoPayload_fields, &proto))
      {
        Serial.println("Failed to decode proto");
        goto finalize_lora_radio;
      }

      Serial.println("Basement battery voltage: " + String(proto.battery_voltage));
      Serial.println("Basement battery level: " + String(proto.battery_level));
      Serial.println("Basement temperature: " + String(proto.temperature));
      Serial.println("Basement pressure: " + String(proto.pressure));
      if (!basement_in_grace_period)
      {
        got_an_alarm = proto.sensor_interrupt;
      }
    }
    else if (state == RADIOLIB_ERR_CRC_MISMATCH)
    {
      Serial.println("CRC mismatch");
    }
    else
    {
      Serial.println("Unknown error: " + String(state));
    }

  finalize_lora_radio:
    esp_timer_stop(basement_timer);
    esp_timer_start_periodic(basement_timer, BASEMENT_TIMER_DURATION_USECS);
    radio.startReceive();
    digitalWrite(LED_BUILTIN, LOW); // Turn the LED off
    lora_interrupt_enabled = true;
  }

  if (basement_timer_tick)
  {
    Serial.println("No more data from the basement, please go check it!");
    basement_timer_tick = false;
    got_an_alarm = true;
  }

  if (got_an_alarm)
  {
    digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
    digitalWrite(BUZZER, HIGH);
    // TODO: handle alarm
    Serial.println("ALARM!");
    delay(500);
    digitalWrite(LED_BUILTIN, LOW); // Turn the LED off
    digitalWrite(BUZZER, LOW);
    delay(200);
  }
}

void loop()
{
  loopProd();
}