#include <Arduino.h>
#include <esp_bt.h>
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

#include "secrets.h"
#include "periodic_timer.h"

#define BLUE_BTN 36
#define BUZZER 37
#define BASEMENT_TIMER_DURATION_USECS 3600 * 1e6 // 1 hour
#define PMS_TIMER_DURATION_USECS 1800 * 1e6      // 30 minutes

SoftwareSerial pms_serial;
PMS pms(pms_serial);
PMS::DATA pms_data;
esp_timer_handle_t pms_timer;
bool pms_timer_tick = false;

esp_timer_handle_t basement_timer;
bool basement_timer_tick = false;

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

void setup()
{
  pinMode(LED_BUILTIN, OUTPUT);    // Initialize the built-in LED
  digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
  pinMode(BUZZER, OUTPUT);
  digitalWrite(BUZZER, HIGH); // Turn the BUZZER off
  pinMode(BLUE_BTN, INPUT_PULLDOWN);
  attachInterrupt(BLUE_BTN, blue_btn_callback, FALLING);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C))
  {
    Serial.println("Failed to initialize display");
    ESP.restart();
  }
  display.dim(false);
  display.println("Air Quality Heltec");

  Serial.begin(9600);                   // Initialize serial communications via USB
  esp_bt_controller_deinit();           // Deinitialize the Bluetooth controller
  WiFi.mode(WIFI_STA);                  // Set the WiFi module to station mode
  WiFi.begin("NET", WIFI_PASSWORD);     // Connect to the WiFi network
  while (WiFi.status() != WL_CONNECTED) // Wait for the Wi-Fi to connect
  {
    delay(500);
    Serial.print(".");
  }
  Serial.print("IP: ");
  Serial.println(WiFi.localIP()); // Print the IP address of the ESP32
  pms.sleep();                    // make sure the PMS sensor is in sleep mode

  cipher.clear();
  if (!cipher.setKey(AES_KEY, 32))
  {
    Serial.println("Failed to set key");
    ESP.restart();
  }

  if (radio.begin(868.0, 125, 12, 5, 18U, 17, 8U, 0) != 0)
  {
    Serial.println("Failed to initialize radio");
    ESP.restart();
  }
  radio.setDio0Action(lora_recv_callback);
  radio.startReceive();

  esp_timer_create_args_t pms_timer_args = {
      .callback = pms_timer_callback,
      .arg = NULL,
      .dispatch_method = ESP_TIMER_TASK,
      .name = "pms_timer"};
  if (esp_timer_create(&pms_timer_args, &pms_timer) != ESP_OK)
  {
    Serial.println("Failed to create PMS sensor timer");
    ESP.restart();
  }
  if (esp_timer_start_periodic(pms_timer, PMS_TIMER_DURATION_USECS) != ESP_OK)
  {
    Serial.println("Failed to start PMS sensor timer");
    ESP.restart();
  }

  esp_timer_create_args_t basement_timer_args = {
      .callback = basement_timer_callback,
      .arg = NULL,
      .dispatch_method = ESP_TIMER_TASK,
      .name = "basement_timer"};
  if (esp_timer_create(&basement_timer_args, &basement_timer) != ESP_OK)
  {
    Serial.println("Failed to create basement timer");
    ESP.restart();
  }
  if (esp_timer_start_periodic(basement_timer, BASEMENT_TIMER_DURATION_USECS) != ESP_OK) // 1 hour max time between transmissions for the basement node
  {
    Serial.println("Failed to start basement timer");
    ESP.restart();
  }

  display.clearDisplay();
  digitalWrite(LED_BUILTIN, LOW); // Turn the LED off
}

void loopProd()
{
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
    delay(1000);
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
      got_an_alarm = proto.sensor_interrupt;
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
  }

  if (got_an_alarm)
  {
    digitalWrite(LED_BUILTIN, HIGH); // Turn the LED on
    // TODO: handle alarm
    Serial.println("ALARM!");
    delay(500);
    digitalWrite(LED_BUILTIN, LOW); // Turn the LED off
    delay(500);
  }
}

void loop()
{
  loopProd();
}