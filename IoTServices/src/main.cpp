#include <Arduino.h>
#include <WiFiNINA.h>
#include <ArduinoHttpClient.h>
#include "arduino_secrets.h"
#include "Adafruit_SHTC3.h"
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <ArduinoJson.h>

char ssid[] = SECRET_SSID;
char pass[] = SECRET_PASS;
char serverAddress[] = SERVER_ADDRESS;
int port = 8080;

Adafruit_SHTC3 shtc3 = Adafruit_SHTC3();
WiFiClient wifi;
HttpClient client = HttpClient(wifi, serverAddress, port);
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, 7200);

float temp, humidity;
int status = WL_IDLE_STATUS;
unsigned long lastConnectionTime = 0;
String deviceSerialNumber = SERIAL_NUMBER;
int lastRequestMinute = -1;

void printWifiStatus();
void httpRequest();
void measureSHT();

void setup() {
  Serial.begin(9600);

  while (!Serial)
    delay(10);

  Serial.println("SHTC3 test");
  if (! shtc3.begin()) {
    Serial.println("Couldn't find SHTC3");
    while (1) delay(1);
  }
  Serial.println("Found SHTC3 sensor");

  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    while (true);
  }

  String fv = WiFi.firmwareVersion();
  if (fv < WIFI_FIRMWARE_LATEST_VERSION) {
    Serial.println("Please upgrade the firmware");
  }

  while (status != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    status = WiFi.begin(ssid, pass);

    delay(10000);
  }
  printWifiStatus();
  timeClient.begin();
}

void loop() {
  timeClient.update();
  int currentMinute = timeClient.getMinutes();
  if ((currentMinute % 5 == 0) && (currentMinute != lastRequestMinute))
  {
    measureSHT();
    httpRequest();

    lastRequestMinute = currentMinute;
  }
}

void measureSHT() {
  sensors_event_t humidity_sensor, temp_sensor;

  shtc3.getEvent(&humidity_sensor, &temp_sensor);

  temp = temp_sensor.temperature;
  humidity = humidity_sensor.relative_humidity;
}

void httpRequest() {
  Serial.println("Attempting request at: " + timeClient.getFormattedTime());
  String endpoint = "/api/v2/Device/" + deviceSerialNumber;
  String contentType = "application/json";
  JsonDocument jsonDocTemp;
  String jsonTemp;
  //String jsonTemp = "{\"name\":shtc3, \"measurementType\":Temperature, \"unit\":C, \"latestReading\":" + String(temp) +"}";
  jsonDocTemp["name"] = "shtc3";
  jsonDocTemp["measurementType"] = "Temperature";
  jsonDocTemp["unit"] = "C";
  jsonDocTemp["latestReading"] = String(temp);

  serializeJson(jsonDocTemp, jsonTemp);

  client.beginRequest();
  client.put(endpoint);
  client.sendHeader("Content-Type", contentType);
  client.sendHeader("Content-Length", String(jsonTemp.length()));
  client.sendHeader("X-Arduino", true);

  client.beginBody();
  client.print(jsonTemp);

  client.endRequest();

  int statusCode = client.responseStatusCode();
  String response = client.responseBody();

  Serial.print("Status code: ");
  Serial.println(statusCode);
  Serial.print("Response: ");
  Serial.println(response);

  client.stop();
}

void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your board's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}