#include <Arduino.h>
#include <ArduinoBearSSL.h>
#include <ArduinoMqttClient.h>
#include <WiFiNINA.h>
#include "arduino_secrets.h"
#include <ArduinoHttpClient.h>
#include "Adafruit_SHTC3.h"
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <ArduinoJson.h>
#include <az_core.h>
#include <az_iot.h>
#include <ECCX08.h>
#include <cstdbool>
#include <cstdlib>
#include <cstring>
#include <time.h>
// Logging
#include "SerialLogger.h"

Adafruit_SHTC3 shtc3 = Adafruit_SHTC3();
WiFiClient wifi;
BearSSLClient bearSSLClient(wifi);
MqttClient mqttClient(bearSSLClient);
az_iot_hub_client azIoTHubClient;

WiFiUDP ntpUDP;
int time_zone = IOT_CONFIG_TIME_ZONE;
int daylight_savings = IOT_CONFIG_TIME_ZONE_DAYLIGHT_SAVINGS_DIFF;
int offset = (time_zone + daylight_savings) * 3600;
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000);

char mqtt_username[128];
char mqtt_publish_topic[128];
char mqtt_subscribe_topic[128];
float temp, humidity;
int status = WL_IDLE_STATUS;
unsigned long lastConnectionTime = 0;
char* device_serial_number = IOT_CONFIG_DEVICE_ID;
char* iot_hub_hostname = IOT_CONFIG_IOTHUB_FQDN;
int lastRequestMinute = -1;
int readingFrequencyInMinutes = 5;

#define BUFFER_LENGTH_MQTT_CLIENT_ID 256
#define BUFFER_LENGTH_MQTT_PASSWORD 256
#define BUFFER_LENGTH_MQTT_TOPIC 256
#define BUFFER_LENGTH_MQTT_USERNAME 512
#define BUFFER_LENGTH_SAS 32
#define BUFFER_LENGTH_SAS_ENCODED_SIGNED_SIGNATURE 64
#define BUFFER_LENGTH_SAS_SIGNATURE 512
#define BUFFER_LENGTH_DATETIME_STRING 256
#define SECS_PER_MIN 60
#define SECS_PER_HOUR (SECS_PER_MIN * 60)
#define GMT_OFFSET_SECS (IOT_CONFIG_DAYLIGHT_SAVINGS ? \
                        ((IOT_CONFIG_TIME_ZONE + IOT_CONFIG_TIME_ZONE_DAYLIGHT_SAVINGS_DIFF) * SECS_PER_HOUR) : \
                        (IOT_CONFIG_TIME_ZONE * SECS_PER_HOUR))
static char mqttClientId[BUFFER_LENGTH_MQTT_CLIENT_ID];
static char mqttUsername[BUFFER_LENGTH_MQTT_USERNAME];
static char mqttPassword[BUFFER_LENGTH_MQTT_PASSWORD];

static char telemetryTopic[BUFFER_LENGTH_MQTT_TOPIC];

void connectToWiFi();
void measureSHT();

void initializeAzureIoTHubClient();
void initializeMQTTClient();
void connectMQTTClientToAzureIoTHub();

void onMessageReceived(int messageSize);
static void sendTelemetry();

static void generateMQTTPassword();
static void generateSASBase64EncodedSignedSignature(
    uint8_t const* sasSignature, size_t const sasSignatureSize,
    uint8_t* encodedSignedSignature, size_t encodedSignedSignatureSize,
    size_t* encodedSignedSignatureLength);
static uint64_t getSASTokenExpirationTime(uint32_t minutes);

static unsigned long getTime();
static String getFormattedDateTime(unsigned long epochTimeInSeconds);
static String mqttErrorCodeName(int errorCode);

#define EXIT_LOOP(condition, errorMessage) \
  do \ 
  { \
    if (condition) { \
      Logger.Error(errorMessage); \
      while (1); \
    } \
  } while (0)
  

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
  
  connectToWiFi(); 
  initializeAzureIoTHubClient();
  initializeMQTTClient();
  connectMQTTClientToAzureIoTHub();
}

void loop() {
  timeClient.update();
  if (WiFi.status() != WL_CONNECTED) 
  {
    connectToWiFi();
  }

  int currentMinute = timeClient.getMinutes();
  if ((currentMinute % readingFrequencyInMinutes == 0) && (currentMinute != lastRequestMinute))
  {
    measureSHT();
    if (!mqttClient.connected()) 
    {
      connectMQTTClientToAzureIoTHub();
    }

    sendTelemetry();
    
    lastRequestMinute = currentMinute;
  }

  // if (mqttClient.available())
  // {
  //   String payload = mqttClient.readString();
  //   processCommand(payload);
  // }

  mqttClient.poll();
  delay(50);
}

void connectToWiFi() 
{
  Logger.Info("Attempting to connect to WIFI SSID: " + String(IOT_CONFIG_WIFI_SSID));

  WiFi.begin(IOT_CONFIG_WIFI_SSID, IOT_CONFIG_WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) 
  {
    Serial.print(".");
    delay(IOT_CONFIG_WIFI_CONNECT_RETRY_MS);
  }
  Serial.println();

  Logger.Info("WiFi connected, IP address: " + String(WiFi.localIP()) + ", Strength (dBm): " + WiFi.RSSI());
  Logger.Info("Syncing time.");

  timeClient.begin();

  unsigned long start = millis();
  while (getTime() < 1000000)
  {
    timeClient.update();
    Serial.print(".");
    delay(500);
    if (millis() - start > 30000) {
      Serial.println("\nTime update timeout. Check your NTP configuration or network.");
      break;
    }
  }
  Serial.println();

  Logger.Info("Time synced!");
}

void processCommand(String &payload) {
  Serial.print("Received C2D command: ");
  Serial.println(payload);

  // Example processing logic:
  if (payload.equals("TURN_ON")) {
    Serial.println("Executing command: TURN ON");
    // Insert code to turn on an LED or actuator here.
  } else if (payload.equals("TURN_OFF")) {
    Serial.println("Executing command: TURN OFF");
    // Insert code to turn off an LED or actuator here.
  } else {
    Serial.println("Unknown command received.");
  }
}

void initializeAzureIoTHubClient() {
  Logger.Info("Initializing Azure IoT Hub client.");

  az_span hostname = AZ_SPAN_FROM_STR(IOT_CONFIG_IOTHUB_FQDN);
  az_span deviceId = AZ_SPAN_FROM_STR(IOT_CONFIG_DEVICE_ID);

  az_iot_hub_client_options options = az_iot_hub_client_options_default();
  options.user_agent = AZ_SPAN_FROM_STR(IOT_CONFIG_AZURE_SDK_CLIENT_USER_AGENT);

  int result = az_iot_hub_client_init(&azIoTHubClient, hostname, deviceId, &options);

  EXIT_LOOP(az_result_failed(result), "Failed to initialize Azure IoT Hub client. Return code: " + result);

  Logger.Info("Azure IoT Hub hostname: " + String(IOT_CONFIG_IOTHUB_FQDN));
  Logger.Info("Azure IoT Hub client initialized.");
}

void initializeMQTTClient() {
  Logger.Info("Initializing MQTT client.");
  
  int result;

  result = az_iot_hub_client_get_client_id(
      &azIoTHubClient, mqttClientId, sizeof(mqttClientId), NULL);
  EXIT_LOOP(az_result_failed(result), "Failed to get MQTT client ID. Return code: " + result);
  
  result = az_iot_hub_client_get_user_name(
      &azIoTHubClient, mqttUsername, sizeof(mqttUsername), NULL);
  EXIT_LOOP(az_result_failed(result), "Failed to get MQTT username. Return code: " + result);

  generateMQTTPassword(); // SAS Token

  mqttClient.setId(mqttClientId);
  mqttClient.setUsernamePassword(mqttUsername, mqttPassword);
  mqttClient.onMessage(onMessageReceived); // Set callback for C2D messages

  Logger.Info("Client ID: " + String(mqttClientId));
  Logger.Info("Username: " + String(mqttUsername));

  Logger.Info("MQTT client initialized.");
}

void connectMQTTClientToAzureIoTHub() 
{
  Logger.Info("Connecting to Azure IoT Hub.");

  // Set a callback to get the current time used to validate the server certificate.
  ArduinoBearSSL.onGetTime(getTime);

  while (!mqttClient.connect(IOT_CONFIG_IOTHUB_FQDN, AZ_IOT_DEFAULT_MQTT_CONNECT_PORT)) 
  {
    int code = mqttClient.connectError();
    Logger.Error("Cannot connect to Azure IoT Hub. Reason: " + mqttErrorCodeName(code) + ", Code: " + code);
    delay(5000);
  }

  Logger.Info("Connected to your Azure IoT Hub!");

  mqttClient.subscribe(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC);

  Logger.Info("Subscribed to MQTT topic: " + String(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC));
}

void onMessageReceived(int messageSize) 
{
  while (mqttClient.available()) 
  {
    Serial.print((char)mqttClient.read());
  }
  Serial.println();
}

static void sendTelemetry() 
{
  Logger.Info("Arduino Nano 33 IoT sending telemetry . . . ");
  unsigned long now = getTime();  // GMT
  unsigned long localNow = now + GMT_OFFSET_SECS;

  Logger.Info("UTC Current time: " + getFormattedDateTime(now) + " (epoch: " + now + " secs)");
  Logger.Info("Local Current time: " + getFormattedDateTime(localNow));

  uint8_t custom_prop_buffer[256];

  // Create an az_iot_message_properties instance.
  az_iot_message_properties custom_properties;

  // Initialize the properties instance using the buffer.
  az_result rc = az_iot_message_properties_init(
      &custom_properties,
      AZ_SPAN_FROM_BUFFER(custom_prop_buffer),
      NULL
  );

  rc = az_iot_message_properties_append(
    &custom_properties,
    AZ_SPAN_FROM_STR("serialNumber"),
    AZ_SPAN_FROM_STR(IOT_CONFIG_DEVICE_ID)
  );

  int result = az_iot_hub_client_telemetry_get_publish_topic(
      &azIoTHubClient, &custom_properties, telemetryTopic, sizeof(telemetryTopic), NULL);
  EXIT_LOOP(az_result_failed(result), "Failed to get telemetry publish topic. Return code: " + result);

  Serial.println(telemetryTopic);
  String topicStr = String(telemetryTopic);

  JsonDocument jsonDoc;
  jsonDoc["serialNumber"] = device_serial_number;
  jsonDoc["name"] = "shtc3";

  JsonArray readings = jsonDoc.createNestedArray("readings");
  JsonObject tempReading = readings.createNestedObject();
  tempReading["measurementType"] = "Temperature";
  tempReading["unit"] = "C";
  tempReading["latestReading"] = String(temp);

  String jsonPayload;
  serializeJsonPretty(jsonDoc, jsonPayload);

  mqttClient.beginMessage(telemetryTopic);
  mqttClient.print(jsonPayload);
  mqttClient.endMessage();

  delay(500);
  
  jsonDoc.remove("readings");
  readings = jsonDoc.createNestedArray("readings");

  JsonObject humidityReading = readings.createNestedObject();
  humidityReading["measurementType"] = "Humidity";
  humidityReading["unit"] = "% rH";
  humidityReading["latestReading"] = String(humidity);

  serializeJsonPretty(jsonDoc, jsonPayload);

  mqttClient.beginMessage(telemetryTopic);
  mqttClient.print(jsonPayload);
  mqttClient.endMessage();

  Logger.Info("Telemetry sent from Arduino Nano 33 IoT.");
  delay(100);
}

static void generateMQTTPassword() 
{
  int result;

  uint64_t sasTokenDuration = 0;
  uint8_t signature[BUFFER_LENGTH_SAS_SIGNATURE] = {0};
  az_span signatureAzSpan = AZ_SPAN_FROM_BUFFER(signature);
  uint8_t encodedSignedSignature[BUFFER_LENGTH_SAS_ENCODED_SIGNED_SIGNATURE] = {0};
  size_t encodedSignedSignatureLength = 0;

  // Get the signature. It will be signed later with the decoded device key.
  // To change the sas token duration, see IOT_CONFIG_SAS_TOKEN_EXPIRY_MINUTES in iot_configs.h
  sasTokenDuration = getSASTokenExpirationTime(IOT_CONFIG_SAS_TOKEN_EXPIRY_MINUTES);
  result = az_iot_hub_client_sas_get_signature(
      &azIoTHubClient, sasTokenDuration, signatureAzSpan, &signatureAzSpan);
  EXIT_LOOP(az_result_failed(result), "Could not get the signature for SAS Token. Return code: " + result);

  // Sign and encode the signature (b64 encoded, HMAC-SHA256 signing).
  // Uses the decoded device key.
  generateSASBase64EncodedSignedSignature(
      az_span_ptr(signatureAzSpan), az_span_size(signatureAzSpan),
      encodedSignedSignature, sizeof(encodedSignedSignature), &encodedSignedSignatureLength);

  // Get the MQTT password (SAS Token) from the base64 encoded, HMAC signed bytes.
  az_span encodedSignedSignatureAzSpan = az_span_create(encodedSignedSignature, 
                                                        encodedSignedSignatureLength);
  result = az_iot_hub_client_sas_get_password(
      &azIoTHubClient, sasTokenDuration, encodedSignedSignatureAzSpan, AZ_SPAN_EMPTY,
      mqttPassword, sizeof(mqttPassword), NULL);
  EXIT_LOOP(az_result_failed(result), "Could not get the MQTT password. Return code: " + result);
}

static void generateSASBase64EncodedSignedSignature(
  uint8_t const* sasSignature, size_t const sasSignatureSize,
  uint8_t* encodedSignedSignature, size_t encodedSignedSignatureSize,
  size_t* encodedSignedSignatureLength) 
{
  int result;
  unsigned char sasDecodedKey[BUFFER_LENGTH_SAS] = {0};
  az_span sasDecodedKeySpan = AZ_SPAN_FROM_BUFFER(sasDecodedKey);
  int32_t sasDecodedKeyLength = 0;
  uint8_t sasHMAC256SignedSignature[BUFFER_LENGTH_SAS] = {0};

  // Decode the SAS base64 encoded device key to use for HMAC signing.
  az_span configDeviceKeySpan = az_span_create((uint8_t*)IOT_CONFIG_DEVICE_KEY, sizeof(IOT_CONFIG_DEVICE_KEY) - 1);
  result = az_base64_decode(sasDecodedKeySpan, configDeviceKeySpan, &sasDecodedKeyLength);
  EXIT_LOOP(result != AZ_OK, "az_base64_decode failed. Return code: " + result);

  // HMAC-SHA256 sign the signature with the decoded device key.
  result = ECCX08.begin();
  EXIT_LOOP(!result, "Failed to communicate with ATECC608.");
  
  result = ECCX08.nonce(sasDecodedKey);
  EXIT_LOOP(!result, "Failed to do nonce.");

  result = ECCX08.beginHMAC(0xFFFF);
  EXIT_LOOP(!result, "Failed to start HMAC operation.");

  result = ECCX08.updateHMAC(sasSignature, sasSignatureSize);
  EXIT_LOOP(!result, "Failed to update HMAC with signature.");

  result = ECCX08.endHMAC(sasHMAC256SignedSignature);
  EXIT_LOOP(!result, "Failed to end HMAC operation.");

  // Base64 encode the result of the HMAC signing.
  az_span signedSignatureSpan = az_span_create(sasHMAC256SignedSignature, sizeof(sasHMAC256SignedSignature));
  az_span encodedSignedSignatureSpan = az_span_create(encodedSignedSignature, encodedSignedSignatureSize);
  result = az_base64_encode(encodedSignedSignatureSpan, signedSignatureSpan, (int32_t*) encodedSignedSignatureLength);
  EXIT_LOOP(result != AZ_OK, "az_base64_encode failed. Return code: " + result);
}

static uint64_t getSASTokenExpirationTime(uint32_t minutes) 
{
  unsigned long now = getTime();  // GMT
  unsigned long expiryTime = now + (SECS_PER_MIN * minutes * 2); // For SAS Token
  unsigned long localNow = now + GMT_OFFSET_SECS;
  unsigned long localExpiryTime = expiryTime + GMT_OFFSET_SECS;

  Logger.Info("UTC Current time: " + getFormattedDateTime(now) + " (epoch: " + now + " secs)");
  Logger.Info("UTC Expiry time: " + getFormattedDateTime(expiryTime) + " (epoch: " + expiryTime + " secs)");
  Logger.Info("Local Current time: " + getFormattedDateTime(localNow));
  Logger.Info("Local Expiry time: " + getFormattedDateTime(localExpiryTime));

  return (uint64_t)expiryTime;
}

static unsigned long getTime()
{
  return timeClient.getEpochTime();
}

static String getFormattedDateTime(unsigned long epochTimeInSeconds) 
{
  char dateTimeString[BUFFER_LENGTH_DATETIME_STRING];

  time_t epochTimeInSecondsAsTimeT = (time_t)epochTimeInSeconds;
  struct tm* timeInfo = localtime(&epochTimeInSecondsAsTimeT);

  strftime(dateTimeString, 20, "%F %T", timeInfo);

  return String(dateTimeString);
}

static String mqttErrorCodeName(int errorCode) 
{
  String errorMessage;
  switch (errorCode) 
  {
  case MQTT_CONNECTION_REFUSED:
    errorMessage = "MQTT_CONNECTION_REFUSED";
    break;
  case MQTT_CONNECTION_TIMEOUT:
    errorMessage = "MQTT_CONNECTION_TIMEOUT";
    break;
  case MQTT_SUCCESS:
    errorMessage = "MQTT_SUCCESS";
    break;
  case MQTT_UNACCEPTABLE_PROTOCOL_VERSION:
    errorMessage = "MQTT_UNACCEPTABLE_PROTOCOL_VERSION";
    break;
  case MQTT_IDENTIFIER_REJECTED:
    errorMessage = "MQTT_IDENTIFIER_REJECTED";
    break;
  case MQTT_SERVER_UNAVAILABLE:
    errorMessage = "MQTT_SERVER_UNAVAILABLE";
    break;
  case MQTT_BAD_USER_NAME_OR_PASSWORD:
    errorMessage = "MQTT_BAD_USER_NAME_OR_PASSWORD";
    break;
  case MQTT_NOT_AUTHORIZED:
    errorMessage = "MQTT_NOT_AUTHORIZED";
    break;
  default:
    errorMessage = "Unknown";
    break;
  }

  return errorMessage;
}

void measureSHT() {
  sensors_event_t humidity_sensor, temp_sensor;

  shtc3.getEvent(&humidity_sensor, &temp_sensor);

  temp = temp_sensor.temperature;
  humidity = humidity_sensor.relative_humidity;
}