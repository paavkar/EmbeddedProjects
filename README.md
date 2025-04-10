# Repository info

This repository is meant to store my Embedded Systems projects.
I've so far only done things with Arduino (PlatformIO).

## Projects

The two projects currently in this repository are connected to
my project [IoTDeviceManager](https://github.com/paavkar/IoTDeviceManager).
You can find information about the project behind the link.

### AzureIoTHub

This project is one where I use Microsoft's Azure SDK for C to connect
with Azure IoT Hub. The IoT Hub connection code is from the example of
[Arduino Nano RP2040](https://github.com/Azure/azure-sdk-for-c-arduino/blob/main/examples/Azure_IoT_Hub_Arduino_Nano_RP2040_Connect/README.md). I am using an [Arduino Nano 33 IoT](https://docs.arduino.cc/hardware/nano-33-iot/)
with this project (with a sensor board).

I have some more function than in the example. I have set place
a Configuration system where user sets the WiFi network the Arduino
connects to. If the IoT Hub is setup correctly, the software sends
telemetry data in form of temperature and humidity readings which
are taken by SHTC3 sensor. To ease the WiFi configuration, I have
set up a button Interrupt to clear the saved WiFi network credentials
and then return the Arduino to configuration mode.

### IoTServices

This is a much simpler project with the same board. In this project,
I send the same readings as stated before straight to an API to save
the readings.