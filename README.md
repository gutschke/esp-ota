# esp-ota
How to maximize ESP32 flash space during OTA updates

ESP32 has a functional, but some restrictive default OTA system. It also has a very powerful API for managing your own over-the-air updates. This demonstration code explores how to forgo dedicated OTA partitions and instead re-partition flash memory on-the-fly whenever a new firmware needs to be flashed.

For the purposes of this example application, we create both a main application image, and have a SPIFFS data partition. The partition will be wiped during updates, as it can presumably be restored easily as part of the OTA process. The partition for the application will always be automatically resized to be just big enough to hold the application. This maximimizes the OTA partition during normal operations.