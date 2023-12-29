# esp-ota
How to maximize ESP32 flash space during OTA updates

ESP32 has a functional, but somewhat restrictive default OTA system. It also has a very powerful API for managing your own over-the-air updates. This demonstration code explores how to forgo dedicated OTA partitions and instead re-partition flash memory on-the-fly whenever a new firmware needs to be flashed.

Related but not entirely required for all of the above, there is the question of discovery and initial configuration. ESP32 gives you all the tools, but doesn't hold your hand. If you want an ad-hoc WiFi access point with a functional captive portal that takes you to an initial configuration page, you'll have to put in some work connecting all the pieces of the API.

Consider this code a grab bag of useful code snippets that you can add to your own applications. Take all of it and use it as a framework for life-cycle management, or pick and choose.

For the purposes of this example application, we create both a main application image, and have a SPIFFS data partition in the remainder of flash storage. The partition will be wiped during updates, as it can presumably be restored easily as part of the OTA process. The partition for the application will always be automatically resized to be just big enough to hold the application. This maximimizes the data partition during normal operations.

For bring-up, we always start both a WiFi access point and connect to the known site-wide WiFi network (if any). When using the access point, we jump through all the hoops that modern browsers want in order to allow you to redirect to a captive portal. Unfortunately, that inevitably requires adding SSL support to the image, which considerably increases the image size. If that is a problem, you'd have to strip out the code for the captive portal and instruct users to manually connect to a hard-coded IP address (e.g. http://192.168.4.1). This is a lot more error prone and a worse user experience, but programming microcontrollers is an exercise in compromise.