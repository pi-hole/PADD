## Chronometer2
Chronometer2 is an extension of the original chronometer.sh that is included with [Pi-Hole](https://pi-hole.net).

### Setup
To setup Chronometer2 with an Adafruit screen:

#### Setup Your Pi
- Download and flash the [Ready-to-Go Adafruit build of Raspian](https://learn.adafruit.com/adafruit-pitft-28-inch-resistive-touchscreen-display-raspberry-pi/easy-install#ready-to-go-image) to an SD card.
- Prevent the display from going to sleep by adding ```consoleblank=0``` to the end of ```/boot/cmdline.txt```.
- Set your Pi to automatically log into the console using ```raspi-config```.
- Configure the console to use the Terminus font at 8x14 by running ```sudo dpkg-reconfigure console-setup```.

#### Setup Pi-Hole
- Install Pi-hole by running ```curl -sSL https://install.pi-hole.net | bash```.
