# Chronometer2
Chronometer2 is an extension of the original chronometer.sh that is included with [Pi-Hole](https://pi-hole.net) that provides more in depth information about your Pi-hole.

![Chronometer2](https://jpmck.com/img/blog/chronometer2.png)

## Setup
To setup Chronometer2 with an PiTFT+ screen:

### Setup Your Pi
- Download and flash the [Ready-to-Go Adafruit build of Raspian](https://learn.adafruit.com/adafruit-pitft-28-inch-resistive-touchscreen-display-raspberry-pi/easy-install#ready-to-go-image) to an SD card.
- Prevent the display from going to sleep by adding `consoleblank=0` to the end of `/boot/cmdline.txt`.
- Set your Pi to automatically log into the console using `raspi-config`.
- Configure the console to use the Terminus font at 8x14 by running `sudo dpkg-reconfigure console-setup`.

### Setup Pi-Hole
- Install Pi-hole by running `curl -sSL https://install.pi-hole.net | bash`.

### Setup Chronometer2
- Get a copy of Chronometer2 by running `wget -N https://raw.githubusercontent.com/jpmck/chronometer2/master/chronometer2.sh` from pi's home directory
- Make Chronometer2 executable by running `sudo chmod +x chronometer2.sh`.
- Set Chronometer2 to auto run by adding `./chronometer2.sh` to the last line of `~/.bashrc`.
- Reboot your Pi-Hole by running `sudo reboot`. Chronometer2 should now run when your Pi-Hole has completed booting.

#### (Optional) Put the Display to Sleep at Night
If you don't want your PiTFT on all night when you are asleep, you can put it to sleep as well! (Note that other screens may not work with this.)

To do so, edit cron as root (`sudo crontab -e`) and add the following:

<pre># PiTFT+ SLEEPY TIME
# Turn off the PiTFT+ at midnight
00 00 * * * sh -c 'echo "0" > /sys/class/backlight/soc\:backlight/brightness'
# Turn on the PiTFT+ at 8:00 am
00 08 * * * sh -c 'echo "1" > /sys/class/backlight/soc\:backlight/brightness'</pre>

## Updating Chronometer2
- Just run `wget -N https://raw.githubusercontent.com/jpmck/chronometer2/master/chronometer2.sh` again from pi's home directory.
