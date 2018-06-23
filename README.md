# PADD

PADD (formerly Chronometer2) is a more expansive version of the original chronometer.sh that is included with [Pi-Hole](https://pi-hole.net). PADD provides in-depth information about your Pi-hole.

PADD is optimized for a 60x22 character display:
![PADD](https://jpmck.com/img/blog/padd.png)

It will also run in PADDmini mode on a screen that is smaller than 60x22 characters:
![PADDmini](https://jpmck.com/img/blog/paddmini.png)

(PADD will not run on a screen smaller than 30x16.)

## Setup
To setup PADD with a PiTFT+ screen:

### Setup Your Pi
*More in-depth instructions on setting up a Raspberry Pi with a PiTFT+ can be found [here](https://learn.adafruit.com/adafruit-pitft-28-inch-resistive-touchscreen-display-raspberry-pi/overview).*
- Download and flash the [latest version of Raspian Lite](https://downloads.raspberrypi.org/raspbian/images/) to an SD card.
- Get and run the latest PiTFT Installer script:
```bash
cd ~
wget https://raw.githubusercontent.com/adafruit/Raspberry-Pi-Installer-Scripts/master/adafruit-pitft.sh
chmod +x adafruit-pitft.sh
sudo ./adafruit-pitft.sh
```
- Prevent the display from going to sleep by adding `consoleblank=0` to the end of `/boot/cmdline.txt`.
- Set your Pi to automatically log into the console using `raspi-config`.
- Configure the console to use the Terminus font at 8x14 by running `sudo dpkg-reconfigure console-setup`.

### Setup Pi-Hole
- Install Pi-hole by running `curl -sSL https://install.pi-hole.net | bash`.

### Setup PADD
- Get a copy of PADD by running:
```bash
cd ~
wget -N https://raw.githubusercontent.com/jpmck/PADD/master/padd.sh
```
- Make PADD executable by running
```bash
sudo chmod +x padd.sh
```
- Set PADD to auto run by adding the following to the end of `~/.bashrc`:
```bash
# Run PADD
# If we're on the PiTFT screen (ssh is xterm)
if [ "$TERM" == "linux" ] ; then
  while :
  do
    ./padd.sh
    sleep 1
  done
fi
```
- Reboot your Pi-Hole by running `sudo reboot`. PADD should now run when your Pi-Hole has completed booting.

#### (Optional) Put the Display to Sleep at Night
*If you don't want your PiTFT on all night when you are asleep, you can put it to sleep! (Note: these instructions only apply to a PiTFT.)*

- To do so, edit cron as root (`sudo crontab -e`) and add the following:
```bash
# PiTFT+ SLEEPY TIME
# Turn off the PiTFT+ at midnight
00 00 * * * sh -c 'echo "0" > /sys/class/backlight/soc\:backlight/brightness'
# Turn on the PiTFT+ at 8:00 am
00 08 * * * sh -c 'echo "1" > /sys/class/backlight/soc\:backlight/brightness'
```

## Updating PADD
- Just run
```bash
cd ~
wget -N https://raw.githubusercontent.com/jpmck/PADD/master/padd.sh
```

## FAQ
1. What screens are supported?

   PADD has only been "officially" tested on a 3.5" PiTFT display. It also works on any terminal emulator (Terminal.app, iTerm, PuTTY, etc.). It has also been in use by other users on several other third-party displays.

2. What version of Pi-hole is supported?

   Generally speaking, the latest version of Pi-hole at the time the a new version of PADD is released. However, if there is an update to Pi-hole, there is a small chance that PADD may break.

   - I'm on the beta version of Pi-hole and the display is messed up. Will there be support for the development branch of Pi-hole?

      No. My Pi-hole, and by extension my PADD, runs in my house with the following goals: (a) don't screw up the internet for for my work-from-home/VPN setup, and (b) don't screw up the internet for my wife. For those reasons, PADD will only ever support the latest stable release of Pi-hole.

3. What does PADD mean?

   [Personal Access Display Device](http://memory-alpha.org/wiki/PADD) ... also "Pi-hole Ad Detection Display" ...

   - "Pi-hole Ad Detection Display"? Does that mean you're part of the Pi-hole team?

      Nope, PADD is a third-party application that isn't affiliated with the official Pi-hole project.

4. Who are you? How can I get a hold of you?

   ![Jim](https://jpmck.com/img/yournameisjim.png)
   Yes, my name is Jim.

   You can send me an email at `jim at jpmck dot com` or send me a message on [Reddit](https://reddit.com/user/jpmck).
