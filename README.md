# PADD

PADD (formerly Chronometer2) is a more expansive version of the original chronometer.sh that is included with [Pi-Hole](https://pi-hole.net). PADD provides in-depth information about your Pi-hole.

![PADD Screenshot](https://pi-hole.github.io/graphics/Screenshots/padd.png)

***Note:** PADD has been adopted by the Pi-hole team, thanks to JPMCK for creating this helpful tool!

## Setup PADD
*More in-depth information about setting up PADD can be found in this repo’s [wiki](https://github.com/pi-hole/PADD/wiki/Setup).*

- Get a copy of PADD by running:

```bash
cd ~
wget -O padd.sh https://install.padd.sh
```
or
```bash
cd ~
curl -sSL https://install.padd.sh -o padd.sh
```

- Make PADD executable by running

```bash
sudo chmod +x padd.sh
```

- Set PADD to auto run on the PiTFT screen by adding the following to the end of `~/.bashrc`:

```bash
# Run PADD
# If we’re on the PiTFT screen (ssh is xterm)
if [ "$TERM" == "linux" ] ; then
  while :
  do
    ./padd.sh
    sleep 1
  done
fi
```

One line version

```bash
cd ~ ; echo "if [ \"\$TERM\" == \"linux\" ] ; then\n  while :\n  do\n    ./padd.sh\n    sleep 1\n  done\nfi" | tee ~/.bashrc -a
```

- Reboot your Pi-Hole by running `sudo reboot`. PADD should now run when your Pi-Hole has completed booting.

### (Optional) Put the PiTFT Display to Sleep at Night
*If you don't want your PiTFT on all night when you are asleep, you can put it to sleep! (Note: __these instructions only apply to a PiTFT__.)*

- To do so, edit cron as root (`sudo crontab -e`) and add the following:
```bash
# PiTFT+ SLEEPY TIME
# Turn off the PiTFT+ at midnight
00 00 * * * sh -c 'echo "0" > /sys/class/backlight/soc\:backlight/brightness'
# Turn on the PiTFT+ at 8:00 am
00 08 * * * sh -c 'echo "1" > /sys/class/backlight/soc\:backlight/brightness'
```

## Updating PADD
- Simply run

```bash
./padd.sh -u
```

- or run the same commands you used to install

```bash
cd ~
wget -O padd.sh https://install.padd.sh
```
```bash
cd ~
curl -sSL https://install.padd.sh -o padd.sh
```

## Running Pi-hole in a Docker Container
If you're running Pi-hole in the official Docker Container, `padd.sh` is pre-installed and named `padd`. It can be used with the following command:
```bash
docker exec -it <container_name> padd [padd_options]
```

## Sizes
PADD will display on screens that anywhere from 20x10 characters to over 80x26 characters.

As your screen gets smaller, you’ll be presented with less information… however, you’ll always get the most important details:
- The status of your Pi-hole (is it online, in need of an update?),
- How many ads have been blocked,
- Your hostname and IP, and
- Your CPU’s current load.

It will also run in the following modes (shown further below):
- Pico: 20x10 characters
- Nano: 24x12 characters
- Micro: 30x16 characters
- Mini: 40x18 characters
- Tiny: 53x20 characters
- Slim: 60x21 characters
- Regular: 60x22 characters (takes up the entire screen on a 3.5" Adafruit PiTFT using the Terminal font at 8x14.)
- Mega: 80x26 characters

### Sizing Your PADD
How PADD will display on your screen depends on the size of the screen in *characters*, not *pixels*! PADD doesn’t care if it is running on a 5k Retina display on your $5,000 iMac Pro or on a $5 display you bought on eBay.

If you want to change how PADD displays on a small display attached to your Raspberry Pi, use
```bash
sudo dpkg-reconfigure console-setup
```
to configure your font settings to an ideal size for you.

If you want to change how PADD displays through a terminal emulator (PuTTY, Terminal.app, iTerm2, etc.), resize your window or play with font sizes in your app of choice.

### The Sizes

![PADD Sizes GIF](https://github.com/pi-hole/graphics/blob/master/PADD/PADDsizes.gif)
