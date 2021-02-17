***Note:** PADD has been adopted by the Pi-hole team, thanks to JPMCK for creating this helpful tool!

# PADD

PADD (formerly Chronometer2) is a more expansive version of the original chronometer.sh that is included with [Pi-Hole](https://pi-hole.net). PADD provides in-depth information about your Pi-hole.

![PADD](https://jpmck.com/img/blog/padd.png)

## Setup PADD
*More in-depth information about setting up PADD can be found in this repo’s [wiki](https://github.com/jpmck/PADD/wiki/Setup).*

- Get a copy of PADD by running:
```bash
cd ~
wget -N https://raw.githubusercontent.com/pi-hole/PADD/master/padd.sh
```
- Make PADD executable by running
```bash
sudo chmod +x padd.sh
```
- Set PADD to auto run by adding the following to the end of `~/.bashrc`:
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

## Running PADD with Pi-Hole in Docker
Using PADD with Pi-Hole in Docker can be easily done with a few extra steps. This assumes that you:
- Named your Pi-Hole container `pihole`
- Are preforming these steps under the user you want to run PADD
- The user you want to run PADD has access to the Docker socket

First, download PADD to a directory owned by the user you want to run PADD:
```bash
mkdir -p ${HOME}/padd
wget -N https://raw.githubusercontent.com/pi-hole/PADD/master/padd.sh -O ${HOME}/padd/padd.sh
```

Next, make sure you add the following mountpoints to your Pi-Hole container. These are formatted to be added to your `docker create` command:
```
-v ${HOME}/padd:/padd \
-v /proc/loadavg:/proc/loadavg:ro \
-v /proc/meminfo:/proc/meminfo:ro \
-v /sys/class/thermal:/sys/class/thermal:ro \
-v /sys/devices/system/cpu:/sys/devices/system/cpu:ro \
```

Then, add the following to the end of `~/.bashrc`:
```bash
# Run PADD
# If we’re on the PiTFT screen (ssh is xterm)
if [ "$TERM" == "linux" ] ; then
  while :
  do
    docker exec -it pihole bash /padd/padd.sh
    sleep 1
  done
fi
```
One line version
```bash
cd ~ ; echo "if [ \"\$TERM\" == \"linux\" ] ; then\n  while :\n  do\n    docker exec -it pihole bash /padd/padd.sh\n    sleep 1\n  done\nfi" | tee ~/.bashrc -a
```
Reboot your Pi-Hole by running `sudo reboot`. PADD should now run when your Pi-Hole has completed booting.

## Updating PADD
- Just run
```bash
cd ~
wget -N https://raw.githubusercontent.com/pi-hole/PADD/master/padd.sh
```

**Note: if you are already running Chronometer2 v1.3.1 or below, you’ll need to follow [these instructions](https://github.com/jpmck/PADD/wiki/Updating-from-Chronometer2)!**

## FAQ
*Answers to frequently asked questions can be found in this repo’s [wiki](https://github.com/jpmck/PADD/wiki/FAQ).*
