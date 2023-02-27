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
