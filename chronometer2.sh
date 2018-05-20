#!/usr/bin/env bash
# Chronometer2
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
# Issue 5: https://github.com/jpmck/chronometer2/issues/5
# Updated to en_US to support
export LC_ALL=en_US.UTF-8

chronometer2Version="1.3"

# COLORS
blueColor=$(tput setaf 6)
greenColor=$(tput setaf 2)
magentaColor=$(tput setaf 5)
redColor=$(tput setaf 1)
resetColor=$(tput setaf 7)
yellowColor=$(tput setaf 3)

# DATE
today=$(date +%Y%m%d)

# CORES
numProc=$(grep -c 'model name' /proc/cpuinfo)

GetFTLData() {
  # Open connection to FTL
  exec 3<>/dev/tcp/localhost/"$(cat /var/run/pihole-FTL.port)"

  # Test if connection is open
  if { >&3; } 2> /dev/null; then
    # Send command to FTL
    echo -e ">$1" >&3

    # Read input
    read -r -t 1 LINE <&3
    until [ ! $? ] || [[ "$LINE" == *"EOM"* ]]; do
      echo "$LINE" >&1
      read -r -t 1 LINE <&3
    done

    # Close connection
    exec 3>&-
    exec 3<&-
  fi
}

GetSummaryInformation() {
  # From pihole -c
  local summary
  summary=$(GetFTLData "stats")

  domains_being_blocked_raw=$(grep "domains_being_blocked" <<< "${summary}" | grep -Eo "[0-9]+$")
  domains_being_blocked=$(printf "%'.f" ${domains_being_blocked_raw})

  dns_queries_today_raw=$(grep "dns_queries_today" <<< "$summary" | grep -Eo "[0-9]+$")
  dns_queries_today=$(printf "%'.f" ${dns_queries_today_raw})

  ads_blocked_today_raw=$(grep "ads_blocked_today" <<< "$summary" | grep -Eo "[0-9]+$")
  ads_blocked_today=$(printf "%'.f" ${ads_blocked_today_raw})

  ads_percentage_today_raw=$(grep "ads_percentage_today" <<< "$summary" | grep -Eo "[0-9.]+$")
  LC_NUMERIC=C ads_percentage_today=$(printf "%'.1f" ${ads_percentage_today_raw})

  adsBlockedBar=$(BarGenerator $ads_percentage_today 40 "color")
}

GetSystemInformation() {
  # System uptime
  systemUptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')

  # CPU temperature
  cpu=$(</sys/class/thermal/thermal_zone0/temp)

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" == "F" ]; then
    temperature=$(printf %.1f "$(echo "scale=4; ${cpu}*9/5000+32" | bc)")°F
  elif [ "${TEMPERATUREUNIT}" == "K" ]; then
    temperature=$(printf %.1f "$(echo "scale=4; (${cpu}/1000+273.15)" | bc)")°K
  # Addresses Issue 1: https://github.com/jpmck/chronometer2/issues/1
  else
    temperature=$(printf %.1f "$(echo "scale=4; ${cpu}/1000" | bc)")°C
  fi

  # CPU load, heatmap and bar
  cpuLoad1=$(cat /proc/loadavg | awk '{print $1}')
  cpuLoad1Heatmap=$(HeatmapGenerator ${cpuLoad1} ${numProc})
  cpuLoad5=$(cat /proc/loadavg | awk '{print $2}')
  cpuLoad5Heatmap=$(HeatmapGenerator ${cpuLoad5} ${numProc})
  cpuLoad15=$(cat /proc/loadavg | awk '{print $3}')
  cpuLoad15Heatmap=$(HeatmapGenerator ${cpuLoad15} ${numProc})
  cpuPercent=$(printf %.1f "$(echo "scale=4; (${cpuLoad1}/${numProc})*100" | bc)")
  cpuBar=$(BarGenerator ${cpuPercent} 10)

  # CPU temperature heatmap
  if [ ${cpu} -gt 60000 ]; then
    tempHeatMap=${redColor}
  else
    tempHeatMap=${blueColor}
  fi

  # Memory use, heatmap and bar
  memoryUsedPercent=$(awk '/MemTotal:/{total=$2} /MemFree:/{free=$2} /Buffers:/{buffers=$2} /^Cached:/{cached=$2} END {printf "%.1f", (total-free-buffers-cached)*100/total}' '/proc/meminfo')
  memoryHeatmap=$(HeatmapGenerator ${memoryUsedPercent})
  memoryBar=$(BarGenerator ${memoryUsedPercent} 10)
}

# Provides a color based on a provided percentage
# takes in one or two parameters
HeatmapGenerator () {
  # if one number is provided, just use that percentage to figure out the colors
  if [ -z "$2" ]; then
    load=$(printf "%.0f" "$1")
  # if two numbers are provided, do some math to make a percentage to figure out the colors
  else
    load=$(printf "%.0f" "$(echo "scale=2; ($1/$2)*100" | bc)")
  fi

  # Color logic
  #  |                   green                    | yellow |  red ->
  #  0  5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100
  if [ ${load} -lt 75 ]; then
    out=${greenColor}
  elif [ ${load} -lt 90 ]; then
    out=${yellowColor}
  else
    out=${redColor}
  fi

  echo $out
}

# Provides a "bar graph"
# takes in two or three parameters
# $1: percentage filled
# $2: max length of the bar
# $3: colored flag, if "color" backfill with color
BarGenerator() {
  # number of filled in cells in the bar
  barNumber=$(printf %.f "$(echo "scale=1; (($1/100)*$2)" | bc)")
  frontFill=$(for i in $(seq $barNumber); do echo -n '■'; done)

  # remaining "unfilled" cells in the bar
  backfillNumber=$(($2-${barNumber}))

  # if the filled in cells is less than the max length of the bar, fill it
  if [ "$barNumber" -lt "$2" ]; then
    # if the bar should be colored
    if [ "$3" = "color" ]; then
      # fill the rest in color
      backFill=$(for i in $(seq $backfillNumber); do echo -n '■'; done)
      out="${redColor}${frontFill}${greenColor}${backFill}${resetColor}"
    # else, it shouldn't be colored in
    else
      # fill the rest with "space"
      backFill=$(for i in $(seq $backfillNumber); do echo -n '·'; done)
      out="${frontFill}${backFill}"
    fi
  # else, fill it all the way
  else
    out=$(for i in $(seq $2); do echo -n '■'; done)
  fi

  echo $out
}

GetNetworkInformation() {
  # Is Pi-Hole acting as the DHCP server?
  if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    dhcpStatus="Enabled"
    dhcpInfo=" Range:    ${DHCP_START} - ${DHCP_END}"
    dhcpHeatmap=${greenColor}

    # Is DHCP handling IPv6?
    if [[ "${DHCP_IPv6}" == "true" ]]; then
      dhcpIPv6Status="Enabled"
      dhcpIPv6Heatmap=${greenColor}
    else
      dhcpIPv6Status="Disabled"
      dhcpIPv6Heatmap=${redColor}
    fi
  else
    dhcpStatus="Disabled"

    # if the DHCP Router variable isn't set
    # Issue 3: https://github.com/jpmck/chronometer2/issues/3
    if [ -z ${DHCP_ROUTER+x} ]; then
      DHCP_ROUTER=$(/sbin/ip route | awk '/default/ { print $3 }')
    fi

    dhcpInfo=" Router:   ${DHCP_ROUTER}"
    dhcpHeatmap=${redColor}

    dhcpIPv6Status="N/A"
    dhcpIPv6Heatmap=${yellowColor}
  fi

  # DNSSEC
  if [[ "${DNSSEC}" == "true" ]]; then
    dnssecStatus="Enabled"
    dnssecHeatmap=${greenColor}
  else
    dnssecStatus="Disabled"
    dnssecHeatmap=${redColor}
  fi
}

GetPiholeInformation() {
  # Get Pi-hole status
  if [[ $(pihole status web) == 1 ]]; then
    piHoleStatus="Active"
    piHoleHeatmap=${greenColor}
  elif [[ $(pihole status web) == 0 ]]; then
    piHoleStatus="Offline"
    piHoleHeatmap=${redColor}
  elif [[ $(pihole status web) == -1 ]]; then
    piHoleStatus="DNS Offline"
    piHoleHeatmap=${redColor}
  else
    piHoleStatus="Unknown"
    piHoleHeatmap=${yellowColor}
  fi

  # Get FTL status
  ftlPID=$(pidof pihole-FTL)

  if [ -z ${ftlPID+x} ]; then
    ftlStatus="Not running"
    ftlHeatmap=${redColor}
  else
    ftlStatus="Running"
    ftlHeatmap=${greenColor}
  fi
}

GetVersionInformation() {
  # Check if version status has been saved
  if [ -e "piHoleVersion" ]; then
    # the file exits, use it
    source piHoleVersion

    # was the last check today?
    if [ "${today}" != "${lastCheck}" ]; then # no, it wasn't today
      # Today is...
      today=$(date +%Y%m%d)

      # what are the latest available versions?
      # TODO: update if necessary if added to pihole
      piholeVersionLatest=$(pihole -v -p -l | awk '{print $5}' | tr -d "[:alpha:]")
         webVersionLatest=$(pihole -v -a -l | awk '{print $5}' | tr -d "[:alpha:]")
         ftlVersionLatest=$(pihole -v -f -l | awk '{print $5}' | tr -d "[:alpha:]")
      chronometer2VersionLatest=$(curl -sI https://github.com/jpmck/chronometer2/releases/latest | grep 'Location' | awk -F '/' '{print $NF}' | tr -d '\r\n[:alpha:]')

      # check if everything is up-to-date...
      # is core up-to-date?
      if [[ "${piholeVersion}" != "${piholeVersionLatest}" ]]; then
        outOfDateFlag="true"
        piholeVersionHeatmap=${redColor}
      else
        piholeVersionHeatmap=${resetColor}
      fi

      # is web up-to-date?
      if [[ "${webVersion}" != "${webVersionLatest}" ]]; then
        outOfDateFlag="true"
        webVersionHeatmap=${redColor}
      else
        webVersionHeatmap=${resetColor}
      fi

      # is ftl up-to-date?
      if [[ "${ftlVersion}" != "${ftlVersionLatest}" ]]; then
        outOfDateFlag="true"
        ftlVersionHeatmap=${redColor}
      else
        ftlVersionHeatmap=${resetColor}
      fi

      # is chronometer2 up-to-date?
      if [[ "${chronometer2Version}" != "${chronometer2VersionLatest}" ]]; then
        chronometer2OutOfDateFlag="true"
        chronometer2VersionHeatmap=${redColor}
      else
        chronometer2VersionHeatmap=${resetColor}
      fi

      # was any portion of Pi-hole out-of-date?
      # yes, pi-hole is out of date
      if [[ "${outOfDateFlag}" == "true" ]]; then
        versionStatus="Pi-hole is out-of-date!"
        versionHeatmap=${redColor}
      else
        # but is chronometer2 out-of-date?
        if [[ "${chronometer2OutOfDateFlag}" == "true" ]]; then
          versionStatus="Chronometer2 is out-of-date!"
          versionHeatmap=${redColor}
        # else, everything is good!
        else
          versionStatus="Pi-hole is up-to-date!"
          versionHeatmap=${greenColor}
        fi
      fi

      # write it all to the file
      echo "lastCheck="${today} > ./piHoleVersion

      echo "piholeVersion="$piholeVersion >> ./piHoleVersion
      echo "piholeVersionHeatmap="$piholeVersionHeatmap >> ./piHoleVersion

      echo "webVersion="$webVersion >> ./piHoleVersion
      echo "webVersionHeatmap="$webVersionHeatmap >> ./piHoleVersion

      echo "ftlVersion="$ftlVersion >> ./piHoleVersion
      echo "ftlVersionHeatmap="$ftlVersionHeatmap >> ./piHoleVersion

      echo "chronometer2Version="$chronometer2Version >> ./piHoleVersion
      echo "chronometer2VersionHeatmap="$chronometer2VersionHeatmap >> ./piHoleVersion

      echo "versionStatus="\"$versionStatus\" >> ./piHoleVersion
      echo "versionHeatmap="$versionHeatmap >> ./piHoleVersion

    fi

  # else the file dosn't exist
  else
    # We're using...
    piholeVersion=$(pihole -v -p | awk '{print $4}' | tr -d "[:alpha:]")
       webVersion=$(pihole -v -a | awk '{print $4}' | tr -d "[:alpha:]")
       ftlVersion=$(pihole -v -f | awk '{print $4}' | tr -d "[:alpha:]")

    echo "lastCheck=0" > ./piHoleVersion
    echo "piholeVersion="$piholeVersion >> ./piHoleVersion
    echo "webVersion="$webVersion >> ./piHoleVersion
    echo "ftlVersion="$ftlVersion >> ./piHoleVersion
    echo "chronometer2Version="$chronometer2Version >> ./piHoleVersion

    # there's a file now
    # will check on next display
  fi
}

outputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw}}"
}

outputLogo() {
  echo -e "${redColor}.${yellowColor}-${greenColor}.${blueColor}.   ${greenColor}.      ${magentaColor}.      ${versionHeatmap}${versionStatus}${resetColor}"

  echo -e "${yellowColor}|${greenColor}-${blueColor}'${magentaColor}. ${yellowColor}- ${blueColor}|${magentaColor}-${redColor}. ${greenColor}.${blueColor}-${magentaColor}.${redColor}| ${greenColor}.${blueColor}-${magentaColor},  ${resetColor}Pi-hole ${piholeVersionHeatmap}v${piholeVersion}${resetColor}, Web ${webVersionHeatmap}v${webVersion}${resetColor}, FTL ${ftlVersionHeatmap}v${ftlVersion}${resetColor}"

  echo -e "${greenColor}'  ${redColor}'   ${magentaColor}' ${yellowColor}'${greenColor}-${blueColor}\`${magentaColor}-${redColor}'${yellowColor}'${greenColor}-${blueColor}\`${magentaColor}'${redColor}-  ${resetColor}Chronometer2 ${chronometer2VersionHeatmap}v${chronometer2Version}${resetColor}"

  echo ""
}

outputNetworkInformation() {
  echo "NETWORK ===================================================="
  printf " %-10s%-19s %-10s%-19s\n" "Hostname:" "$(hostname)" "Domain:" ${PIHOLE_DOMAIN}
  printf " %-10s%-19s\n" "IPv4:" "${IPV4_ADDRESS}"
  printf " %-10s%-19s\n" "IPv6:" "${IPV6_ADDRESS}"

  if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    printf " %-10s${dhcpHeatmap}%-19s${resetColor} %-10s${dhcpIPv6Heatmap}%-19s${resetColor}\n" "DHCP:" "${dhcpStatus}" "IPv6:" ${dhcpIPv6Status}
    printf "${dhcpInfo}\n"
  fi
}

outputPiholeInformation() {
  echo "PI-HOLE ===================================================="
  printf " %-10s${piHoleHeatmap}%-19s${resetColor} %-10s${ftlHeatmap}%-19s${resetColor}\n" "Status:" "${piHoleStatus}" "FTL:" "${ftlStatus}"
}

outputPiholeStats() {
  # Pi-Hole Information
  echo "STATS ======================================================"
  printf " %-10s%-49s\n" "Blocking:" "${domains_being_blocked} domains"
  printf " %-10s[%-40s] %-5s\n" "Pi-holed:" "${adsBlockedBar}" "${ads_percentage_today}%"
  printf " %-10s%-49s\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
  printf " %-10s%-39s\n" "Latest:" "${latestBlocked}"
  printf " %-10s%-39s\n" "Top Ad:" "${topBlocked}"
  if [[ "${DHCP_ACTIVE}" != "true" ]]; then
    printf " %-10s%-39s\n" "Top Dmn:" "${topDomain}"
    printf " %-10s%-39s\n" "Top Clnt:" "${topClient}"
  fi
}

outputSystemInformation() {
  # System Information
  echo "SYSTEM ====================================================="
  # Uptime
  printf " %-10s%-39s\n" "Uptime:" "${systemUptime}"

  # Temp and Loads
  printf " %-10s${tempHeatMap}%-19s${resetColor}" "CPU Temp:" "${temperature}"
  printf " %-10s${cpuLoad1Heatmap}%-4s${resetColor}, ${cpuLoad5Heatmap}%-4s${resetColor}, ${cpuLoad15Heatmap}%-4s${resetColor}\n" "CPU Load:" "${cpuLoad1}" "${cpuLoad5}" "${cpuLoad15}"

  # Memory and CPU bar
  printf " %-10s[${memoryHeatmap}%-10s${resetColor}] %-5s %-10s[${cpuLoad1Heatmap}%-10s${resetColor}] %-5s" "Memory:" "${memoryBar}" "${memoryUsedPercent}%" "CPU Load:" "${cpuBar}" "${cpuPercent}%"
}

normalChrono() {
  for (( ; ; )); do
    GetSummaryInformation

		latestBlocked=$(GetFTLData recentBlocked)
    topBlocked=$(GetFTLData "top-ads (1)" | awk '{print $3}')

    topDomain=$(GetFTLData "top-domains (1)" | awk '{print $3}')
    topClient=$(GetFTLData "top-clients (1)" | awk '{print $3}')

    clear

    # Get Config variables
    . /etc/pihole/setupVars.conf

    # Output everything to the screen
    outputLogo
    outputPiholeInformation
    outputPiholeStats
    outputNetworkInformation
    outputSystemInformation

    # Get our information
    GetSystemInformation
    GetPiholeInformation
    GetNetworkInformation
    GetVersionInformation


    sleep 5
  done
}

displayHelp() {
  cat << EOM
::: Displays stats about your piHole!
:::
::: Usage: sudo pihole -c [optional:-j]
::: Note: If no option is passed, then stats are displayed on screen, updated every 5 seconds
:::
::: Options:
:::  -j, --json    output stats as JSON formatted string
:::  -h, --help    display this help text
EOM
    exit 0
}

if [[ $# = 0 ]]; then

  # Turns off the cursor
  # (From Pull request #8 https://github.com/jpmck/chronometer2/pull/8)
  setterm -cursor off
  trap "{ setterm -cursor on ; echo "" ; exit 0 ; }" SIGINT SIGTERM EXIT

  clear

  # Nice logo
  echo -e " ${yellowColor}.${greenColor}-${blueColor}.                        .         ,${magentaColor}-${redColor}."
  echo -e "${yellowColor}(  ${magentaColor}|${redColor}-${yellowColor}. ${blueColor}.${magentaColor}-${redColor}.${yellowColor}.${greenColor}-${blueColor}.${magentaColor}.${redColor}-${yellowColor}.${greenColor}.${blueColor}-${magentaColor}.${redColor}.${yellowColor}-${greenColor}.${blueColor}-${magentaColor}.${redColor}.${yellowColor}-${greenColor},${blueColor}-${magentaColor}|${redColor}-${yellowColor}.${greenColor}-${blueColor},${magentaColor}.${redColor}-${yellowColor}.   ${redColor}/"
  echo -e " ${blueColor}\`${magentaColor}-${redColor}' ${greenColor}'${blueColor}-${magentaColor}'  ${greenColor}\`${blueColor}-${magentaColor}'${redColor}' ${greenColor}'${blueColor}\`${magentaColor}-${redColor}'${yellowColor}' ${blueColor}' ${redColor}'${yellowColor}\`${greenColor}'${blueColor}- ${redColor}'${yellowColor}-${greenColor}\`${blueColor}'${magentaColor}-${redColor}'    ${redColor}'${yellowColor}-${greenColor}-${resetColor}"
  echo ""

  # Get Our Config Values
  . /etc/pihole/setupVars.conf

  echo "START UP ==================================================="

  # Get PID of Chronometer2
  pid=$(echo $$)
  echo "- Writing PID (${pid}) to file..."
  echo ${pid} > ./chronometer2.pid

  # Check for updates
  echo "- Checking for Chronometer2 version file..."
  if [ -e "piHoleVersion" ]; then
    echo "  - Chronometer2 version file found... deleting."
    rm piHoleVersion
  else
    echo "  - Chronometer2 version file not found."
  fi

  # Get our information for the first time
  echo "- Gathering system information..."
  GetSystemInformation
  echo "- Gathering Pi-hole information..."
  GetPiholeInformation
  echo "- Gathering network information..."
  GetNetworkInformation
  echo "- Gathering version information..."
  GetVersionInformation
  echo "  - Pi-hole Core v$piholeVersion"
  echo "  - Web Admin v$webVersion"
  echo "  - FTL v$ftlVersion"
  echo "  - Chronometer2 v$chronometer2Version"
  echo "- Checking for update information..."
  GetVersionInformation
  echo "  - $versionStatus"
  echo ""
  printf "Chronometer2 will start in"

  for i in 3 2 1
  do
    printf " $i..."
    sleep 1
  done

  printf " now!"
  # Run Chronometer2
  normalChrono
fi

for var in "$@"; do
  case "$var" in
    "-j" | "--json"  ) outputJSON;;
    "-h" | "--help"  ) displayHelp;;
    *                ) exit 1;;
  esac
done
