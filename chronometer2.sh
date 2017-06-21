#!/usr/bin/env bash
# Chronometer2
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
# Addresses Issue 5: https://github.com/jpmck/chronometer2/issues/5 ... I think...
export LC_ALL=C.UTF-8

chronometer2Version="1.2.0"

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
  local summary
  summary=$(GetFTLData "stats")
  domains_being_blocked_raw=$(grep "domains_being_blocked" <<< "${summary}" | grep -Eo "[0-9]+$")
  domains_being_blocked=$(printf "%'.f" ${domains_being_blocked_raw})
  dns_queries_today_raw=$(grep "dns_queries_today" <<< "$summary" | grep -Eo "[0-9]+$")
  dns_queries_today=$(printf "%'.f" ${dns_queries_today_raw})
  ads_blocked_today_raw=$(grep "ads_blocked_today" <<< "$summary" | grep -Eo "[0-9]+$")
  ads_blocked_today=$(printf "%'.f" ${ads_blocked_today_raw})
  ads_percentage_today_raw=$(grep "ads_percentage_today" <<< "$summary" | grep -Eo "[0-9.]+$")
  LC_NUMERIC=C ads_percentage_today=$(printf "%'.f" ${ads_percentage_today_raw})
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

  # CPU load and heatmap calculations
  cpuLoad1=$(cat /proc/loadavg | awk '{print $1}')
  cpuLoad1Heatmap=$(CPUHeatmapGenerator ${cpuLoad1} ${numProc})

  cpuLoad5=$(cat /proc/loadavg | awk '{print $2}')
  cpuLoad5Heatmap=$(CPUHeatmapGenerator ${cpuLoad5} ${numProc})

  cpuLoad15=$(cat /proc/loadavg | awk '{print $3}')
  cpuLoad15Heatmap=$(CPUHeatmapGenerator ${cpuLoad15} ${numProc})

  cpuPercent=$(printf %.1f "$(echo "scale=4; (${cpuLoad1}/${numProc})*100" | bc)")

  # Memory use
  memoryUsedPercent=$(free | awk '/Mem/ {printf "%.1f",($2-$4-$6-$7)/$2 * 100}')

  # CPU temperature heatmap
  if [ ${cpu} -gt 60000 ]; then
    tempHeatMap=${redColor}
  else
    tempHeatMap=${blueColor}
  fi
}

CPUHeatmapGenerator () {
  x=$(echo "scale=2; ($1/$2)*100" | bc)
  load=$(printf "%.0f" "${x}")

  if [ ${load} -lt 75 ]; then
    out=${greenColor}
  elif [ ${load} -lt 90 ]; then
    out=${yellowColor}
  else
    out=${redColor}
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
    # Addresses Issue 3: https://github.com/jpmck/chronometer2/issues/3
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

outputDHCPInformation() {
  echo "DHCP SERVER ================================================"
  printf " %-10s${dhcpHeatmap}%-19s${resetColor}%-10s${dhcpIPv6Heatmap}%-19s${resetColor}\n" "Status:" "${dhcpStatus}" "IPv6:" ${dhcpIPv6Status}
  printf "${dhcpInfo}\n"
}

outputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw}}"
}

outputLogo() {
  echo -e "${redColor}.${yellowColor}-${greenColor}.${blueColor}.   ${greenColor}.      ${magentaColor}.      ${versionHeatmap}${versionStatus}${resetColor}"

  echo -e "${yellowColor}|${greenColor}-${blueColor}'${magentaColor}. ${yellowColor}- ${blueColor}|${magentaColor}-${redColor}. ${greenColor}.${blueColor}-${magentaColor}.${redColor}| ${greenColor}.${blueColor}-${magentaColor},  ${resetColor}Pi-hole ${piholeVersionHeatmap}v${piholeVersion}${resetColor}, Web ${webVersionHeatmap}v${webVersion}${resetColor}, FTL ${ftlVersionHeatmap}v${ftlVersion}${resetColor}"

  echo -e "${greenColor}'  ${redColor}'   ${magentaColor}' ${yellowColor}'${greenColor}-${blueColor}\`${magentaColor}-${redColor}'${yellowColor}'${greenColor}-${blueColor}\`${magentaColor}'${redColor}-  ${resetColor}Chronometer2 ${chronometer2VersionHeatmap}v${chronometer2Version}${resetColor}"


  # echo " [0;1;35;95m_[0;1;31;91m__[0m [0;1;33;93m_[0m     [0;1;34;94m_[0m        [0;1;36;96m_[0m"
  # echo -e "[0;1;31;91m|[0m [0;1;33;93m_[0m [0;1;32;92m(_[0;1;36;96m)_[0;1;34;94m__[0;1;35;95m|[0m [0;1;31;91m|_[0m  [0;1;32;92m__[0;1;36;96m_|[0m [0;1;34;94m|[0;1;35;95m__[0;1;31;91m_[0m     ${versionHeatmap}${versionStatus}"
  # echo "[0;1;33;93m|[0m  [0;1;32;92m_[0;1;36;96m/[0m [0;1;34;94m|_[0;1;35;95m__[0;1;31;91m|[0m [0;1;33;93m'[0m [0;1;32;92m\/[0m [0;1;36;96m_[0m [0;1;34;94m\[0m [0;1;35;95m/[0m [0;1;31;91m-[0;1;33;93m_)[0m${resetColor}    Pi-hole Core ${piholeVersionHeatmap}v${piholeVersion}${resetColor}"
  # echo "[0;1;32;92m|_[0;1;36;96m|[0m [0;1;34;94m|_[0;1;35;95m|[0m   [0;1;33;93m|_[0;1;32;92m||[0;1;36;96m_\[0;1;34;94m__[0;1;35;95m_/[0;1;31;91m_\[0;1;33;93m__[0;1;32;92m_|[0m${resetColor}    (Web ${webVersionHeatmap}v${webVersion}${resetColor}, FTL ${ftlVersionHeatmap}v${ftlVersion}${resetColor})"
  echo ""
}

outputNetworkInformation() {
  echo "NETWORK ===================================================="
  printf " %-10s%-19s%-10s%-19s\n" "Hostname:" "$(hostname)" "Domain:" ${PIHOLE_DOMAIN}
  printf " %-10s%-19s\n" "IPv4:" "${IPV4_ADDRESS}"
  printf " %-10s%-19s\n" "IPv6:" "${IPV6_ADDRESS}"
}

outputPiholeInformation() {
  echo "PI-HOLE ===================================================="
  printf " %-10s${piHoleHeatmap}%-19s${resetColor}%-10s${ftlHeatmap}%-19s${resetColor}\n" "Status:" "${piHoleStatus}" "FTL:" "${ftlStatus}"
}

outputPiholeStats() {
  # Pi-Hole Information
  echo "STATS ======================================================"
  printf " %-10s%0.0f\n" "Blocking:" "${domains_being_blocked}"
  printf " %-10s%-19s%-10s%-19s\n" "Queries:" "${dns_queries_today}" "Pi-holed:" "${ads_blocked_today} (${ads_percentage_today}%)"
  printf " %-10s%-39s\n" "Latest:" "${domain}"
}

outputSystemInformation() {
  # System Information
  echo "SYSTEM ====================================================="
  printf " %-10s%-19s\n" "Uptime:" "${systemUptime}"
  printf " %-10s${tempHeatMap}%-19s${resetColor}" "CPU Temp:" "${temperature}"
  printf " %-10s${cpuLoad1Heatmap}%-4s${resetColor}, ${cpuLoad5Heatmap}%-4s${resetColor}, ${cpuLoad15Heatmap}%-4s${resetColor}\n" "CPU Load:" "${cpuLoad1}" "${cpuLoad5}" "${cpuLoad15}"
  printf " %-10s%-19s%-10s${cpuLoad1Heatmap}%-19s${resetColor}" "Memory:" "${memoryUsedPercent}%" "CPU Load:" "${cpuPercent}%"
}

normalChrono() {
  for (( ; ; )); do
    GetSummaryInformation
		domain=$(GetFTLData recentBlocked)
    clear

    # Get Config variables
    . /etc/pihole/setupVars.conf

    # Output everything to the screen
    outputLogo
    outputPiholeInformation
    outputPiholeStats
    outputNetworkInformation
    outputDHCPInformation
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
  clear

  # Nice logo
  echo -e " ${yellowColor}.${greenColor}-${blueColor}.                        .         ,${magentaColor}-${redColor}."
  echo -e "${yellowColor}(  ${magentaColor}|${redColor}-${yellowColor}. ${blueColor}.${magentaColor}-${redColor}.${yellowColor}.${greenColor}-${blueColor}.${magentaColor}.${redColor}-${yellowColor}.${greenColor}.${blueColor}-${magentaColor}.${redColor}.${yellowColor}-${greenColor}.${blueColor}-${magentaColor}.${redColor}.${yellowColor}-${greenColor},${blueColor}-${magentaColor}|${redColor}-${yellowColor}.${greenColor}-${blueColor},${magentaColor}.${redColor}-${yellowColor}.   ${redColor}/"
  echo -e " ${blueColor}\`${magentaColor}-${redColor}' ${greenColor}'${blueColor}-${magentaColor}'  ${greenColor}\`${blueColor}-${magentaColor}'${redColor}' ${greenColor}'${blueColor}\`${magentaColor}-${redColor}'${yellowColor}' ${blueColor}' ${redColor}'${yellowColor}\`${greenColor}'${blueColor}- ${redColor}'${yellowColor}-${greenColor}\`${blueColor}'${magentaColor}-${redColor}'    ${redColor}'${yellowColor}-${greenColor}-${resetColor}"
  echo ""

  # Get Our Config Values
  . /etc/pihole/setupVars.conf

  echo "START UP===================================================="
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

  for i in 5 4 3 2 1
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
