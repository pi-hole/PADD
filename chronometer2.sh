#!/usr/bin/env bash
# Chronometer2
# A more advanced version of the chronometer provided with Pihole

#Functions#########################################################################################
piLog="/var/log/pihole.log"
gravity="/etc/pihole/gravity.list"

resetColor=$(tput setaf 7)

CalcBlockedDomains() {
  if [ -e "${gravity}" ]; then
    # if BOTH IPV4 and IPV6 are in use, then we need to divide total domains by 2.
    if [[ -n "${IPV4_ADDRESS}" && -n "${IPV6_ADDRESS}" ]]; then
      blockedDomainsTotal=$(wc -l /etc/pihole/gravity.list | awk '{print $1/2}')
    else
      # only one is set.
      blockedDomainsTotal=$(wc -l /etc/pihole/gravity.list | awk '{print $1}')
    fi
  else
    blockedDomainsTotal="Err."
  fi
}

CalcQueriesToday() {
  if [ -e "${piLog}" ]; then
    queriesToday=$(awk '/query\[/ {print $6}' < "${piLog}" | wc -l)
  else
    queriesToday="Err."
  fi
}

CalcblockedToday() {
  if [ -e "${piLog}" ] && [ -e "${gravity}" ];then
    blockedToday=$(awk '/\/etc\/pihole\/gravity.list/ && !/address/ {print $6}' < "${piLog}" | wc -l)
  else
    blockedToday="Err."
  fi
}

CalcPercentBlockedToday() {
  if [ "${queriesToday}" != "Err." ] && [ "${blockedToday}" != "Err." ]; then
    if [ "${queriesToday}" != 0 ]; then #Fixes divide by zero error :)
      #scale 2 rounds the number down, so we'll do scale 4 and then trim the last 2 zeros
      percentBlockedToday=$(echo "scale=4; ${blockedToday}/${queriesToday}*100" | bc)
      percentBlockedToday=$(sed 's/.\{2\}$//' <<< "${percentBlockedToday}")
    else
      percentBlockedToday=0
    fi
  fi
}

GetSystemInformation() {
  # System uptime
  systemUptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')

  # CPU temperature
  cpu=$(</sys/class/thermal/thermal_zone0/temp)

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" == "F" ]; then
    temperature=$(printf %.1f $(echo "scale=4; ${cpu}*9/5000+32" | bc))°F
  elif [ "${TEMPERATUREUNIT}" == "C" ]; then
    temperature=$(printf %.1f $(echo "scale=4; ${cpu}/1000" | bc))°C
  elif [ "${TEMPERATUREUNIT}" == "K" ]; then
    temperature=$(printf %.1f $(echo "scale=4; (${cpu}/1000+273.15)" | bc))°K
  fi

  # CPU load and heatmap calculations
  numProc=$(grep 'model name' /proc/cpuinfo | wc -l)

  cpuLoad1=$(cat /proc/loadavg | awk '{print $1}')
  cpuLoad1Heatmap=$(CPUHeatmapGenerator ${cpuLoad1} ${numProc})

  cpuLoad5=$(cat /proc/loadavg | awk '{print $2}')
  cpuLoad5Heatmap=$(CPUHeatmapGenerator ${cpuLoad5} ${numProc})

  cpuLoad15=$(cat /proc/loadavg | awk '{print $3}')
  cpuLoad15Heatmap=$(CPUHeatmapGenerator ${cpuLoad15} ${numProc})

  cpuPercent=$(printf %.1f $(echo "scale=4; (${cpuLoad1}/${numProc})*100" | bc))

  # Memory use
  memoryUsedPercent=$(free | grep Mem | awk '{printf "%.1f",($2-$4-$6-$7)/$2 * 100}')

  # CPU temperature heatmap
  if [ ${cpu} -gt 60000 ]; then
    tempHeatMap=$(tput setaf 1)
  else
    tempHeatMap=$(tput setaf 6)
  fi
}

CPUHeatmapGenerator () {
  x=$(echo "scale=2; ($1/$2)*100" | bc)
  load=$(printf "%.0f" "${x}")

  if [ ${load} -lt 75 ]; then
    out=$(tput setaf 2)
  elif [ ${load} -lt 90 ]; then
    out=$(tput setaf 3)
  else
    out=$(tput setaf 1)
  fi

  echo $out
}

GetPiholeInformation() {
  # Get Pi-hole status
  if [[ $(pihole status web) == 1 ]]; then
    piHoleStatus="Active"
    piHoleHeatmap=$(tput setaf 2)
  elif [[ $(pihole status web) == 0 ]]; then
    piHoleStatus="Offline"
    piHoleHeatmap=$(tput setaf 1)
  elif [[ $(pihole status web) == -1 ]]; then
    piHoleStatus="DNS Offline"
    piHoleHeatmap=$(tput setaf 1)
  else
    piHoleStatus="Unknown"
    piHoleHeatmap=$(tput setaf 3)
  fi

  # Pi-hole DHCP heatmap
  if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    dhcpStatus="Enabled"
    dhcpInfo="("${DHCP_START}" - "${DHCP_END}")"
    dhcpHeatmap=$(tput setaf 2) #green
  else
    dhcpStatus="Disabled"
    dhcpInfo=" (Router: "${DHCP_ROUTER}")"
    dhcpHeatmap=$(tput setaf 1) #red
  fi
}

GetPiholeVersionInformation() {
  # Today is...
  today=$(date +%Y%m%d)

  # Check if version status has been saved
  if [ -e "piHoleVersion" ]; then
    # the file exits, use it
    source piHoleVersion

    # Check if last check on version wasn't today...
    if [[ $today != $lastCheck ]]; then
      piholeVersion=$(pihole -v -p -c)
      webVersion=$(pihole -v -a -c)
      ftlVersion=$(/usr/bin/pihole-FTL version)

      piholeVersionLatest=$(pihole -v -p -l)
      webVersionLatest=$(pihole -v -a -l)

      # check if everything is up-to-date
      # if it's not up-to-date (i.e. out-of-date)
      if [ "${piholeVersion}" != "${piholeVersionLatest}" ] || [ "${webVersion}" != "${webVersionLatest}" ]; then
        # then write to the file that it's not
        echo "lastCheck="$(date +%Y%m%d) > ./piHoleVersion
        echo "piholeVersion="$piholeVersion >> ./piHoleVersion
        echo "webVersion="$webVersion >> ./piHoleVersion
        echo "ftlVersion="$(/usr/bin/pihole-FTL version) >> ./piHoleVersion
        echo -e "versionStatus=\"Pi-hole is out-of-date!\"" >> ./piHoleVersion
        echo -e "versionHeatmap="$(tput setaf 1) >> ./piHoleVersion

        versionStatus="Pi-hole is out-of-date!"
        versionHeatmap=$(tput setaf 1)
      else
        versionStatus="Pi-hole is up-to-date!"
        versionHeatmap=$(tput setaf 2)
      fi

    fi

  # else it dosn't exist
  else
    # We're using...
    piholeVersion=$(pihole -v -p -c)
    webVersion=$(pihole -v -a -c)
    ftlVersion=$(/usr/bin/pihole-FTL version)

    piholeVersionLatest=$(pihole -v -p -l)
    webVersionLatest=$(pihole -v -a -l)

    echo "lastCheck="$(date +%Y%m%d) > ./piHoleVersion
    echo "piholeVersion="$piholeVersion >> ./piHoleVersion
    echo "webVersion="$webVersion >> ./piHoleVersion
    echo "ftlVersion="$(/usr/bin/pihole-FTL version) >> ./piHoleVersion

    # Check if either isn't up-to-date
    if [ "${piholeVersion}" != "${piholeVersionLatest}" ] || [ "${webVersion}" != "${webVersionLatest}" ]; then
      echo -e "versionStatus=\"Pi-hole is out-of-date!\"" >> ./piHoleVersion
      echo -e "versionHeatmap="$(tput setaf 1) >> ./piHoleVersion
      versionStatus="Pi-hole is out-of-date!"
      versionHeatmap=$(tput setaf 1)
    else
      echo -e "versionStatus=\"Pi-hole is up-to-date!\"" >> ./piHoleVersion
      echo -e "versionHeatmap="$(tput setaf 2) >> ./piHoleVersion
      versionStatus="Pi-hole is up-to-date!"
      versionHeatmap=$(tput setaf 2)
    fi
  fi

}

outputJSON() {
  CalcQueriesToday
  CalcblockedToday
  CalcPercentBlockedToday

  CalcBlockedDomains

  printf '{"domains_being_blocked":"%s","dns_queries_today":"%s","ads_blocked_today":"%s","ads_percentage_today":"%s"}\n' "$blockedDomainsTotal" "$queriesToday" "$blockedToday" "$percentBlockedToday"
}

outputLogo() {
  # Displays a colorful Pi-hole logo
  echo " [0;1;35;95m_[0;1;31;91m__[0m [0;1;33;93m_[0m     [0;1;34;94m_[0m        [0;1;36;96m_[0m         ${versionHeatmap}${versionStatus}"
  echo -e "[0;1;31;91m|[0m [0;1;33;93m_[0m [0;1;32;92m(_[0;1;36;96m)_[0;1;34;94m__[0;1;35;95m|[0m [0;1;31;91m|_[0m  [0;1;32;92m__[0;1;36;96m_|[0m [0;1;34;94m|[0;1;35;95m__[0;1;31;91m_[0m     Pi-hole ${piholeVersion}"
  echo "[0;1;33;93m|[0m  [0;1;32;92m_[0;1;36;96m/[0m [0;1;34;94m|_[0;1;35;95m__[0;1;31;91m|[0m [0;1;33;93m'[0m [0;1;32;92m\/[0m [0;1;36;96m_[0m [0;1;34;94m\[0m [0;1;35;95m/[0m [0;1;31;91m-[0;1;33;93m_)[0m    Pi-hole Web-Admin ${webVersion}"
  echo "[0;1;32;92m|_[0;1;36;96m|[0m [0;1;34;94m|_[0;1;35;95m|[0m   [0;1;33;93m|_[0;1;32;92m||[0;1;36;96m_\[0;1;34;94m__[0;1;35;95m_/[0;1;31;91m_\[0;1;33;93m__[0;1;32;92m_|[0m    FTL ${ftlVersion}"
  echo ""
}

outputNetworkInformation() {
  # Network Information
  echo "NETWORK ===================================================="
  printf " %-10s%-19s\n" "Gateway:" "$(ip route show default | awk '/default/ {print $3}')"
  printf " %-10s%-19s\n" "IPv4:" "${IPV4_ADDRESS}"
  printf " %-10s%-19s\n" "IPv6:" "${IPV6_ADDRESS}"
  printf " %-10s${dhcpHeatmap}%-8s${resetColor}%-30s\n" "DHCP:" "${dhcpStatus}" "${dhcpInfo}"
}

outputPiholeInformation() {
  # Pi-Hole Information
  echo "PI-HOLE ===================================================="
  printf " %-10s${piHoleHeatmap}%-19s${resetColor}%-10s%-19s\n" "Status:" "${piHoleStatus}" "Blocking:" "${blockedDomainsTotal}"
  printf " %-10s%-19s%-10s%-19s\n" "Queries:" "${queriesToday}" "Pi-holed:" "${blockedToday} (${percentBlockedToday}%)"
  printf " %-10s%-19s%-10s%-19s\n" "DNS 1:" "${PIHOLE_DNS_1}" "DNS 2:" "${PIHOLE_DNS_2}"
}

outputSystemInformation() {
  # System Information
  echo "SYSTEM ====================================================="
  printf " %-10s%-19s\n" "Hostname:" "$(hostname)"
  printf " %-10s%-19s\n" "Uptime:" "${systemUptime}"
  printf " %-10s${tempHeatMap}%-19s${resetColor}" "CPU Temp:" "${temperature}"
  printf " %-10s${cpuLoad1Heatmap}%-4s${resetColor}, ${cpuLoad5Heatmap}%-4s${resetColor}, ${cpuLoad15Heatmap}%-4s${resetColor}\n" "CPU Load:" "${cpuLoad1}" "${cpuLoad5}" "${cpuLoad15}"
  printf " %-10s%-19s%-10s${cpuLoad1Heatmap}%-19s${resetColor}\n" "Memory:" "${memoryUsedPercent}%" "CPU Load:" "${cpuPercent}%"
}

normalChrono() {
  for (( ; ; )); do
    clear

    # Get Our Config Values
    . /etc/pihole/setupVars.conf

    #Do Our Calculations
    CalcQueriesToday
    CalcblockedToday
    CalcPercentBlockedToday
    CalcBlockedDomains

    # Get our information
    GetSystemInformation
    GetPiholeInformation
    GetPiholeVersionInformation

    outputLogo
    outputPiholeInformation
    outputNetworkInformation
    outputSystemInformation

    echo ""
    printf "              \e[2mPress ^C to quit chronometer\e[0m"

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
  normalChrono
fi

for var in "$@"; do
  case "$var" in
    "-j" | "--json"  ) outputJSON;;
    "-h" | "--help"  ) displayHelp;;
    *                ) exit 1;;
  esac
done
