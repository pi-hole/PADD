#!/usr/bin/env bash
# shellcheck disable=SC2034

# PADD
#
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
# Issue 5: https://github.com/jpmck/PADD/issues/5
# Updated to en_US to support
export LC_ALL=en_US.UTF-8 > /dev/null 2>&1 || export LC_ALL=en_GB.UTF-8 > /dev/null 2>&1 || export LC_ALL=C.UTF-8 > /dev/null 2>&1

############################################ VARIABLES #############################################

# VERSION
PADDVersion="2.0.0"

# DATE
today=$(date +%Y%m%d)

# CORES
coreCount=$(grep -c 'model name' /proc/cpuinfo)

# COLORS
blackText=$(tput setaf 0)   # Black
redText=$(tput setaf 1)     # Red
greenText=$(tput setaf 2)   # Green
yellowText=$(tput setaf 3)  # Yellow
blueText=$(tput setaf 4)    # Blue
magentaText=$(tput setaf 5) # Magenta
cyanText=$(tput setaf 6)    # Cyan
whiteText=$(tput setaf 7)   # White
resetText=$(tput sgr0)      # Reset to default color

# STYLES
boldText=$(tput bold)
blinkingText=$(tput blink)
dimText=$(tput dim)

# CHECK BOXES
checkBoxGood="[${greenText}✓${resetText}]"       # Good
checkBoxBad="[${redText}✗${resetText}]"          # Bad
checkBoxQuestion="[${yellowText}?${resetText}]"  # Question / ?
checkBoxInfo="[${yellowText}i${resetText}]"      # Info / i

# PICO STATUSES
picoStatusOk="${checkBoxGood} Sys. OK"
picoStatusUpdate="${checkBoxInfo} Update"
picoStatusHot="${checkBoxBad} Sys. Hot!"
picoStatusOff="${checkBoxBad} Offline"
picoStatusFTLDown="${checkBoxInfo} FTL"
picoStatusDNSDown="${checkBoxBad} DNS"
picoStatusUnknown="${checkBoxQuestion} Stat. Unk."

# MINI STATUS
miniStatusOk="${checkBoxGood} System OK"
miniStatusUpdate="${checkBoxInfo} Update avail."
miniStatusHot="${checkBoxBad} Hot Pi!"
miniStatusOff="${checkBoxBad} Pi-hole off!"
miniStatusFTLDown="${checkBoxInfo} FTL down!"
miniStatusDNSDown="${checkBoxBad} DNS off!"
miniStatusUnknown="${checkBoxQuestion} Status unknown!"

# Text only "logos"
PADDText="${greenText}${boldText}PADD${resetText}"
PADDTextRetro="${boldText}${redText}P${yellowText}A${greenText}D${blueText}D${resetText}${resetText}"
miniTextRetro="${dimText}${cyanText}m${magentaText}i${redText}n${yellowText}i${resetText}"

# PADD logos - regular and retro
PADDLogo1="${boldText}${greenText} __      __  __   ${resetText}"
PADDLogo2="${boldText}${greenText}|__) /\ |  \|  \  ${resetText}"
PADDLogo3="${boldText}${greenText}|   /--\|__/|__/  ${resetText}"
PADDLogoRetro1="${boldText} ${yellowText}_${greenText}_      ${blueText}_   ${yellowText}_${greenText}_   ${resetText}"
PADDLogoRetro2="${boldText}${yellowText}|${greenText}_${blueText}_${cyanText}) ${redText}/${yellowText}\ ${blueText}|  ${redText}\\${yellowText}|  ${cyanText}\  ${resetText}"
PADDLogoRetro3="${boldText}${greenText}|   ${redText}/${yellowText}-${greenText}-${blueText}\\${cyanText}|${magentaText}_${redText}_${yellowText}/${greenText}|${blueText}_${cyanText}_${magentaText}/  ${resetText}"

# old script Pi-hole logos - regular and retro
PiholeLogoScript1="${boldText}${greenText}.-..   .      .      ${resetText}"
PiholeLogoScript2="${boldText}${greenText}|-'. - |-. .-.| .-,  ${resetText}"
PiholeLogoScript3="${boldText}${greenText}'  '   ' '-\`-''-\`'-  ${resetText}"
PiholeLogoScriptRetro1="${redText}.${yellowText}-${greenText}.${blueText}.   ${greenText}.      ${magentaText}.      ${resetText}"
PiholeLogoScriptRetro2="${yellowText}|${greenText}-${blueText}'${magentaText}. ${yellowText}- ${blueText}|${magentaText}-${redText}. ${greenText}.${blueText}-${magentaText}.${redText}| ${greenText}.${blueText}-${magentaText},  ${resetText}"
PiholeLogoScriptRetro3="${greenText}'  ${redText}'   ${magentaText}' ${yellowText}'${greenText}-${blueText}\`${magentaText}-${redText}'${yellowText}'${greenText}-${blueText}\`${magentaText}'${redText}-  ${resetText}"

############################################# GETTERS ##############################################

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

  if [ "$1" = "mini" ]; then
    adsBlockedBar=$(BarGenerator $ads_percentage_today 10 "color")
  else
    adsBlockedBar=$(BarGenerator $ads_percentage_today 40 "color")
  fi
}

GetSystemInformation() {
  # System uptime
  if [ "$1" = "mini" ]; then
    systemUptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours"}')
  else
    systemUptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')
  fi

  # CPU temperature
  cpu=$(</sys/class/thermal/thermal_zone0/temp)

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" == "F" ]; then
    temperature=$(printf %.1f "$(echo "scale=4; ${cpu}*9/5000+32" | bc)")°F
  elif [ "${TEMPERATUREUNIT}" == "K" ]; then
    temperature=$(printf %.1f "$(echo "scale=4; (${cpu}/1000+273.15)" | bc)")°K
  # Addresses Issue 1: https://github.com/jpmck/PADD/issues/1
  else
    temperature=$(printf %.1f "$(echo "scale=4; ${cpu}/1000" | bc)")°C
  fi

  # CPU load, heatmap and bar
  cpuLoad1=$(cat /proc/loadavg | awk '{print $1}')
  cpuLoad1Heatmap=$(HeatmapGenerator ${cpuLoad1} ${coreCount})
  cpuLoad5=$(cat /proc/loadavg | awk '{print $2}')
  cpuLoad5Heatmap=$(HeatmapGenerator ${cpuLoad5} ${coreCount})
  cpuLoad15=$(cat /proc/loadavg | awk '{print $3}')
  cpuLoad15Heatmap=$(HeatmapGenerator ${cpuLoad15} ${coreCount})
  cpuPercent=$(printf %.1f "$(echo "scale=4; (${cpuLoad1}/${coreCount})*100" | bc)")
  cpuBar=$(BarGenerator ${cpuPercent} 10)

  # CPU temperature heatmap
  # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)
  if [ ${cpu} -gt 80000 ]; then
    tempHeatMap=${blinkingText}${redText}
    picoStatus="${miniStatusHot}"
    miniStatus="${miniStatusHot} ${blinkingText}${redText}${temperature}${resetText}"
  elif [ ${cpu} -gt 70000 ]; then
    tempHeatMap=${magentaText}
  elif [ ${cpu} -gt 60000 ]; then
    tempHeatMap=${blueText}
  else
    tempHeatMap=${cyanText}
  fi

  # Memory use, heatmap and bar
  memoryUsedPercent=$(awk '/MemTotal:/{total=$2} /MemFree:/{free=$2} /Buffers:/{buffers=$2} /^Cached:/{cached=$2} END {printf "%.1f", (total-free-buffers-cached)*100/total}' '/proc/meminfo')
  memoryHeatmap=$(HeatmapGenerator ${memoryUsedPercent})
  memoryBar=$(BarGenerator ${memoryUsedPercent} 10)
}

GetNetworkInformation() {
  # Get pi IP address
  piIPAddress=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
  # Get hostname information
  piHostname=$(hostname)
  # does the Pi-hole have a domain set?
  if [ -z ${PIHOLE_DOMAIN+x} ]; then
    fullHostname=${piHostname}
  else
    count=${piHostname}"."${PIHOLE_DOMAIN}
    count=${#count}

    if [ "${count}" -lt "18" ]; then
      fullHostname="${piHostname}${dimText}.${PIHOLE_DOMAIN}${resetText}  "
    else
      fullHostname=${piHostname}
    fi
  fi

  # Get the DNS count (from pihole -c)
  dnsCount="0"
  [[ -n "${PIHOLE_DNS_1}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_2}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_3}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_4}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_5}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_6}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_7}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_8}" ]] && dnsCount=$((dnsCount+1))
  [[ -n "${PIHOLE_DNS_9}" ]] && dnsCount="$dnsCount+"

  # Is Pi-Hole acting as the DHCP server?
  if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    dhcpStatus="Enabled"
    dhcpInfo=" Range:    ${DHCP_START} - ${DHCP_END}"
    dhcpHeatmap=${greenText}
    dhcpCheckBox=${checkBoxGood}

    # Is DHCP handling IPv6?
    if [[ "${DHCP_IPv6}" == "true" ]]; then
      dhcpIPv6Status="Enabled"
      dhcpIPv6Heatmap=${greenText}
      dhcpIPv6CheckBox=${checkBoxGood}
    else
      dhcpIPv6Status="Disabled"
      dhcpIPv6Heatmap=${redText}
      dhcpIPv6CheckBox=${checkBoxBad}
    fi
  else
    dhcpStatus="Disabled"
    dhcpHeatmap=${redText}
    dhcpCheckBox=${checkBoxBad}

    # if the DHCP Router variable isn't set
    # Issue 3: https://github.com/jpmck/PADD/issues/3
    if [ -z ${DHCP_ROUTER+x} ]; then
      DHCP_ROUTER=$(/sbin/ip route | awk '/default/ { print $3 }')
    fi

    dhcpInfo=" Router:   ${DHCP_ROUTER}"
    dhcpHeatmap=${redText}
    dhcpCheckBox=${checkBoxBad}

    dhcpIPv6Status="N/A"
    dhcpIPv6Heatmap=${yellowText}
    dhcpIPv6CheckBox=${checkBoxQuestion}
  fi

  # DNSSEC
  if [[ "${DNSSEC}" == "true" ]]; then
    dnssecStatus="Enabled"
    dnssecHeatmap=${greenText}
    dnssecCheckBox=${checkBoxGood}
  else
    dnssecStatus="Disabled"
    dnssecHeatmap=${redText}
    dnssecCheckBox=${checkBoxBad}
  fi
}

GetPiholeInformation() {
  # Get Pi-hole status
  if [[ $(pihole status web) == 1 ]]; then
    piHoleStatus="Active"
    piHoleHeatmap=${greenText}
    piHoleCheckBox=${checkBoxGood}
  elif [[ $(pihole status web) == 0 ]]; then
    piHoleStatus="Offline"
    piHoleHeatmap=${redText}
    piHoleCheckBox=${checkBoxBad}
    picoStatus=${picoStatusOff}
    miniStatus=${miniStatusOff}
  elif [[ $(pihole status web) == -1 ]]; then
    piHoleStatus="DNS Offline"
    piHoleHeatmap=${redText}
    piHoleCheckBox=${checkBoxBad}
    picoStatus=${picoStatusDNSDown}
    miniStatus=${miniStatusDNSDown}
  else
    piHoleStatus="Unknown"
    piHoleHeatmap=${yellowText}
    piHoleCheckBox=${checkBoxQuestion}
    picoStatus${picoStatusUnknown}
    miniStatus${miniStatusUnknown}
  fi

  # Get FTL status
  ftlPID=$(pidof pihole-FTL)

  if [ -z ${ftlPID+x} ]; then
    ftlStatus="Not running"
    ftlHeatmap=${yellowText}
    ftlCheckBox=${informationCheckBox}
    picoStatus=${picoStatusFTLDown}
    miniStatus=${miniStatusFTLDown}
  else
    ftlStatus="Running"
    ftlHeatmap=${greenText}
    ftlCheckBox=${checkBoxGood}
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
        PADDVersionLatest=$(curl -sI https://github.com/jpmck/PADD/releases/latest | grep 'Location' | awk -F '/' '{print $NF}' | tr -d '\r\n[:alpha:]')

      # check if everything is up-to-date...
      # is core up-to-date?
      if [[ "${piholeVersion}" != "${piholeVersionLatest}" ]]; then
        outOfDateFlag="true"
        piholeVersionHeatmap=${redText}
      else
        piholeVersionHeatmap=${greenText}
      fi

      # is web up-to-date?
      if [[ "${webVersion}" != "${webVersionLatest}" ]]; then
        outOfDateFlag="true"
        webVersionHeatmap=${redText}
      else
        webVersionHeatmap=${greenText}
      fi

      # is ftl up-to-date?
      if [[ "${ftlVersion}" != "${ftlVersionLatest}" ]]; then
        outOfDateFlag="true"
        ftlVersionHeatmap=${redText}
      else
        ftlVersionHeatmap=${greenText}
      fi

      # is PADD up-to-date?
      if [[ "${PADDVersion}" != "${PADDVersionLatest}" ]]; then
        PADDOutOfDateFlag="true"
        PADDVersionHeatmap=${redText}
      else
        PADDVersionHeatmap=${greenText}
      fi

      # was any portion of Pi-hole out-of-date?
      # yes, pi-hole is out of date
      if [[ "${outOfDateFlag}" == "true" ]]; then
        versionStatus="Pi-hole is out-of-date!"
        versionHeatmap=${redText}
        versionCheckBox=${checkBoxBad}
        picoStatus=${picoStatusUpdate}
        miniStatus=${miniStatusUpdate}
      else
        # but is PADD out-of-date?
        if [[ "${PADDOutOfDateFlag}" == "true" ]]; then
          versionStatus="PADD is out-of-date!"
          versionHeatmap=${redText}
          versionCheckBox=${checkBoxBad}
          picoStatus=${picoStatusUpdate}
          miniStatus=${miniStatusUpdate}
        # else, everything is good!
        else
          versionStatus="Pi-hole is up-to-date!"
          versionHeatmap=${greenText}
          versionCheckBox=${checkBoxGood}
          picoStatus=${picoStatusOk}
          miniStatus=${miniStatusOk}
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

      echo "PADDVersion="$PADDVersion >> ./piHoleVersion
      echo "PADDVersionHeatmap="$PADDVersionHeatmap >> ./piHoleVersion

      echo "versionStatus="\"$versionStatus\" >> ./piHoleVersion
      echo "versionHeatmap="$versionHeatmap >> ./piHoleVersion
      echo "versionCheckBox="\"$versionCheckBox\" >> ./piHoleVersion

      echo "picoStatus="\"$picoStatus\" >> ./piHoleVersion
      echo "miniStatus="\"$miniStatus\" >> ./piHoleVersion

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
    echo "PADDVersion="$PADDVersion >> ./piHoleVersion

    # there's a file now
    # will check on next display
  fi
}

############################################# PRINTERS #############################################

PrintLogo() {
  # Screen size checks
  if [ "$1" = "pico" ]; then
    echo -e "p${PADDText} ${picoStatus}"
  elif [ "$1" = "nano" ]; then
    echo -e "n${PADDText} ${miniStatus}"
  elif [ "$1" = "micro" ]; then
    echo -e "µ${PADDText}     ${miniStatus}\n"
  elif [ "$1" = "mini" ]; then
    echo -e "${PADDText}${dimText}mini${resetText}  ${miniStatus}\n"
  elif [ "$1" = "slim" ]; then
    echo -e "${PADDText}${dimText}slim${resetText}   ${miniStatus}\n"
  # normal or not defined
  else
    echo -e "${PADDLogo1}"
    echo -e "${PADDLogo2}Pi-hole® ${piholeVersionHeatmap}v${piholeVersion}${resetText}, Web ${webVersionHeatmap}v${webVersion}${resetText}, FTL ${ftlVersionHeatmap}v${ftlVersion}${resetText}"
    echo -e "${PADDLogo3}PADD ${PADDVersionHeatmap}v${PADDVersion}${resetText} ${versionHeatmap}${versionStatus}${resetText}"

    echo ""
  fi
}

PrintNetworkInformation() {
  if [ "$1" = "pico" ]; then
    echo "${boldText}NETWORK ============${resetText}"
    echo -e " Hst: ${piHostname}"
    echo -e " IP:  ${piIPAddress}"
    echo -e " DHCP ${dhcpCheckBox} IPv6 ${dhcpIPv6CheckBox}"
  elif [ "$1" = "nano" ]; then
    echo "${boldText}NETWORK ================${resetText}"
    echo -e " Host: ${piHostname}"
    echo -e " IPv4: ${IPV4_ADDRESS}"
    echo -e " DHCP: ${dhcpCheckBox}    IPv6: ${dhcpIPv6CheckBox}"
  elif [ "$1" = "micro" ]; then
    echo "${boldText}NETWORK ======================${resetText}"
    echo -e " Host:    ${fullHostname}"
    echo -e " IPv4:    ${IPV4_ADDRESS}"
    echo -e " DHCP:    ${dhcpCheckBox}     IPv6:  ${dhcpIPv6CheckBox}"
  elif [ "$1" = "mini" ]; then
    echo "${boldText}NETWORK ================================${resetText}"
    printf " %-9s%-19s\n" "Host:" "${fullHostname}"
    printf " %-9s%-19s\n" "IPv4:" "${IPV4_ADDRESS}"
    printf " %-9s%-10s %-9s%-10s\n" "DNS:" "${dnsCount} servers" "DNSSEC:" "${dnssecHeatmap}${dnssecStatus}${resetText}"

    if [[ "${DHCP_ACTIVE}" == "true" ]]; then
      printf " %-9s${dhcpHeatmap}%-10s${resetText} %-9s${dhcpIPv6Heatmap}%-10s${resetText}\n" "DHCP:" "${dhcpStatus}" "IPv6:" ${dhcpIPv6Status}
    fi
  # else we're not
  else
    echo "${boldText}NETWORK ====================================================${resetText}"
    printf " %-10s%-19s %-10s%-19s\n" "Hostname:" "${fullHostname}" "IPv4:" "${IPV4_ADDRESS}"
    printf " %-10s%-19s\n" "IPv6:" "${IPV6_ADDRESS}"
    printf " %-10s%-19s %-10s%-19s\n" "DNS:" "${dnsCount} DNS servers" "DNSSEC:" "${dnssecHeatmap}${dnssecStatus}${resetText}"

    if [[ "${DHCP_ACTIVE}" == "true" ]]; then
      printf " %-10s${dhcpHeatmap}%-19s${resetText} %-10s${dhcpIPv6Heatmap}%-19s${resetText}\n" "DHCP:" "${dhcpStatus}" "IPv6:" ${dhcpIPv6Status}
      printf "${dhcpInfo}\n"
    fi
  fi
}

PrintPiholeInformation() {
  # size checks
  if [ "$1" = "pico" ]; then
    :
  elif [ "$1" = "nano" ]; then
    echo "${boldText}PI-HOLE ================${resetText}"
    echo -e " Up:  ${piHoleCheckBox}      FTL: ${ftlCheckBox}"
  elif [ "$1" = "micro" ]; then
    echo "${boldText}PI-HOLE ======================${resetText}"
    echo -e " Status:  ${piHoleCheckBox}      FTL:  ${ftlCheckBox}"
  elif [ "$1" = "mini" ]; then
    echo "${boldText}PI-HOLE ================================${resetText}"
    printf " %-9s${piHoleHeatmap}%-10s${resetText} %-9s${ftlHeatmap}%-10s${resetText}\n" "Status:" "${piHoleStatus}" "FTL:" "${ftlStatus}"
  else
    echo "${boldText}PI-HOLE ====================================================${resetText}"
    printf " %-10s${piHoleHeatmap}%-19s${resetText} %-10s${ftlHeatmap}%-19s${resetText}\n" "Status:" "${piHoleStatus}" "FTL:" "${ftlStatus}"
  fi
}

PrintPiholeStats() {
  # are we on a tiny screen?
  if [ "$1" = "pico" ]; then
    echo "${boldText}PI-HOLE ============${resetText}"
    echo -e " [${adsBlockedBar}] ${ads_percentage_today}%"
    echo -e " ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "nano" ]; then
    echo -e " Blk: [${adsBlockedBar}] ${ads_percentage_today}%"
    echo -e " Blk: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "micro" ]; then
    echo "${boldText}STATS ========================${resetText}"
    echo -e " Blckng:  ${domains_being_blocked} domains"
    echo -e " Piholed: [${adsBlockedBar}] ${ads_percentage_today}%"
    echo -e " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "mini" ]; then
    echo "${boldText}STATS ==================================${resetText}"
    printf " %-9s%-29s\n" "Blckng:" "${domains_being_blocked} domains"
    printf " %-9s[%-20s] %-5s\n" "Piholed:" "${adsBlockedBar}" "${ads_percentage_today}%"
    printf " %-9s%-29s\n" "Piholed:" "${ads_blocked_today} out of ${dns_queries_today}"
    printf " %-9s%-29s\n" "Latest:" "${latestBlocked}"
    if [[ "${DHCP_ACTIVE}" != "true" ]]; then
      printf " %-9s%-29s\n" "Top Ad:" "${topBlocked}"
    fi
  # else we're not
  else
    echo "${boldText}STATS ======================================================${resetText}"
    printf " %-10s%-49s\n" "Blocking:" "${domains_being_blocked} domains"
    printf " %-10s[%-40s] %-5s\n" "Pi-holed:" "${adsBlockedBar}" "${ads_percentage_today}%"
    printf " %-10s%-49s\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
    printf " %-10s%-39s\n" "Latest:" "${latestBlocked}"
    printf " %-10s%-39s\n" "Top Ad:" "${topBlocked}"
    if [[ "${DHCP_ACTIVE}" != "true" ]]; then
      printf " %-10s%-39s\n" "Top Dmn:" "${topDomain}"
      printf " %-10s%-39s\n" "Top Clnt:" "${topClient}"
    fi
  fi
}

PrintSystemInformation() {
  if [ "$1" = "pico" ]; then
    echo "${boldText}CPU ==============${resetText}"
    echo -e " [${cpuLoad1Heatmap}${cpuBar}${resetText}] ${cpuPercent}%"
  elif [ "$1" = "nano" ]; then
    echo "${boldText}SYSTEM =================${resetText}"
    echo -e  " Up:  ${systemUptime}"
    echo -e  " CPU: [${cpuLoad1Heatmap}${cpuBar}${resetText}] ${cpuPercent}%"
  elif [ "$1" = "micro" ]; then
    echo "${boldText}SYSTEM =======================${resetText}"
    echo -e  " Uptime:  ${systemUptime}"
    echo -e  " Load:    [${cpuLoad1Heatmap}${cpuBar}${resetText}] ${cpuPercent}%"
    echo -ne " Memory:  [${memoryHeatmap}${memoryBar}${resetText}] ${memoryUsedPercent}%"
  elif [ "$1" = "mini" ]; then
    echo "${boldText}SYSTEM =================================${resetText}"
    printf " %-9s%-29s\n" "Uptime:" "${systemUptime}"
    echo -e  " Load:    [${cpuLoad1Heatmap}${cpuBar}${resetText}] ${cpuPercent}%"
    echo -ne " Memory:  [${memoryHeatmap}${memoryBar}${resetText}] ${memoryUsedPercent}%"
  # else we're not
  else
    echo "${boldText}SYSTEM =====================================================${resetText}"
    # Uptime
    printf " %-10s%-39s\n" "Uptime:" "${systemUptime}"

    # Temp and Loads
    printf " %-10s${tempHeatMap}%-20s${resetText}" "CPU Temp:" "${temperature}"
    printf " %-10s${cpuLoad1Heatmap}%-4s${resetText}, ${cpuLoad5Heatmap}%-4s${resetText}, ${cpuLoad15Heatmap}%-4s${resetText}\n" "CPU Load:" "${cpuLoad1}" "${cpuLoad5}" "${cpuLoad15}"

    # Memory and CPU bar
    printf " %-10s[${memoryHeatmap}%-10s${resetText}] %-6s %-10s[${cpuLoad1Heatmap}%-10s${resetText}] %-5s" "Memory:" "${memoryBar}" "${memoryUsedPercent}%" "CPU Load:" "${cpuBar}" "${cpuPercent}%"
  fi
}

############################################# HELPERS ##############################################

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
  #  |<-                 green                  ->| yellow |  red ->
  #  0  5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100
  if [ ${load} -lt 75 ]; then
    out=${greenText}
  elif [ ${load} -lt 90 ]; then
    out=${yellowText}
  else
    out=${redText}
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
  barNumber=$(printf %.f "$(echo "scale=2; (($1/100)*$2)" | bc)")
  frontFill=$(for i in $(seq $barNumber); do echo -n '■'; done)

  # remaining "unfilled" cells in the bar
  backfillNumber=$(($2-${barNumber}))

  # if the filled in cells is less than the max length of the bar, fill it
  if [ "$barNumber" -lt "$2" ]; then
    # if the bar should be colored
    if [ "$3" = "color" ]; then
      # fill the rest in color
      backFill=$(for i in $(seq $backfillNumber); do echo -n '■'; done)
      out="${redText}${frontFill}${greenText}${backFill}${resetText}"
    # else, it shouldn't be colored in
    else
      # fill the rest with "space"
      backFill=$(for i in $(seq $backfillNumber); do echo -n '·'; done)
      out="${frontFill}${resetText}${backFill}"
    fi
  # else, fill it all the way
  else
    out=$(for i in $(seq $2); do echo -n '■'; done)
  fi

  echo $out
}

OutputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw}}"
}

StartupRoutine(){
  :
}

NormalPADD() {
  for (( ; ; )); do

    consoleWidth=$(tput cols)
    consoleHeight=$(tput lines)

    # Sizing Checks

    # Below Pico. Gives you nothing...
    if [[ "$consoleWidth" -lt "20" || "$consoleHeight" -lt "10" ]]; then
      # Nothing is this small, sorry
      clear
      echo -e "${checkBoxBad} Error!\n    PADD isn't\n    for ants!"
      exit 0
    # Below Nano. Gives you Pico.
    elif [[ "$consoleWidth" -lt "24" || "$consoleHeight" -lt "12" ]]; then
      PADDsize="pico"
    # Below Micro, Gives you Nano.
    elif [[ "$consoleWidth" -lt "30" || "$consoleHeight" -lt "16" ]]; then
      PADDsize="nano"
    # Below Mini. Gives you Micro.
    elif [[ "$consoleWidth" -lt "40" || "$consoleHeight" -lt "18" ]]; then
      PADDsize="micro"
    # Below Slim. Gives you Mini.
    elif [[ "$consoleWidth" -lt "60" || "$consoleHeight" -lt "20" ]]; then
      PADDsize="mini"
    # Below Regular. Gives you Slim.
    elif [[ "$consoleWidth" -lt "60" || "$consoleHeight" -lt "22" ]]; then
      PADDsize="slim"
    # Regular
    else
      PADDsize="regular"
    fi

    # echo ${PADDsize} ${consoleWidth}"x"${consoleHeight}

    # if [[ "$consoleWidth" -lt "30" || "$consoleHeight" -lt "16" ]]; then
    #   clear
    #   echo -e "${checkBoxBad} Error!\nPADD doesn't run on a screen that small!"
    #   exit 0
    # fi

    # Get Config variables
    . /etc/pihole/setupVars.conf

    # Output everything to the screen
      PrintLogo ${PADDsize}
      PrintPiholeInformation ${PADDsize}
      PrintPiholeStats ${PADDsize}
      PrintNetworkInformation ${PADDsize}
      PrintSystemInformation ${PADDsize}

      picoStatus=${picoStatusOk}
      miniStatus=${miniStatusOk}

      # Start getting our information
      GetVersionInformation
      GetPiholeInformation
      GetNetworkInformation
      GetSummaryInformation "mini"
      GetSystemInformation "mini"

		latestBlocked=$(GetFTLData recentBlocked)
    topBlocked=$(GetFTLData "top-ads (1)" | awk '{print $3}')

    topDomain=$(GetFTLData "top-domains (1)" | awk '{print $3}')
    topClient=$(GetFTLData "top-clients (1)" | awk '{print $3}')

    # Sleep for 5 seconds, then clear the screen
    sleep 5
    clear
  done
}

DisplayHelp() {
  cat << EOM
::: PADD displays stats about your piHole!
:::
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
  # (From Pull request #8 https://github.com/jpmck/PADD/pull/8)
  setterm -cursor off
  trap "{ setterm -cursor on ; echo "" ; exit 0 ; }" SIGINT SIGTERM EXIT

  clear

  consoleWidth=$(tput cols)
  consoleHeight=$(tput lines)

  # Get Our Config Values
  . /etc/pihole/setupVars.conf

  if [[ "$consoleWidth" -lt "30" || "$consoleHeight" -lt "16" ]]; then
    # clear
    # echo -e "${checkBoxBad} Error!\nPADD doesn't run on a screen this small!"
    # exit 0
    :
  elif [[ "$consoleWidth" -lt "60" || "$consoleHeight" -lt "22" ]]; then
    #statements
    echo -e "${miniPADDLogo}\n"

    echo "START UP ====================="

    # Get PID of PADD
    pid=$(echo $$)
    echo "- Writing PID (${pid}) to file."
    echo ${pid} > ./PADD.pid

    # Check for updates
    echo "- Checking for version file."
    if [ -e "piHoleVersion" ]; then
      echo "  - Found and deleted."
      rm -f piHoleVersion
    else
      echo "  - Not found."
    fi

    # Get our information for the first time
    echo "- Gathering system info."
    GetSystemInformation "mini"
    echo "- Gathering Pi-hole info."
    GetSummaryInformation "mini"
    echo "- Gathering network info."
    GetNetworkInformation
    echo "- Gathering version info."
    GetVersionInformation
    echo "  - Core v$piholeVersion, Web v$webVersion"
    echo "  - FTL v$ftlVersion, PADD v$PADDVersion"
    echo "- Checking for update info."
    GetVersionInformation
    echo "  - $versionStatus"
  else
    echo -e "${PADDLogoRetro1}"
    echo -e "${PADDLogoRetro2}Pi-hole® Ad Detection Display"
    echo -e "${PADDLogoRetro3}A client for Pi-hole\n"
    echo "START UP ==================================================="

    # Get PID of PADD
    pid=$(echo $$)
    echo "- Writing PID (${pid}) to file..."
    echo ${pid} > ./PADD.pid

    # Check for updates
    echo "- Checking for PADD version file..."
    if [ -e "piHoleVersion" ]; then
      echo "  - PADD version file found... deleting."
      rm -f piHoleVersion
    else
      echo "  - PADD version file not found."
    fi

    # Get our information for the first time
    echo "- Gathering system information..."
    GetSystemInformation
    echo "- Gathering Pi-hole information..."
    GetSummaryInformation
    GetPiholeInformation
    echo "- Gathering network information..."
    GetNetworkInformation
    echo "- Gathering version information..."
    GetVersionInformation
    echo "  - Pi-hole Core v$piholeVersion"
    echo "  - Web Admin v$webVersion"
    echo "  - FTL v$ftlVersion"
    echo "  - PADD v$PADDVersion"
    echo "- Checking for update information..."
    GetVersionInformation
    echo "  - $versionStatus"
  fi

  latestBlocked=$(GetFTLData recentBlocked)
  topBlocked=$(GetFTLData "top-ads (1)" | awk '{print $3}')

  topDomain=$(GetFTLData "top-domains (1)" | awk '{print $3}')
  topClient=$(GetFTLData "top-clients (1)" | awk '{print $3}')

  echo ""
  printf "PADD will start in"

  for i in 3 2 1
  do
    printf " $i,"
    sleep 1
  done

  printf " 0."
  # Run PADD
  clear
  NormalPADD
fi

for var in "$@"; do
  case "$var" in
    "-j" | "--json"  ) OutputJSON;;
    "-h" | "--help"  ) DisplayHelp;;
    *                ) exit 1;;
  esac
done
