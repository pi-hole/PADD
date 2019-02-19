#!/usr/bin/env bash
# shellcheck disable=SC2034
# shellcheck disable=SC1091
# shellcheck disable=SC2154

# PADD
#
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
# Issue 5: https://github.com/jpmck/PADD/issues/5
# Updated to en_US to support
# export LC_ALL=en_US.UTF-8 > /dev/null 2>&1 || export LC_ALL=en_GB.UTF-8 > /dev/null 2>&1 || export LC_ALL=C.UTF-8 > /dev/null 2>&1
LC_ALL=C
LC_NUMERIC=C

############################################ VARIABLES #############################################

# VERSION
padd_version="2.2.1"

# DATE
today=$(date +%Y%m%d)

# CORES
declare -i core_count=1
core_count=$(cat /sys/devices/system/cpu/kernel_max 2> /dev/null)+1

# COLORS
black_text=$(tput setaf 0)   # Black
red_text=$(tput setaf 1)     # Red
green_text=$(tput setaf 2)   # Green
yellow_text=$(tput setaf 3)  # Yellow
blue_text=$(tput setaf 4)    # Blue
magenta_text=$(tput setaf 5) # Magenta
cyan_text=$(tput setaf 6)    # Cyan
white_text=$(tput setaf 7)   # White
reset_text=$(tput sgr0)      # Reset to default color

# STYLES
bold_text=$(tput bold)
blinking_text=$(tput blink)
dim_text=$(tput dim)

# CHECK BOXES
check_box_good="[${green_text}✓${reset_text}]"       # Good
check_box_bad="[${red_text}✗${reset_text}]"          # Bad
check_box_question="[${yellow_text}?${reset_text}]"  # Question / ?
check_box_info="[${yellow_text}i${reset_text}]"      # Info / i

# PICO STATUSES
pico_status_Ok="${check_box_good} Sys. OK"
pico_status_Update="${check_box_info} Update"
pico_status_Hot="${check_box_bad} Sys. Hot!"
pico_status_Off="${check_box_bad} Offline"
pico_status_FTLDown="${check_box_info} FTL Down"
pico_status_DNSDown="${check_box_bad} DNS Down"
pico_status_Unknown="${check_box_question} Stat. Unk."

# MINI STATUS
mini_status_Ok="${check_box_good} System OK"
mini_status_Update="${check_box_info} Update avail."
mini_status_Hot="${check_box_bad} System is hot!"
mini_status_Off="${check_box_bad} Pi-hole off!"
mini_status_FTLDown="${check_box_info} FTL down!"
mini_status_DNSDown="${check_box_bad} DNS off!"
mini_status_Unknown="${check_box_question} Status unknown"

# REGULAR STATUS
full_Status_Ok="${check_box_good} System is healthy."
full_Status_Update="${check_box_info} Updates are available."
full_Status_Hot="${check_box_bad} System is hot!"
full_Status_Off="${check_box_bad} Pi-hole is offline"
full_Status_FTLDown="${check_box_info} FTL is down!"
full_Status_DNSDown="${check_box_bad} DNS is off!"
full_Status_Unknown="${check_box_question} Status unknown!"

# MEGA STATUS


# Text only "logos"
PADDText="${green_text}${bold_text}PADD${reset_text}"
PADDTextRetro="${bold_text}${red_text}P${yellow_text}A${green_text}D${blue_text}D${reset_text}${reset_text}"
miniTextRetro="${dim_text}${cyan_text}m${magenta_text}i${red_text}n${yellow_text}i${reset_text}"

# PADD logos - regular and retro
PADDLogo1="${bold_text}${green_text} __      __  __   ${reset_text}"
PADDLogo2="${bold_text}${green_text}|__) /\\ |  \\|  \\  ${reset_text}"
PADDLogo3="${bold_text}${green_text}|   /--\\|__/|__/  ${reset_text}"
PADDLogoRetro1="${bold_text} ${yellow_text}_${green_text}_      ${blue_text}_   ${yellow_text}_${green_text}_   ${reset_text}"
PADDLogoRetro2="${bold_text}${yellow_text}|${green_text}_${blue_text}_${cyan_text}) ${red_text}/${yellow_text}\\ ${blue_text}|  ${red_text}\\${yellow_text}|  ${cyan_text}\\  ${reset_text}"
PADDLogoRetro3="${bold_text}${green_text}|   ${red_text}/${yellow_text}-${green_text}-${blue_text}\\${cyan_text}|${magenta_text}_${red_text}_${yellow_text}/${green_text}|${blue_text}_${cyan_text}_${magenta_text}/  ${reset_text}"

# old script Pi-hole logos - regular and retro
PiholeLogoScript1="${bold_text}${green_text}.-..   .      .      ${reset_text}"
PiholeLogoScript2="${bold_text}${green_text}|-'. - |-. .-.| .-,  ${reset_text}"
PiholeLogoScript3="${bold_text}${green_text}'  '   ' '-\`-''-\`'-  ${reset_text}"
PiholeLogoScriptRetro1="${red_text}.${yellow_text}-${green_text}.${blue_text}.   ${green_text}.      ${magenta_text}.      ${reset_text}"
PiholeLogoScriptRetro2="${yellow_text}|${green_text}-${blue_text}'${magenta_text}. ${yellow_text}- ${blue_text}|${magenta_text}-${red_text}. ${green_text}.${blue_text}-${magenta_text}.${red_text}| ${green_text}.${blue_text}-${magenta_text},  ${reset_text}"
PiholeLogoScriptRetro3="${green_text}'  ${red_text}'   ${magenta_text}' ${yellow_text}'${green_text}-${blue_text}\`${magenta_text}-${red_text}'${yellow_text}'${green_text}-${blue_text}\`${magenta_text}'${red_text}-  ${reset_text}"

############################################# GETTERS ##############################################

GetFTLData() {
  # Get FTL port number
  ftlPort=$(cat /var/run/pihole-FTL.port)

  # Did we find a port for FTL?
  if [[ -n "$ftlPort" ]]; then
    # Open connection to FTL
    exec 3<>"/dev/tcp/localhost/$ftlPort"

    # Test if connection is open
    if { "true" >&3; } 2> /dev/null; then
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
  # We didn't...?
  else
    echo "0"
  fi
}

GetSummaryInformation() {
  local summary
  local cache_summary
  summary=$(GetFTLData "stats")
  cache_info=$(GetFTLData "cacheinfo")

  clients=$(grep "unique_clients" <<< "${summary}" | grep -Eo "[0-9]+$")

  domains_being_blocked_raw=$(grep "domains_being_blocked" <<< "${summary}" | grep -Eo "[0-9]+$")
  domains_being_blocked=$(printf "%'.f" "${domains_being_blocked_raw}")

  dns_queries_today_raw=$(grep "dns_queries_today" <<< "$summary" | grep -Eo "[0-9]+$")
  dns_queries_today=$(printf "%'.f" "${dns_queries_today_raw}")

  ads_blocked_today_raw=$(grep "ads_blocked_today" <<< "$summary" | grep -Eo "[0-9]+$")
  ads_blocked_today=$(printf "%'.f" "${ads_blocked_today_raw}")

  ads_percentage_today_raw=$(grep "ads_percentage_today" <<< "$summary" | grep -Eo "[0-9.]+$")
  ads_percentage_today=$(printf "%'.1f" "${ads_percentage_today_raw}")

  cache_size=$(grep "cache-size" <<< "$cache_info" | grep -Eo "[0-9.]+$")
  cache_deletes=$(grep "cache-live-freed" <<< "$cache_info" | grep -Eo "[0-9.]+$")
  cache_inserts=$(grep "cache-inserted" <<< "$cache_info" | grep -Eo "[0-9.]+$")

  latest_blocked=$(GetFTLData recentBlocked)

  top_blocked=$(GetFTLData "top-ads (1)" | awk '{print $3}')

  top_domain=$(GetFTLData "top-domains (1)" | awk '{print $3}')

  read -r -a top_client_raw <<< "$(GetFTLData "top-clients (1)")"
  if [[ "${top_client_raw[3]}" ]]; then
    top_client="${top_client_raw[3]}"
  else
    top_client="${top_client_raw[2]}"
  fi

  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 10 "color")
  elif [ "$1" = "mini" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 20 "color")

    if [ ${#latest_blocked} -gt 30 ]; then
      latest_blocked=$(echo "$latest_blocked" | cut -c1-27)"..."
    fi

    if [ ${#top_blocked} -gt 30 ]; then
      top_blocked=$(echo "$top_blocked" | cut -c1-27)"..."
    fi
  elif [ "$1" = "regular" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 40 "color")
  else
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 30 "color")
  fi
}

GetSystemInformation() {
  # System uptime
  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    system_uptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours"}')
  else
    system_uptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/) {d=$6;h=$8;m=$9} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')
  fi

  # CPU temperature
  if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    cpu=$(</sys/class/thermal/thermal_zone0/temp)
  else
    cpu=0
  fi

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" == "F" ]; then
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 * 9 / 5000 + 32}')")°F"
  elif [ "${TEMPERATUREUNIT}" == "K" ]; then
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 / 1000 + 273.15}')")°K"
  # Addresses Issue 1: https://github.com/jpmck/PAD/issues/1
  else
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 / 1000}')")°C"
  fi

  # CPU load, heatmap
  read -r -a cpu_load < /proc/loadavg
  cpu_load_1_heatmap=$(HeatmapGenerator "${cpu_load[0]}" "${core_count}")
  cpu_load_5_heatmap=$(HeatmapGenerator "${cpu_load[1]}" "${core_count}")
  cpu_load_15_heatmap=$(HeatmapGenerator "${cpu_load[2]}" "${core_count}")
  cpu_percent=$(printf %.1f "$(echo "${cpu_load[0]} ${core_count}" | awk '{print ($1 / $2) * 100}')")

  # CPU temperature heatmap
  # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)
  if [ ${cpu} -gt 80000 ]; then
    temp_heatmap=${blinking_text}${red_text}
    pico_status_="${pico_status_Hot}"
    mini_status_="${mini_status_Hot} ${blinking_text}${red_text}${temperature}${reset_text}"
    full_Status_="${full_Status_Hot} ${blinking_text}${red_text}${temperature}${reset_text}"
  elif [ ${cpu} -gt 70000 ]; then
    temp_heatmap=${magenta_text}
  elif [ ${cpu} -gt 60000 ]; then
    temp_heatmap=${blue_text}
  else
    temp_heatmap=${cyan_text}
  fi

  # Memory use, heatmap and bar
  memory_percent=$(awk '/MemTotal:/{total=$2} /MemFree:/{free=$2} /Buffers:/{buffers=$2} /^Cached:/{cached=$2} END {printf "%.1f", (total-free-buffers-cached)*100/total}' '/proc/meminfo')
  memory_heatmap=$(HeatmapGenerator "${memory_percent}")

  #  Bar generations
  if [ "$1" = "mini" ]; then
    cpu_bar=$(BarGenerator "${cpu_percent}" 20)
    memory_bar=$(BarGenerator "${memory_percent}" 20)
  else
    cpu_bar=$(BarGenerator "${cpu_percent}" 10)
    memory_bar=$(BarGenerator "${memory_percent}" 10)
  fi
}

GetNetworkInformation() {
  # Get pi IP address, hostname and gateway
  pi_ip_address=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
  pi_hostname=$(hostname)
  pi_gateway=$(route -n | grep 'UG[ \t]' | awk '{print $2}')

  # does the Pi-hole have a domain set?
  if [ -z ${PIHOLE_DOMAIN+x} ]; then
    full_hostname=${pi_hostname}
  else
    count=${pi_hostname}"."${PIHOLE_DOMAIN}
    count=${#count}

    if [ "${count}" -lt "18" ]; then
      full_hostname=${pi_hostname}"."${PIHOLE_DOMAIN}
    else
      full_hostname=${pi_hostname}
    fi
  fi

  # Get the DNS count (from pihole -c)
  dns_count="0"
  [[ -n "${PIHOLE_DNS_1}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_2}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_3}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_4}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_5}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_6}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_7}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_8}" ]] && dns_count=$((dns_count+1))
  [[ -n "${PIHOLE_DNS_9}" ]] && dns_count=$((dns_count+1))

  # if there's only one DNS server
  if [[ ${dns_count} -eq 1 ]]; then
    if [[ "${PIHOLE_DNS_1}" == "127.0.0.1#5053" ]]; then
      dnsInformation="1 server (Cloudflared)"
    elif [[ "${PIHOLE_DNS_1}" == "${pi_gateway}#53" ]]; then
      dnsInformation="1 server (gateway)"
    else
      dnsInformation="1 server"
    fi
  elif [[ ${dns_count} -gt 8 ]]; then
    dnsInformation="8+ servers"
  else
    dnsInformation="${dns_count} servers"
  fi

  # Is Pi-Hole acting as the DHCP server?
  if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    dhcp_status="Enabled"
    dhcpInfo=" Range:    ${DHCP_START} - ${DHCP_END}"
    dhcpHeatmap=${green_text}
    dhcpCheck_box_=${check_box_good}

    # Is DHCP handling IPv6?
    if [[ "${DHCP_IPv6}" == "true" ]]; then
      dhcp_ipv6_status="Enabled"
      dhcp_ipv6_heatmap=${green_text}
      dhcp_ipv6_check_box=${check_box_good}
    else
      dhcp_ipv6_status="Disabled"
      dhcp_ipv6_heatmap=${red_text}
      dhcp_ipv6_check_box=${check_box_bad}
    fi
  else
    dhcp_status="Disabled"
    dhcpHeatmap=${red_text}
    dhcpCheck_box_=${check_box_bad}

    # if the DHCP Router variable isn't set
    # Issue 3: https://github.com/jpmck/PADD/issues/3
    if [ -z ${DHCP_ROUTER+x} ]; then
      DHCP_ROUTER=$(/sbin/ip route | awk '/default/ { print $3 }')
    fi

    dhcpInfo=" Router:   ${DHCP_ROUTER}"
    dhcpHeatmap=${red_text}
    dhcpCheck_box_=${check_box_bad}

    dhcp_ipv6_status="N/A"
    dhcp_ipv6_heatmap=${yellow_text}
    dhcp_ipv6_check_box=${check_box_question}
  fi

  # DNSSEC
  if [[ "${DNSSEC}" == "true" ]]; then
    dnssec_status="Enabled"
    dnssec_heatmap=${green_text}
    dnssec_check_box=${check_box_good}
  else
    dnssec_status="Disabled"
    dnssec_heatmap=${red_text}
    dnssec_check_box=${check_box_bad}
  fi

  # Conditional forwarding
  if [[ "${CONDITIONAL_FORWARDING}" == "true" ]]; then
    conditional_forwarding_status="Enabled"
    conditional_forwarding_heatmap=${green_text}
    conditional_forwarding_check_box=${check_box_good}
  else
    conditional_forwarding_status="Disabled"
    conditional_forwarding_heatmap=${red_text}
    conditional_forwarding_check_box=${check_box_bad}
  fi
}

GetPiholeInformation() {
  # Get Pi-hole status
  if [[ $(pihole status web) == 1 ]]; then
    pihole_status="Active"
    pihole_heatmap=${green_text}
    pihole_check_box=${check_box_good}
  elif [[ $(pihole status web) == 0 ]]; then
    pihole_status="Offline"
    pihole_heatmap=${red_text}
    pihole_check_box=${check_box_bad}
    pico_status_=${pico_status_Off}
    mini_status_=${mini_status_Off}
    full_Status_=${full_Status_Off}
  elif [[ $(pihole status web) == -1 ]]; then
    pihole_status="DNS Offline"
    pihole_heatmap=${red_text}
    pihole_check_box=${check_box_bad}
    pico_status_=${pico_status_DNSDown}
    mini_status_=${mini_status_DNSDown}
    full_Status_=${full_Status_DNSDown}
  else
    pihole_status="Unknown"
    pihole_heatmap=${yellow_text}
    pihole_check_box=${check_box_question}
    pico_status_=${pico_status_Unknown}
    mini_status_=${mini_status_Unknown}
    full_Status_=${full_Status_Unknown}
  fi

  # Get FTL status
  ftlPID=$(pidof pihole-FTL)

  if [ -z ${ftlPID+x} ]; then
    ftlStatus="Not running"
    ftlHeatmap=${yellow_text}
    ftlCheck_box_=${check_box_info}
    pico_status_=${pico_status_FTLDown}
    mini_status_=${mini_status_FTLDown}
    full_Status_=${full_Status_FTLDown}
  else
    ftlStatus="Running"
    ftlHeatmap=${green_text}
    ftlCheck_box_=${check_box_good}
  fi
}

GetVersionInformation() {
  # Check if version status has been saved
  if [ -e "piHoleVersion" ]; then # the file exists...
    # the file exits, use it
    # shellcheck disable=SC1091
    source piHoleVersion

    # Today is...
    today=$(date +%Y%m%d)
    
    # was the last check today?
    if [ "${today}" != "${lastCheck}" ]; then # no, it wasn't today
      # Remove the Pi-hole version file...
      rm -f piHoleVersion
    fi

  else # the file doesn't exist, create it...
    # Gather core version information...
    read -r -a coreVersions <<< $(pihole -v -p)
    coreVersion=$(echo "${coreVersions[3]}" | tr -d '\r\n[:alpha:]')
    coreVersionLatest=${coreVersions[5]//)}
    if [[ "${coreVersion}" == "ERROR" ]]; then
      coreVersionLatest=${coreVersion}
    else
      coreVersionLatest=$(echo "${coreVersion}" | tr -d '\r\n[:alpha:]')
    fi

    # Gather web version information...
    read -r -a webVersions <<< $(pihole -v -a)
    webVersion=$(echo "${webVersions[3]}" | tr -d '\r\n[:alpha:]')
    webVersionLatest=${webVersions[5]//)}
    if [[ "${webVersion}" == "ERROR" ]]; then
      webVersionLatest=${webVersion}
    else
      webVersionLatest=$(echo "${webVersion}" | tr -d '\r\n[:alpha:]')
    fi

    # Gather FTL version information...
    read -r -a ftlVersions <<< $(pihole -v -f)
    ftlVersion=$(echo "${ftlVersions[3]}" | tr -d '\r\n[:alpha:]')
    ftlVersionLatest=${ftlVersions[5]//)}
    if [[ "${ftlVersion}" == "ERROR" ]]; then
      ftlVersionLatest=${ftlVersion}
    else
      ftlVersionLatest=$(echo "${ftlVersion}" | tr -d '\r\n[:alpha:]')
    fi

    # PADD version information...
    padd_versionLatest=$(curl -sI https://github.com/jpmck/PADD/releases/latest | grep 'Location' | awk -F '/' '{print $NF}' | tr -d '\r\n[:alpha:]')

    # check if everything is up-to-date...
    # is core up-to-date?
    if [[ "${coreVersion}" != "${coreVersionLatest}" ]]; then
      outOfDateFlag="true"
      piholeVersionHeatmap=${red_text}
    else
      piholeVersionHeatmap=${green_text}
    fi

    # is web up-to-date?
    if [[ "${webVersion}" != "${webVersionLatest}" ]]; then
      outOfDateFlag="true"
      webVersionHeatmap=${red_text}
    else
      webVersionHeatmap=${green_text}
    fi

    # is ftl up-to-date?
    if [[ "${ftlVersion}" != "${ftlVersionLatest}" ]]; then
      outOfDateFlag="true"
      ftlVersionHeatmap=${red_text}
    else
      ftlVersionHeatmap=${green_text}
    fi

    # is PADD up-to-date?
    if [[ "${padd_version}" != "${padd_versionLatest}" ]]; then
      PADDOutOfDateFlag="true"
      padd_versionHeatmap=${red_text}
    else
      padd_versionHeatmap=${green_text}
    fi

    # was any portion of Pi-hole out-of-date?
    # yes, pi-hole is out of date
    if [[ "${outOfDateFlag}" == "true" ]]; then
      versionStatus="Pi-hole is out-of-date!"
      versionHeatmap=${red_text}
      versionCheck_box_=${check_box_bad}
      pico_status_=${pico_status_Update}
      mini_status_=${mini_status_Update}
      full_Status_=${full_Status_Update}
    else
      # but is PADD out-of-date?
      if [[ "${PADDOutOfDateFlag}" == "true" ]]; then
        versionStatus="PADD is out-of-date!"
        versionHeatmap=${red_text}
        versionCheck_box_=${check_box_bad}
        pico_status_=${pico_status_Update}
        mini_status_=${mini_status_Update}
        full_Status_=${full_Status_Update}
      # else, everything is good!
      else
        versionStatus="Pi-hole is up-to-date!"
        versionHeatmap=${green_text}
        versionCheck_box_=${check_box_good}
        pico_status_=${pico_status_Ok}
        mini_status_=${mini_status_Ok}
        full_Status_=${full_Status_Ok}
      fi
    fi

    # write it all to the file
    echo "lastCheck=${today}" > ./piHoleVersion
    {
      echo "coreVersion=$coreVersion"
      echo "coreVersionHeatmap=$coreVersionHeatmap"

      echo "webVersion=$webVersion"
      echo "webVersionHeatmap=$webVersionHeatmap"

      echo "ftlVersion=$ftlVersion"
      echo "ftlVersionHeatmap=$ftlVersionHeatmap"

      echo "padd_version=$padd_version"
      echo "padd_versionHeatmap=$padd_versionHeatmap"

      echo "versionStatus=\"$versionStatus\""
      echo "versionHeatmap=$versionHeatmap"
      echo "versionCheck_box_=\"$versionCheck_box_\""

      echo "pico_status_=\"$pico_status_\""
      echo "mini_status_=\"$mini_status_\""
      echo "full_Status_=\"$full_Status_\""
    } >> ./piHoleVersion

    # there's a file now
  fi
}

############################################# PRINTERS #############################################

PrintLogo() {
  # Screen size checks
  if [ "$1" = "pico" ]; then
    echo -e "p${PADDText} ${pico_status_}"
  elif [ "$1" = "nano" ]; then
    echo -e "n${PADDText} ${mini_status_}"
  elif [ "$1" = "micro" ]; then
    echo -e "µ${PADDText}     ${mini_status_}\\n"
  elif [ "$1" = "mini" ]; then
    echo -e "${PADDText}${dim_text}mini${reset_text}  ${mini_status_}\\n"
  elif [ "$1" = "slim" ]; then
    echo -e "${PADDText}${dim_text}slim${reset_text}   ${full_Status_}\\n"
  elif [ "$1" = "regular" ]; then
    echo -e "${PADDLogo1}"
    echo -e "${PADDLogo2}Pi-hole® ${piholeVersionHeatmap}v${coreVersion}${reset_text}, Web ${webVersionHeatmap}v${webVersion}${reset_text}, FTL ${ftlVersionHeatmap}v${ftlVersion}${reset_text}"
    echo -e "${PADDLogo3}PADD ${PADDVersionHeatmap}v${PADDVersion}${resetText} ${fullStatus}${resetText}"

    echo ""
  # normal or not defined
  else
    echo -e "${PADDLogoRetro1}"
    echo -e "${PADDLogoRetro2}   Pi-hole® ${piholeVersionHeatmap}v${coreVersion}${reset_text}, Web ${webVersionHeatmap}v${webVersion}${reset_text}, FTL ${ftlVersionHeatmap}v${ftlVersion}${reset_text}, PADD ${padd_versionHeatmap}v${padd_version}${reset_text}"
    echo -e "${PADDLogoRetro3}   ${pihole_check_box} Core  ${ftlCheck_box_} FTL   ${full_Status_}${reset_text}"

    echo ""
  fi
}

PrintNetworkInformation() {
  if [ "$1" = "pico" ]; then
    echo "${bold_text}NETWORK ============${reset_text}"
    echo -e " Hst: ${pi_hostname}"
    echo -e " IP:  ${pi_ip_address}"
    echo -e " DHCP ${dhcpCheck_box_} IPv6 ${dhcp_ipv6_check_box}"
  elif [ "$1" = "nano" ]; then
    echo "${bold_text}NETWORK ================${reset_text}"
    echo -e " Host: ${pi_hostname}"
    echo -e " IPv4: ${IPV4_ADDRESS}"
    echo -e " DHCP: ${dhcpCheck_box_}    IPv6: ${dhcp_ipv6_check_box}"
  elif [ "$1" = "micro" ]; then
    echo "${bold_text}NETWORK ======================${reset_text}"
    echo -e " Host:    ${full_hostname}"
    echo -e " IPv4:    ${IPV4_ADDRESS}"
    echo -e " DHCP:    ${dhcpCheck_box_}     IPv6:  ${dhcp_ipv6_check_box}"
  elif [ "$1" = "mini" ]; then
    echo "${bold_text}NETWORK ================================${reset_text}"
    printf " %-9s%-19s\\n" "Host:" "${full_hostname}"
    printf " %-9s%-19s\\n" "IPv4:" "${IPV4_ADDRESS}"
    printf " %-9s%-10s %-9s%-10s\\n" "DNS:" "${dnsInformation}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"

    if [[ "${DHCP_ACTIVE}" == "true" ]]; then
      printf " %-9s${dhcpHeatmap}%-10s${reset_text} %-9s${dhcp_ipv6_heatmap}%-10s${reset_text}\\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
    fi
  elif [ "$1" = "regular" ]; then
    echo "${bold_text}NETWORK ====================================================${reset_text}"
    printf " %-10s%-19s %-10s%-19s\\n" "Hostname:" "${full_hostname}" "IPv4:" "${IPV4_ADDRESS}"
    printf " %-10s%-19s\\n" "IPv6:" "${IPV6_ADDRESS}"
    printf " %-10s%-19s %-10s%-19s\\n" "DNS:" "${dnsInformation}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"

    if [[ "${DHCP_ACTIVE}" == "true" ]]; then
      printf " %-10s${dhcpHeatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-19s${reset_text}\\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
      printf "%s\\n" "${dhcpInfo}"
    fi
  else
    echo "${bold_text}NETWORK ========================================================================${reset_text}"
    printf " %-10s%-19s\\n" "Hostname:" "${full_hostname}"
    printf " %-10s%-19s %-10s%-29s\\n" "IPv4:" "${IPV4_ADDRESS}" "IPv6:" "${IPV6_ADDRESS}"
    echo "DNS ============================================================================"
    printf " %-10s%-39s\\n" "Servers:" "${dnsInformation}"
    printf " %-10s${dnssec_heatmap}%-9s${reset_text} %-20s${conditional_forwarding_heatmap}%-9s${reset_text}\\n" "DNSSEC:" "${dnssec_status}" "Conditional Fwding:" "${conditional_forwarding_status}"

    echo "DHCP ==========================================================================="
    printf " %-10s${dhcpHeatmap}%-9s${reset_text} %-10s${dhcp_ipv6_heatmap}%-9s${reset_text} %-10s%-9s\\n" "DHCP:" "${dhcp_status}" "IPv6:" "${dhcp_ipv6_status}" "Gateway:" "255.255.255.255"
    printf "%s\\n" "${dhcpInfo}"
  fi
}

PrintPiholeInformation() {
  # size checks
  if [ "$1" = "pico" ]; then
    :
  elif [ "$1" = "nano" ]; then
    echo "${bold_text}PI-HOLE ================${reset_text}"
    echo -e " Up:  ${pihole_check_box}      FTL: ${ftlCheck_box_}"
  elif [ "$1" = "micro" ]; then
    echo "${bold_text}PI-HOLE ======================${reset_text}"
    echo -e " Status:  ${pihole_check_box}      FTL:  ${ftlCheck_box_}"
  elif [ "$1" = "mini" ]; then
    echo "${bold_text}PI-HOLE ================================${reset_text}"
    printf " %-9s${pihole_heatmap}%-10s${reset_text} %-9s${ftlHeatmap}%-10s${reset_text}\\n" "Status:" "${pihole_status}" "FTL:" "${ftlStatus}"
  elif [ "$1" = "regular" ]; then
    echo "${bold_text}PI-HOLE ====================================================${reset_text}"
    printf " %-10s${pihole_heatmap}%-19s${reset_text} %-10s${ftlHeatmap}%-19s${reset_text}\\n" "Status:" "${pihole_status}" "FTL:" "${ftlStatus}"
  else
    return
  fi
}

PrintPiholeStats() {
  # are we on a tiny screen?
  if [ "$1" = "pico" ]; then
    echo "${bold_text}PI-HOLE ============${reset_text}"
    echo -e " [${ads_blocked_bar}] ${ads_percentage_today}%"
    echo -e " ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "nano" ]; then
    echo -e " Blk: [${ads_blocked_bar}] ${ads_percentage_today}%"
    echo -e " Blk: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "micro" ]; then
    echo "${bold_text}STATS ========================${reset_text}"
    echo -e " Blckng:  ${domains_being_blocked} domains"
    echo -e " Piholed: [${ads_blocked_bar}] ${ads_percentage_today}%"
    echo -e " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "mini" ]; then
    echo "${bold_text}STATS ==================================${reset_text}"
    printf " %-9s%-29s\\n" "Blckng:" "${domains_being_blocked} domains"
    printf " %-9s[%-20s] %-5s\\n" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    printf " %-9s%-29s\\n" "Piholed:" "${ads_blocked_today} out of ${dns_queries_today}"
    printf " %-9s%-29s\\n" "Latest:" "${latest_blocked}"
    if [[ "${DHCP_ACTIVE}" != "true" ]]; then
      printf " %-9s%-29s\\n" "Top Ad:" "${top_blocked}"
    fi
  elif [ "$1" = "regular" ]; then
    echo "${bold_text}STATS ======================================================${reset_text}"
    printf " %-10s%-49s\\n" "Blocking:" "${domains_being_blocked} domains"
    printf " %-10s[%-40s] %-5s\\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    printf " %-10s%-49s\\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
    printf " %-10s%-39s\\n" "Latest:" "${latest_blocked}"
    printf " %-10s%-39s\\n" "Top Ad:" "${top_blocked}"
    if [[ "${DHCP_ACTIVE}" != "true" ]]; then
      printf " %-10s%-39s\\n" "Top Dmn:" "${top_domain}"
      printf " %-10s%-39s\\n" "Top Clnt:" "${top_client}"
    fi
  else
    echo "${bold_text}STATS ==========================================================================${reset_text}"
    printf " %-10s%-19s %-10s[%-40s] %-5s\\n" "Blocking:" "${domains_being_blocked} domains" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    printf " %-10s%-30s%-29s\\n" "Clients:" "${clients}" "${ads_blocked_today} out of ${dns_queries_today} queries"
    printf " %-10s%-39s\\n" "Latest:" "${latest_blocked}"
    printf " %-10s%-39s\\n" "Top Ad:" "${top_blocked}"
    printf " %-10s%-39s\\n" "Top Dmn:" "${top_domain}"
    printf " %-10s%-39s\\n" "Top Clnt:" "${top_client}"
    echo "${bold_text}FTL ============================================================================${reset_text}"
    printf " %-10s%-9s\\n" "PID:" "${ftlPID}"
    printf " %-10s%-69s\\n" "DNSCache:" "${cache_inserts} insertions, ${cache_deletes} deletions, ${cache_size} total entries"
  fi
}

PrintSystemInformation() {
  if [ "$1" = "pico" ]; then
    echo "${bold_text}CPU ================${reset_text}"
    echo -ne " [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
  elif [ "$1" = "nano" ]; then
    echo "${bold_text}SYSTEM =================${reset_text}"
    echo -e  " Up:  ${system_uptime}"
    echo -ne  " CPU: [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
  elif [ "$1" = "micro" ]; then
    echo "${bold_text}SYSTEM =======================${reset_text}"
    echo -e  " Uptime:  ${system_uptime}"
    echo -e  " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    echo -ne " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
  elif [ "$1" = "mini" ]; then
    echo "${bold_text}SYSTEM =================================${reset_text}"
    printf " %-9s%-29s\\n" "Uptime:" "${system_uptime}"
    echo -e  " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    echo -ne " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
  # else we're not
  elif [ "$1" = "normal" ]; then
    echo "${bold_text}SYSTEM =====================================================${reset_text}"
    # Uptime
    printf " %-10s%-39s\\n" "Uptime:" "${system_uptime}"

    # Temp and Loads
    printf " %-10s${temp_heatmap}%-20s${reset_text}" "CPU Temp:" "${temperature}"
    printf " %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}\\n" "CPU Load:" "${cpu_load[0]}" "${cpu_load[1]}" "${cpu_load[2]}"

    # Memory and CPU bar
    printf " %-10s[${memory_heatmap}%-10s${reset_text}] %-6s %-10s[${cpu_load_1_heatmap}%-10s${reset_text}] %-5s" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
  else
    echo "${bold_text}SYSTEM =========================================================================${reset_text}"
    # Uptime and memory
    printf " %-10s%-39s %-10s[${memory_heatmap}%-10s${reset_text}] %-6s\\n" "Uptime:" "${system_uptime}" "Memory:" "${memory_bar}" "${memory_percent}%"

    # CPU temp, load, percentage
    printf " %-10s${temp_heatmap}%-10s${reset_text} %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-7s${reset_text} %-10s[${memory_heatmap}%-10s${reset_text}] %-6s" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load[0]}" "${cpu_load[1]}" "${cpu_load[2]}" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
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
    load=$(printf "%.0f" "$(echo "$1 $2" | awk '{print ($1 / $2) * 100}')")
  fi

  # Color logic
  #  |<-                 green                  ->| yellow |  red ->
  #  0  5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100
  if [ "${load}" -lt 75 ]; then
    out=${green_text}
  elif [ "${load}" -lt 90 ]; then
    out=${yellow_text}
  else
    out=${red_text}
  fi

  echo "$out"
}

# Provides a "bar graph"
# takes in two or three parameters
# $1: percentage filled
# $2: max length of the bar
# $3: colored flag, if "color" backfill with color
BarGenerator() {
  # number of filled in cells in the bar
  barNumber=$(printf %.f "$(echo "$1 $2" | awk '{print ($1 / 100) * $2}')")
  frontFill=$(for i in $(seq "$barNumber"); do echo -n '■'; done)

  # remaining "unfilled" cells in the bar
  backfillNumber=$(($2-barNumber))

  # if the filled in cells is less than the max length of the bar, fill it
  if [ "$barNumber" -lt "$2" ]; then
    # if the bar should be colored
    if [ "$3" = "color" ]; then
      # fill the rest in color
      backFill=$(for i in $(seq $backfillNumber); do echo -n '■'; done)
      out="${red_text}${frontFill}${green_text}${backFill}${reset_text}"
    # else, it shouldn't be colored in
    else
      # fill the rest with "space"
      backFill=$(for i in $(seq $backfillNumber); do echo -n '·'; done)
      out="${frontFill}${reset_text}${backFill}"
    fi
  # else, fill it all the way
  else
    out=$(for i in $(seq "$2"); do echo -n '■'; done)
  fi

  echo "$out"
}

SizeChecker(){
  # Below Pico. Gives you nothing...
  if [[ "$console_width" -lt "20" || "$console_height" -lt "10" ]]; then
    # Nothing is this small, sorry
    clear
    echo -e "${check_box_bad} Error!\\n    PADD isn't\\n    for ants!"
    exit 0
  # Below Nano. Gives you Pico.
  elif [[ "$console_width" -lt "24" || "$console_height" -lt "12" ]]; then
    padd_size="pico"
  # Below Micro, Gives you Nano.
  elif [[ "$console_width" -lt "30" || "$console_height" -lt "16" ]]; then
    padd_size="nano"
  # Below Mini. Gives you Micro.
  elif [[ "$console_width" -lt "40" || "$console_height" -lt "18" ]]; then
    padd_size="micro"
  # Below Slim. Gives you Mini.
  elif [[ "$console_width" -lt "60" || "$console_height" -lt "20" ]]; then
    padd_size="mini"
  # Below Regular. Gives you Slim.
  elif [[ "$console_width" -lt "60" || "$console_height" -lt "22" ]]; then
    padd_size="slim"
  # Below Mega. Gives you Regular.
  elif [[ "$console_width" -lt "80" || "$console_height" -lt "26" ]]; then
    padd_size="regular"
  # Regular
  else
    padd_size="mega"
  fi
}

########################################## MAIN FUNCTIONS ##########################################

OutputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw}}"
}

StartupRoutine(){
  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    PrintLogo "$1"
    echo -e "START-UP ==========="
    echo -e "Starting PADD.\\nPlease stand by."

    # Get PID of PADD
    pid=$$
    echo -ne " [■·········]  10%\\r"
    echo ${pid} > ./PADD.pid

    # Check for updates
    echo -ne " [■■········]  20%\\r"
    if [ -e "piHoleVersion" ]; then
      echo -ne " [■■■·······]  30%\\r"
      rm -f piHoleVersion
    else
      echo -ne " [■■■·······]  30%\\r"
    fi

    # Get our information for the first time
    echo -ne " [■■■■······]  40%\\r"
    GetSystemInformation "$1"
    echo -ne " [■■■■■·····]  50%\\r"
    GetSummaryInformation "$1"
    echo -ne " [■■■■■■····]  60%\\r"
    GetPiholeInformation "$1"
    echo -ne " [■■■■■■■···]  70%\\r"
    GetNetworkInformation "$1"
    echo -ne " [■■■■■■■■··]  80%\\r"
    GetVersionInformation "$1"
    echo -ne " [■■■■■■■■■·]  90%\\r"
    GetVersionInformation "$1"
    echo -ne " [■■■■■■■■■■] 100%\\n"

  elif [ "$1" = "mini" ]; then
    PrintLogo "$1"
    echo "START UP ====================="
    # Get PID of PADD
    pid=$$
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
    GetNetworkInformation "mini"
    echo "- Gathering version info."
    GetVersionInformation "mini"
    echo "  - Core v$coreVersion, Web v$webVersion"
    echo "  - FTL v$ftlVersion, PADD v$padd_version"
    echo "  - $versionStatus"

  else
    echo -e "${PADDLogoRetro1}"
    echo -e "${PADDLogoRetro2}Pi-hole® Ad Detection Display"
    echo -e "${PADDLogoRetro3}A client for Pi-hole\\n"
    echo "START UP ==================================================="

    # Get PID of PADD
    pid=$$
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
    echo "  - Pi-hole Core v$coreVersion"
    echo "  - Web Admin v$webVersion"
    echo "  - FTL v$ftlVersion"
    echo "  - PADD v$padd_version"
    echo "  - $versionStatus"
  fi

  printf "Starting in "

  for i in 3 2 1
  do
    printf "%s..." "$i"
    sleep 1
  done
}

NormalPADD() {
  for (( ; ; )); do

    console_width=$(tput cols)
    console_height=$(tput lines)

    # Sizing Checks
    SizeChecker

    # Get Config variables
    . /etc/pihole/setupVars.conf

    # Output everything to the screen
    PrintLogo ${padd_size}
    PrintPiholeInformation ${padd_size}
    PrintPiholeStats ${padd_size}
    PrintNetworkInformation ${padd_size}
    PrintSystemInformation ${padd_size}

    pico_status_=${pico_status_Ok}
    mini_status_=${mini_status_Ok}

    # Start getting our information
    GetVersionInformation ${padd_size}
    GetPiholeInformation ${padd_size}
    GetNetworkInformation ${padd_size}
    GetSummaryInformation ${padd_size}
    GetSystemInformation ${padd_size}

    # Sleep for 6 seconds, then clear the screen
    sleep 6
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

  console_width=$(tput cols)
  console_height=$(tput lines)

  # Get Our Config Values
  # shellcheck disable=SC1091
  . /etc/pihole/setupVars.conf

  SizeChecker

  StartupRoutine ${padd_size}

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
