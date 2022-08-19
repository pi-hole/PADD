#!/usr/bin/env sh
# shellcheck disable=SC1091

# Ignore warning about `local` being undefinded in POSIX
# shellcheck disable=SC3043
# https://github.com/koalaman/shellcheck/wiki/SC3043#exceptions

# PADD
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
# Issue 5: https://github.com/jpmck/PADD/issues/5
# Updated to en_US to support
# export LC_ALL=en_US.UTF-8 > /dev/null 2>&1 || export LC_ALL=en_GB.UTF-8 > /dev/null 2>&1 || export LC_ALL=C.UTF-8 > /dev/null 2>&1
LC_ALL=C
LC_NUMERIC=C

############################################ VARIABLES #############################################

# VERSION
padd_version="v3.8.1"

# LastChecks
LastCheckVersionInformation=$(date +%s)
LastCheckNetworkInformation=$(date +%s)
LastCheckSummaryInformation=$(date +%s)
LastCheckPiholeInformation=$(date +%s)
LastCheckSystemInformation=$(date +%s)

# CORES
core_count=$(nproc --all 2> /dev/null)

# COLORS
CSI="$(printf '\033')["
red_text="${CSI}91m"     # Red
green_text="${CSI}92m"   # Green
yellow_text="${CSI}93m"  # Yellow
blue_text="${CSI}94m"    # Blue
magenta_text="${CSI}95m" # Magenta
cyan_text="${CSI}96m"    # Cyan
reset_text="${CSI}0m"    # Reset to default
clear_line="${CSI}0K"    # Clear the current line to the right to wipe any artifacts remaining from last print

# STYLES
bold_text="${CSI}1m"
blinking_text="${CSI}5m"
dim_text="${CSI}2m"

# CHECK BOXES
check_box_good="[${green_text}✓${reset_text}]"       # Good
check_box_bad="[${red_text}✗${reset_text}]"          # Bad
check_box_question="[${yellow_text}?${reset_text}]"  # Question / ?
check_box_info="[${yellow_text}i${reset_text}]"      # Info / i

# PICO STATUSES
pico_status_ok="${check_box_good} Sys. OK"
pico_status_update="${check_box_info} Update"
pico_status_hot="${check_box_bad} Sys. Hot!"
pico_status_off="${check_box_bad} Offline"
pico_status_ftl_down="${check_box_info} FTL Down"
pico_status_dns_down="${check_box_bad} DNS Down"
pico_status_unknown="${check_box_question} Stat. Unk."

# MINI STATUS
mini_status_ok="${check_box_good} System OK"
mini_status_update="${check_box_info} Update avail."
mini_status_hot="${check_box_bad} System is hot!"
mini_status_off="${check_box_bad} Pi-hole off!"
mini_status_ftl_down="${check_box_info} FTL down!"
mini_status_dns_down="${check_box_bad} DNS off!"
mini_status_unknown="${check_box_question} Status unknown"

# REGULAR STATUS
full_status_ok="${check_box_good} System is healthy."
full_status_update="${check_box_info} Updates are available."
full_status_hot="${check_box_bad} System is hot!"
full_status_off="${check_box_bad} Pi-hole is offline"
full_status_ftl_down="${check_box_info} FTL is down!"
full_status_dns_down="${check_box_bad} DNS is off!"
full_status_unknown="${check_box_question} Status unknown!"

# MEGA STATUS
mega_status_ok="${check_box_good} Your system is healthy."
mega_status_update="${check_box_info} Updates are available."
mega_status_hot="${check_box_bad} Your system is hot!"
mega_status_off="${check_box_bad} Pi-hole is offline."
mega_status_ftl_down="${check_box_info} FTLDNS service is not running."
mega_status_dns_down="${check_box_bad} Pi-hole's DNS server is off!"
mega_status_unknown="${check_box_question} Unable to determine Pi-hole status."

# TINY STATUS
tiny_status_ok="${check_box_good} System is healthy."
tiny_status_update="${check_box_info} Updates are available."
tiny_status_hot="${check_box_bad} System is hot!"
tiny_status_off="${check_box_bad} Pi-hole is offline"
tiny_status_ftl_down="${check_box_info} FTL is down!"
tiny_status_dns_down="${check_box_bad} DNS is off!"
tiny_status_unknown="${check_box_question} Status unknown!"

# Text only "logos"
padd_text="${green_text}${bold_text}PADD${reset_text}"

# PADD logos - regular and retro
padd_logo_1="${bold_text}${green_text} __      __  __   ${reset_text}"
padd_logo_2="${bold_text}${green_text}|__) /\\ |  \\|  \\  ${reset_text}"
padd_logo_3="${bold_text}${green_text}|   /--\\|__/|__/  ${reset_text}"
padd_logo_retro_1="${bold_text} ${yellow_text}_${green_text}_      ${blue_text}_${magenta_text}_  ${yellow_text}_${green_text}_   ${reset_text}"
padd_logo_retro_2="${bold_text}${yellow_text}|${green_text}_${blue_text}_${cyan_text}) ${red_text}/${yellow_text}\\ ${blue_text}|  ${red_text}\\${yellow_text}|  ${cyan_text}\\  ${reset_text}"
padd_logo_retro_3="${bold_text}${green_text}|   ${red_text}/${yellow_text}-${green_text}-${blue_text}\\${cyan_text}|${magenta_text}_${red_text}_${yellow_text}/${green_text}|${blue_text}_${cyan_text}_${magenta_text}/  ${reset_text}"


############################################# GETTERS ##############################################

GetFTLData() {
    local ftl_port data
    ftl_port=$(getFTLAPIPort)
    if [ -n "$ftl_port" ]; then
      # Send command to FTL and ask to quit when finished
      data="$(echo ">$1 >quit" | nc 127.0.0.1 "${ftl_port}")"
      echo "${data}"
    else
      echo "0"
    fi
}

GetSummaryInformation() {
  summary=$(GetFTLData "stats")
  cache_info=$(GetFTLData "cacheinfo")

  clients=$(echo "${summary}" | grep "unique_clients" | grep -Eo "[0-9]+$")

  blocking_status=$(echo "${summary}" | grep "status" | grep -Eo "enabled|disabled|unknown" )

  domains_being_blocked_raw=$(echo "${summary}" | grep "domains_being_blocked" | grep -Eo "[0-9]+$")
  domains_being_blocked=$(printf "%.f" "${domains_being_blocked_raw}")

  dns_queries_today_raw=$(echo "$summary" | grep "dns_queries_today" | grep -Eo "[0-9]+$")
  dns_queries_today=$(printf "%.f" "${dns_queries_today_raw}")

  ads_blocked_today_raw=$(echo "$summary" | grep "ads_blocked_today" | grep -Eo "[0-9]+$")
  ads_blocked_today=$(printf "%.f" "${ads_blocked_today_raw}")

  ads_percentage_today_raw=$(echo "$summary" | grep "ads_percentage_today" | grep -Eo "[0-9.]+$")
  ads_percentage_today=$(printf "%.1f" "${ads_percentage_today_raw}")

  cache_size=$(echo "$cache_info" | grep "cache-size" | grep -Eo "[0-9.]+$")
  cache_deletes=$(echo "$cache_info" | grep "cache-live-freed" | grep -Eo "[0-9.]+$")
  cache_inserts=$(echo "$cache_info"| grep "cache-inserted" | grep -Eo "[0-9.]+$")

  latest_blocked=$(GetFTLData recentBlocked)

  top_blocked=$(GetFTLData "top-ads (1)" | awk '{print $3}')

  top_domain=$(GetFTLData "top-domains (1)" | awk '{print $3}')

  top_client_raw=$(GetFTLData "top-clients (1)" | awk '{print $4}')
  if [ -z "${top_client_raw}" ]; then
    top_client=$(GetFTLData "top-clients (1)" | awk '{print $3}')
  else
    top_client="${top_client_raw}"
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
  elif [ "$1" = "tiny" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 30 "color")

    if [ ${#latest_blocked} -gt 38 ]; then
      latest_blocked=$(echo "$latest_blocked" | cut -c1-38)"..."
    fi

    if [ ${#top_blocked} -gt 38 ]; then
      top_blocked=$(echo "$top_blocked" | cut -c1-38)"..."
    fi

    if [ ${#top_domain} -gt 38 ]; then
      top_domain=$(echo "$top_domain" | cut -c1-38)"..."
    fi

    if [ ${#top_client} -gt 38 ]; then
      top_client=$(echo "$top_client" | cut -c1-38)"..."
    fi
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 40 "color")
  else
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 30 "color")
  fi
}

GetSystemInformation() {
  # System uptime
  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    system_uptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/){if ($9=="min") {d=$6;m=$8} else {d=$6;h=$8;m=$9}} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours"}')
  else
    system_uptime=$(uptime | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/){if ($9=="min") {d=$6;m=$8} else {d=$6;h=$8;m=$9}} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')
  fi

  # CPU temperature
  if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    cpu=$(cat /sys/class/thermal/thermal_zone0/temp)
  elif [ -f /sys/class/hwmon/hwmon0/temp1_input ]; then
    cpu=$(cat /sys/class/hwmon/hwmon0/temp1_input)
  else
    cpu=0
  fi

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" = "F" ]; then
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 * 9 / 5000 + 32}')")°F"
  elif [ "${TEMPERATUREUNIT}" = "K" ]; then
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 / 1000 + 273.15}')")°K"
  # Addresses Issue 1: https://github.com/jpmck/PAD/issues/1
  else
    temperature="$(printf %.1f "$(echo "${cpu}" | awk '{print $1 / 1000}')")°C"
  fi

  # CPU load, heatmap
  cpu_load_1=$(awk '{print $1}' < /proc/loadavg)
  cpu_load_5=$(awk '{print $2}' < /proc/loadavg)
  cpu_load_15=$(awk '{print $3}' < /proc/loadavg)
  cpu_load_1_heatmap=$(HeatmapGenerator "${cpu_load_1}" "${core_count}")
  cpu_load_5_heatmap=$(HeatmapGenerator "${cpu_load_5}" "${core_count}")
  cpu_load_15_heatmap=$(HeatmapGenerator "${cpu_load_15}" "${core_count}")
  cpu_percent=$(printf %.1f "$(echo "${cpu_load_1} ${core_count}" | awk '{print ($1 / $2) * 100}')")

  # CPU temperature heatmap
  # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)
  if [ ${cpu} -gt 80000 ]; then
    temp_heatmap=${blinking_text}${red_text}
    pico_status="${pico_status_hot}"
    mini_status="${mini_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
    tiny_status="${tiny_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
    full_status="${full_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
    mega_status="${mega_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
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
  elif [ "$1" = "tiny" ]; then
    cpu_bar=$(BarGenerator "${cpu_percent}" 7)
    memory_bar=$(BarGenerator "${memory_percent}" 7)
  else
    cpu_bar=$(BarGenerator "${cpu_percent}" 10)
    memory_bar=$(BarGenerator "${memory_percent}" 10)
  fi

  # Device model
  if [ -f /sys/firmware/devicetree/base/model ]; then
    # Get model, remove possible null byte
    sys_model=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
  else
    sys_model=""
  fi
}

GetNetworkInformation() {
  # Get pi IPv4 address
  pi_ip4_addrs="$(ip addr | grep 'inet ' | grep -v '127.0.0.1/8' | awk '{print $2}' | cut -f1 -d'/' |wc -l)"
  if [ "${pi_ip4_addrs}" -eq 0 ]; then
    # No IPv4 address available
    pi_ip4_addr="N/A"
  elif [ "${pi_ip4_addrs}" -eq 1 ]; then
    # One IPv4 address available
    pi_ip4_addr="$(ip addr | grep 'inet ' | grep -v '127.0.0.1/8' | awk '{print $2}' | cut -f1 -d'/' | head -n 1)"
  else
    # More than one IPv4 address available
    pi_ip4_addr="$(ip addr | grep 'inet ' | grep -v '127.0.0.1/8' | awk '{print $2}' | cut -f1 -d'/' | head -n 1)+"
  fi

  # Get pi IPv6 address
  pi_ip6_addrs="$(ip addr | grep 'inet6 ' | grep -v '::1/128' | awk '{print $2}' | cut -f1 -d'/' | wc -l)"
  if [ "${pi_ip6_addrs}" -eq 0 ]; then
    # No IPv6 address available
    pi_ip6_addr="N/A"
  elif [ "${pi_ip6_addrs}" -eq 1 ]; then
    # One IPv6 address available
    pi_ip6_addr="$(ip addr | grep 'inet6 ' | grep -v '::1/128' | awk '{print $2}' | cut -f1 -d'/' | head -n 1)"
  else
    # More than one IPv6 address available
    pi_ip6_addr="$(ip addr | grep 'inet6 ' | grep -v '::1/128' | awk '{print $2}' | cut -f1 -d'/' | head -n 1)+"
  fi

  # Get hostname and gateway
  pi_hostname=$(hostname)
  pi_gateway=$(ip r | grep 'default' | awk '{print $3}')

  full_hostname=${pi_hostname}
  # does the Pi-hole have a domain set?
  if [ -n "${PIHOLE_DOMAIN+x}" ]; then
    # is Pi-hole acting as DHCP server?
    if [ "${DHCP_ACTIVE}" = "true" ]; then
      count=${pi_hostname}"."${PIHOLE_DOMAIN}
      count=${#count}
      if [ "${count}" -lt "18" ]; then
        full_hostname=${pi_hostname}"."${PIHOLE_DOMAIN}
      fi
    fi
  fi

  # Get the DNS count (from pihole -c)
  dns_count="0"
  [ -n "${PIHOLE_DNS_1}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_2}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_3}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_4}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_5}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_6}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_7}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_8}" ] && dns_count=$((dns_count+1))
  [ -n "${PIHOLE_DNS_9}" ] && dns_count=$((dns_count+1))

  # if there's only one DNS server
  if [ ${dns_count} -eq 1 ]; then
    if [ "${PIHOLE_DNS_1}" = "127.0.0.1#5053" ]; then
      dns_information="1 server (Cloudflared)"
    elif [ "${PIHOLE_DNS_1}" = "${pi_gateway}#53" ]; then
      dns_information="1 server (gateway)"
    else
      dns_information="1 server"
    fi
  elif [ ${dns_count} -gt 8 ]; then
    dns_information="8+ servers"
  else
    dns_information="${dns_count} servers"
  fi

  # Is Pi-Hole acting as the DHCP server?
  if [ "${DHCP_ACTIVE}" = "true" ]; then
    dhcp_status="Enabled"
    dhcp_info=" Range:    ${DHCP_START} - ${DHCP_END}"
    dhcp_heatmap=${green_text}
    dhcp_check_box=${check_box_good}

    # Is DHCP handling IPv6?
    # DHCP_IPv6 is set in setupVars.conf
    # shellcheck disable=SC2154
    if [ "${DHCP_IPv6}" = "true" ]; then
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
    dhcp_heatmap=${red_text}
    dhcp_check_box=${check_box_bad}

    # if the DHCP Router variable isn't set
    # Issue 3: https://github.com/jpmck/PADD/issues/3
    if [ -z ${DHCP_ROUTER+x} ]; then
      DHCP_ROUTER=$(GetFTLData "gateway" | awk '{ printf $1 }')
    fi

    dhcp_info=" Router:   ${DHCP_ROUTER}"
    dhcp_heatmap=${red_text}
    dhcp_check_box=${check_box_bad}

    dhcp_ipv6_status="N/A"
    dhcp_ipv6_heatmap=${yellow_text}
    dhcp_ipv6_check_box=${check_box_question}
  fi

  # DNSSEC
  if [ "${DNSSEC}" = "true" ]; then
    dnssec_status="Enabled"
    dnssec_heatmap=${green_text}
  else
    dnssec_status="Disabled"
    dnssec_heatmap=${red_text}
  fi

  # Conditional forwarding
  if [ "${CONDITIONAL_FORWARDING}" = "true" ] || [ "${REV_SERVER}" = "true" ]; then
    conditional_forwarding_status="Enabled"
    conditional_forwarding_heatmap=${green_text}
  else
    conditional_forwarding_status="Disabled"
    conditional_forwarding_heatmap=${red_text}
  fi

  #Default interface data
  def_iface_data=$(GetFTLData "interfaces" | head -n1)
  iface_name="$(echo "$def_iface_data" | awk '{print $1}')"
  tx_bytes="$(echo "$def_iface_data" | awk '{print $4}')"
  rx_bytes="$(echo "$def_iface_data" | awk '{print $5}')"
}

GetPiholeInformation() {
  # Get FTL status
  ftlPID=$(pidof pihole-FTL)

  if [ -z ${ftlPID+x} ]; then
    ftl_status="Not running"
    ftl_heatmap=${yellow_text}
    ftl_check_box=${check_box_info}
    pico_status=${pico_status_ftl_down}
    mini_status=${mini_status_ftl_down}
    tiny_status=${tiny_status_ftl_down}
    full_status=${full_status_ftl_down}
    mega_status=${mega_status_ftl_down}
  else
    ftl_status="Running"
    ftl_heatmap=${green_text}
    ftl_check_box=${check_box_good}
    ftl_cpu="$(ps -p "${ftlPID}" -o %cpu | tail -n1 | tr -d '[:space:]')"
    ftl_mem_percentage="$(ps -p "${ftlPID}" -o %mem | tail -n1 | tr -d '[:space:]')"
  fi

  # Get Pi-hole (blocking) status
  ftl_dns_port=$(GetFTLData "dns-port")

  # ${ftl_dns_port} == 0 DNS server part of dnsmasq disabled, ${ftl_status} == "Not running" no ftlPID found
  if [ "${ftl_dns_port}" = 0 ] || [ "${ftl_status}" = "Not running" ]; then
    pihole_status="DNS Offline"
    pihole_heatmap=${red_text}
    pihole_check_box=${check_box_bad}
    pico_status=${pico_status_dns_down}
    mini_status=${mini_status_dns_down}
    tiny_status=${tiny_status_dns_down}
    full_status=${full_status_dns_down}
    mega_status=${mega_status_dns_down}
  else
    if [ "${blocking_status}" = "enabled" ]; then
      pihole_status="Active"
      pihole_heatmap=${green_text}
      pihole_check_box=${check_box_good}
    fi
    if [ "${blocking_status}" = "disabled" ]; then
      pihole_status="Blocking disabled"
      pihole_heatmap=${red_text}
      pihole_check_box=${check_box_bad}
      pico_status=${pico_status_off}
      mini_status=${mini_status_off}
      tiny_status=${tiny_status_off}
      full_status=${full_status_off}
      mega_status=${mega_status_off}
    fi
    if [ "${blocking_status}" = "unknown" ]; then
      pihole_status="Unknown"
      pihole_heatmap=${yellow_text}
      pihole_check_box=${check_box_question}
      pico_status=${pico_status_unknown}
      mini_status=${mini_status_unknown}
      tiny_status=${tiny_status_unknown}
      full_status=${full_status_unknown}
      mega_status=${mega_status_unknown}
    fi
  fi

}

GetVersionInformation() {
  # Check if version status has been saved
  core_version=$(pihole -v -p | awk '{print $4}' | tr -d '[:alpha:]')
  core_version_latest=$(pihole -v -p | awk '{print $(NF)}' | tr -d ')')

  # if core_version is something else then x.xx or x.xx.xxx set it to N/A
  if ! echo "${core_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ "${core_version_latest}" = "ERROR" ]; then
    core_version="N/A"
    core_version_heatmap=${yellow_text}
  else
    # remove the leading "v" from core_version_latest
    core_version_latest=$(echo "${core_version_latest}" | tr -d '\r\n[:alpha:]')
    # is core up-to-date?
    if [ "${core_version}" != "${core_version_latest}" ]; then
      out_of_date_flag="true"
      core_version_heatmap=${red_text}
    else
      core_version_heatmap=${green_text}
    fi
    # add leading "v" to version number
    core_version="v${core_version}"
  fi

  # Gather web version information...
  if [ "$INSTALL_WEB_INTERFACE" = true ]; then
    web_version=$(pihole -v -a | awk '{print $4}' | tr -d '[:alpha:]')
    web_version_latest=$(pihole -v -a | awk '{print $(NF)}' | tr -d ')')

    # if web_version is something else then x.xx or x.xx.xxx set it to N/A
    if ! echo "${web_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ "${web_version_latest}" = "ERROR" ]; then
      web_version="N/A"
      web_version_heatmap=${yellow_text}
    else
      # remove the leading "v" from web_version_latest
      web_version_latest=$(echo "${web_version_latest}" | tr -d '\r\n[:alpha:]')
      # is web up-to-date?
      if [ "${web_version}" != "${web_version_latest}" ]; then
        out_of_date_flag="true"
        web_version_heatmap=${red_text}
      else
        web_version_heatmap=${green_text}
      fi
      # add leading "v" to version number
      web_version="v${web_version}"
    fi
  else
    # Web interface not installed
    web_version="N/A"
    web_version_heatmap=${yellow_text}
  fi

  # Gather FTL version information...
  ftl_version=$(pihole -v -f | awk '{print $4}' | tr -d '[:alpha:]')
  ftl_version_latest=$(pihole -v -f | awk '{print $(NF)}' | tr -d ')')

  # if ftl_version is something else then x.xx or x.xx.xxx set it to N/A
  if ! echo "${ftl_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ "${ftl_version_latest}" = "ERROR" ]; then
    ftl_version="N/A"
    ftl_version_heatmap=${yellow_text}
  else
    # remove the leading "v" from ftl_version_latest
    ftl_version_latest=$(echo "${ftl_version_latest}" | tr -d '\r\n[:alpha:]')
    # is ftl up-to-date?
    if [ "${ftl_version}" != "${ftl_version_latest}" ]; then
      out_of_date_flag="true"
      ftl_version_heatmap=${red_text}
    else
      ftl_version_heatmap=${green_text}
    fi
  # add leading "v" to version number
  ftl_version="v${ftl_version}"
  fi

  # PADD version information...
  padd_version_latest="$(curl --silent https://api.github.com/repos/pi-hole/PADD/releases/latest | grep '"tag_name":' | awk -F \" '{print $4}')"
  # is PADD up-to-date?
  if [ -z "${padd_version_latest}" ]; then
    padd_version_heatmap=${yellow_text}
  else
    padd_version_latest_converted="$(VersionConverter "${padd_version_latest}")"
    padd_version_converted=$(VersionConverter "${padd_version}")

    if [ "${padd_version_converted}" -lt "${padd_version_latest_converted}" ]; then
      padd_out_of_date_flag="true"
      padd_version_heatmap=${red_text}
    else
      # local and remote PADD version match or local is newer
      padd_version_heatmap=${green_text}
    fi
  fi


  # was any portion of Pi-hole out-of-date?
  # yes, pi-hole is out of date
  if [ "${out_of_date_flag}" = "true" ]; then
    version_status="Pi-hole is out-of-date!"
    pico_status=${pico_status_update}
    mini_status=${mini_status_update}
    tiny_status=${tiny_status_update}
    full_status=${full_status_update}
    mega_status=${mega_status_update}
  else
    # but is PADD out-of-date?
    if [ "${padd_out_of_date_flag}" = "true" ]; then
      version_status="PADD is out-of-date!"
      pico_status=${pico_status_update}
      mini_status=${mini_status_update}
      tiny_status=${tiny_status_update}
      full_status=${full_status_update}
      mega_status=${mega_status_update}
    # else, everything is good!
    else
      version_status="Pi-hole is up-to-date!"
      pico_status=${pico_status_ok}
      mini_status=${mini_status_ok}
      tiny_status=${tiny_status_ok}
      full_status=${full_status_ok}
      mega_status=${mega_status_ok}
    fi
  fi
}

############################################# PRINTERS #############################################

PrintLogo() {
  # Screen size checks
  if [ "$1" = "pico" ]; then
    printf "%s${clear_line}\n" "p${padd_text} ${pico_status}"
  elif [ "$1" = "nano" ]; then
    printf "%s${clear_line}\n" "n${padd_text} ${mini_status}"
  elif [ "$1" = "micro" ]; then
    printf "%s${clear_line}\n${clear_line}\n" "µ${padd_text}     ${mini_status}"
  elif [ "$1" = "mini" ]; then
    printf "%s${clear_line}\n${clear_line}\n" "${padd_text}${dim_text}mini${reset_text}  ${mini_status}"
  elif [ "$1" = "tiny" ]; then
    printf "%s${clear_line}\n" "${padd_text}${dim_text}tiny${reset_text}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}"
    printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}"
  elif [ "$1" = "slim" ]; then
    printf "%s${clear_line}\n${clear_line}\n" "${padd_text}${dim_text}slim${reset_text}   ${full_status}"
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    printf "%s${clear_line}\n" "${padd_logo_1}"
    printf "%s${clear_line}\n" "${padd_logo_2}Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}"
    printf "%s${clear_line}\n${clear_line}\n" "${padd_logo_3}PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
  # normal or not defined
  else
    printf "%s${clear_line}\n" "${padd_logo_retro_1}"
    printf "%s${clear_line}\n" "${padd_logo_retro_2}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}, PADD ${padd_version_heatmap}${padd_version}${reset_text}"
    printf "%s${clear_line}\n${clear_line}\n" "${padd_logo_retro_3}   ${pihole_check_box} Core  ${ftl_check_box} FTL   ${mega_status}${reset_text}"
  fi
}

PrintDashboard() {
    if [ "$1" = "pico" ]; then
        # pico is a screen at least 20x10 (columns x lines)
        printf "%s${clear_line}\n" "p${padd_text} ${pico_status}"
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ============${reset_text}"
        printf "%s${clear_line}\n" " [${ads_blocked_bar}] ${ads_percentage_today}%"
        printf "%s${clear_line}\n" " ${ads_blocked_today} / ${dns_queries_today}"
        printf "%s${clear_line}\n" "${bold_text}NETWORK ============${reset_text}"
        printf "%s${clear_line}\n" " Hst: ${pi_hostname}"
        printf "%s${clear_line}\n" " IP:  ${pi_ip4_addr}"
        printf "%s${clear_line}\n" " DHCP ${dhcp_check_box} IPv6 ${dhcp_ipv6_check_box}"
        printf "%s${clear_line}\n" "${bold_text}CPU ================${reset_text}"
        printf "%s${clear_line}" " [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    elif [ "$1" = "nano" ]; then
        # nano is a screen at least 24x12 (columns x lines)
        printf "%s${clear_line}\n" "n${padd_text} ${mini_status}"
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ================${reset_text}"
        printf "%s${clear_line}\n" " Up:  ${pihole_check_box}      FTL: ${ftl_check_box}"
        printf "%s${clear_line}\n" " Blk: [${ads_blocked_bar}] ${ads_percentage_today}%"
        printf "%s${clear_line}\n" " Blk: ${ads_blocked_today} / ${dns_queries_today}"
        printf "%s${clear_line}\n" "${bold_text}NETWORK ================${reset_text}"
        printf "%s${clear_line}\n" " Host: ${pi_hostname}"
        printf "%s${clear_line}\n" " IP:   ${pi_ip4_addr}"
        printf "%s${clear_line}\n" " DHCP: ${dhcp_check_box}    IPv6: ${dhcp_ipv6_check_box}"
        printf "%s${clear_line}\n" "${bold_text}SYSTEM =================${reset_text}"
        printf "%s${clear_line}\n" " Up:  ${system_uptime}"
        printf "%s${clear_line}"  " CPU: [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    elif [ "$1" = "micro" ]; then
        # micro is a screen at least 30x16 (columns x lines)
        printf "%s${clear_line}\n" "µ${padd_text}     ${mini_status}"
        printf "%s${clear_line}\n" ""
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ======================${reset_text}"
        printf "%s${clear_line}\n" " Status:  ${pihole_check_box}      FTL:  ${ftl_check_box}"
        printf "%s${clear_line}\n" "${bold_text}STATS ========================${reset_text}"
        printf "%s${clear_line}\n" " Blckng:  ${domains_being_blocked} domains"
        printf "%s${clear_line}\n" " Piholed: [${ads_blocked_bar}] ${ads_percentage_today}%"
        printf "%s${clear_line}\n" " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
        printf "%s${clear_line}\n" "${bold_text}NETWORK ======================${reset_text}"
        printf "%s${clear_line}\n" " Host:    ${full_hostname}"
        printf "%s${clear_line}\n" " IP:      ${pi_ip4_addr}"
        printf "%s${clear_line}\n" " DHCP:    ${dhcp_check_box}     IPv6:  ${dhcp_ipv6_check_box}"
        printf "%s${clear_line}\n" "${bold_text}SYSTEM =======================${reset_text}"
        printf "%s${clear_line}\n" " Uptime:  ${system_uptime}"
        printf "%s${clear_line}\n" " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
        printf "%s${clear_line}" " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
    elif [ "$1" = "mini" ]; then
        # mini is a screen at least 40x18 (columns x lines)
        printf "%s${clear_line}\n" "${padd_text}${dim_text}mini${reset_text}  ${mini_status}"
        printf "%s${clear_line}\n" ""
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ================================${reset_text}"
        printf " %-9s${pihole_heatmap}%-10s${reset_text} %-9s${ftl_heatmap}%-10s${reset_text}${clear_line}\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
        printf "%s${clear_line}\n" "${bold_text}STATS ==================================${reset_text}"
        printf " %-9s%-29s${clear_line}\n" "Blckng:" "${domains_being_blocked} domains"
        printf " %-9s[%-20s] %-5s${clear_line}\n" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        printf " %-9s%-29s${clear_line}\n" "Piholed:" "${ads_blocked_today} out of ${dns_queries_today}"
        printf " %-9s%-29s${clear_line}\n" "Latest:" "${latest_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            printf " %-9s%-29s${clear_line}\n" "Top Ad:" "${top_blocked}"
        fi
        printf "%s${clear_line}\n" "${bold_text}NETWORK ================================${reset_text}"
        printf " %-9s%-19s${clear_line}\n" "Host:" "${full_hostname}"
        printf " %-9s%-19s${clear_line}\n" "IP:"   "${pi_ip4_addr}"
        printf " %-9s%-8s %-4s%-5s %-4s%-5s${clear_line}\n" "Iface:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        printf " %-9s%-10s${clear_line}\n" "DNS:" "${dns_information}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            printf " %-9s${dhcp_heatmap}%-10s${reset_text} %-9s${dhcp_ipv6_heatmap}%-10s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
        fi
        printf "%s${clear_line}\n" "${bold_text}SYSTEM =================================${reset_text}"
        printf " %-9s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        printf "%s${clear_line}\n" " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
        printf "%s${clear_line}" " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
    elif [ "$1" = "tiny" ]; then
         # tiny is a screen at least 53x20 (columns x lines)
        printf "%s${clear_line}\n" "${padd_text}${dim_text}tiny${reset_text}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}"
        printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}"
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ============================================${reset_text}"
        printf " %-10s${pihole_heatmap}%-16s${reset_text} %-8s${ftl_heatmap}%-10s${reset_text}${clear_line}\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
        printf "%s${clear_line}\n" "${bold_text}STATS ==============================================${reset_text}"
        printf " %-10s%-29s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains"
        printf " %-10s[%-30s] %-5s${clear_line}\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        printf " %-10s%-39s${clear_line}\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today}"
        printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
            printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        fi
        printf "%s${clear_line}\n" "${bold_text}NETWORK ============================================${reset_text}"
        printf " %-10s%-16s %-8s%-16s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:  " "${pi_ip4_addr}"
        printf " %-10s%-16s${clear_line}\n" "IPv6:" "${pi_ip6_addr}"
        printf " %-10s%-16s %-4s%-5s %-4s%-5s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        printf " %-10s%-16s %-8s%-16s${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            printf " %-10s${dhcp_heatmap}%-16s${reset_text} %-8s${dhcp_ipv6_heatmap}%-10s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
            printf "%s${clear_line}\n" "${dhcp_info}"
        fi
        printf "%s${clear_line}\n" "${bold_text}SYSTEM =============================================${reset_text}"
        printf " %-10s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        printf " %-10s${temp_heatmap}%-17s${reset_text} %-8s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Temp:" "${temperature}" "Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        printf " %-10s[${memory_heatmap}%-7s${reset_text}] %-6s %-8s[${cpu_load_1_heatmap}%-7s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU:" "${cpu_bar}" "${cpu_percent}%"
    elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
        # slim is a screen with at least 60 columns and exactly 21 lines
        # regular is a screen at least 60x22 (columns x lines)
        if [ "$1" = "slim" ]; then
           printf "%s${clear_line}\n" "${padd_text}${dim_text}slim${reset_text}   ${full_status}"
           printf "%s${clear_line}\n" ""
        else
            printf "%s${clear_line}\n" "${padd_logo_1}"
            printf "%s${clear_line}\n" "${padd_logo_2}Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}"
            printf "%s${clear_line}\n" "${padd_logo_3}PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
            printf "%s${clear_line}\n" ""
        fi
        printf "%s${clear_line}\n" "${bold_text}PI-HOLE ===================================================${reset_text}"
        printf " %-10s${pihole_heatmap}%-19s${reset_text} %-10s${ftl_heatmap}%-19s${reset_text}${clear_line}\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
        printf "%s${clear_line}\n" "${bold_text}STATS =====================================================${reset_text}"
        printf " %-10s%-49s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains"
        printf " %-10s[%-40s] %-5s${clear_line}\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        printf " %-10s%-49s${clear_line}\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
        printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
            printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        fi
        printf "%s${clear_line}\n" "${bold_text}NETWORK ===================================================${reset_text}"
        printf " %-10s%-19s %-10s%-19s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:" "${pi_ip4_addr}"
        printf " %-10s%-19s${clear_line}\n" "IPv6:" "${pi_ip6_addr}"
        printf " %-10s%-19s %-4s%-5s %-4s%-5s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        printf " %-10s%-19s %-10s%-19s${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            printf " %-10s${dhcp_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-19s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
            printf "%s${clear_line}\n" "${dhcp_info}"
        fi
        printf "%s${clear_line}\n" "${bold_text}SYSTEM ====================================================${reset_text}"
        printf " %-10s%-39s${clear_line}\n" "Device:" "${sys_model}"
        printf " %-10s%-39s${clear_line}\n" "Uptime:" "${system_uptime}"
        printf " %-10s${temp_heatmap}%-20s${reset_text}${clear_line}" "CPU Temp:" "${temperature}"
        printf " %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        printf " %-10s[${memory_heatmap}%-10s${reset_text}] %-6s %-10s[${cpu_load_1_heatmap}%-10s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
    else # ${padd_size} = mega
         # mega is a screen with at least 80 columns and 26 lines
        printf "%s${clear_line}\n" "${padd_logo_retro_1}"
        printf "%s${clear_line}\n" "${padd_logo_retro_2}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}, PADD ${padd_version_heatmap}${padd_version}${reset_text}"
        printf "%s${clear_line}\n" "${padd_logo_retro_3}   ${pihole_check_box} Core  ${ftl_check_box} FTL   ${mega_status}${reset_text}"
        printf "%s${clear_line}\n" ""
        printf "%s${clear_line}\n" "${bold_text}STATS =========================================================================${reset_text}"
        printf " %-10s%-19s %-10s[%-40s] %-5s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        printf " %-10s%-30s%-29s${clear_line}\n" "Clients:" "${clients}" " ${ads_blocked_today} out of ${dns_queries_today} queries"
        printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
        printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        printf "%s${clear_line}\n" "FTL ==========================================================================="
        printf " %-10s%-9s %-10s%-9s %-10s%-9s${clear_line}\n" "PID:" "${ftlPID}" "CPU Use:" "${ftl_cpu}%" "Mem. Use:" "${ftl_mem_percentage}%"
        printf " %-10s%-69s${clear_line}\n" "DNSCache:" "${cache_inserts} insertions, ${cache_deletes} deletions, ${cache_size} total entries"
        printf "%s${clear_line}\n" "${bold_text}NETWORK =======================================================================${reset_text}"
        printf " %-10s%-19s${clear_line}\n" "Hostname:" "${full_hostname}"
        printf " %-11s%-14s %-4s%-9s %-4s%-9s${clear_line}\n" "Interface:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        printf " %-6s%-19s %-10s%-29s${clear_line}\n" "IPv4:" "${pi_ip4_addr}" "IPv6:" "${pi_ip6_addr}"
        printf "%s${clear_line}\n" "DNS ==========================================================================="
        printf " %-10s%-39s${clear_line}\n" "Servers:" "${dns_information}"
        printf " %-10s${dnssec_heatmap}%-19s${reset_text} %-20s${conditional_forwarding_heatmap}%-9s${reset_text}${clear_line}\n" "DNSSEC:" "${dnssec_status}" "Conditional Fwding:" "${conditional_forwarding_status}"
        printf "%s${clear_line}\n" "DHCP =========================================================================="
        printf " %-10s${dhcp_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-9s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6 Spt:" "${dhcp_ipv6_status}"
        printf "%s${clear_line}\n" "${dhcp_info}"
        printf "%s${clear_line}\n" "${bold_text}SYSTEM ========================================================================${reset_text}"
        printf " %-10s%-39s${clear_line}\n" "Device:" "${sys_model}"
        printf " %-10s%-39s %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}\n" "Uptime:" "${system_uptime}" "Memory:" "${memory_bar}" "${memory_percent}%"
        printf " %-10s${temp_heatmap}%-10s${reset_text} %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-7s${reset_text} %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
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
  frontFill=$(for i in $(seq "$barNumber"); do printf "%b" "■"; done)

  # remaining "unfilled" cells in the bar
  backfillNumber=$(($2-barNumber))

  # if the filled in cells is less than the max length of the bar, fill it
  if [ "$barNumber" -lt "$2" ]; then
    # if the bar should be colored
    if [ "$3" = "color" ]; then
      # fill the rest in color
      backFill=$(for i in $(seq $backfillNumber); do printf "%b" "■"; done)
      out="${red_text}${frontFill}${green_text}${backFill}${reset_text}"
    # else, it shouldn't be colored in
    else
      # fill the rest with "space"
      backFill=$(for i in $(seq $backfillNumber); do printf "%b" "·"; done)
      out="${frontFill}${reset_text}${backFill}"
    fi
  # else, fill it all the way
  else
    out=$(for i in $(seq "$2"); do printf "%b" "■"; done)
  fi

  echo "$out"
}

# Checks the size of the screen and sets the value of padd_size
SizeChecker(){
  # Below Pico. Gives you nothing...
  if [ "$console_width" -lt "20" ] || [ "$console_height" -lt "10" ]; then
    # Nothing is this small, sorry
    clear
    printf "%b" "${check_box_bad} Error!\n    PADD isn't\n    for ants!\n"
    exit 1
  # Below Nano. Gives you Pico.
  elif [ "$console_width" -lt "24" ] || [ "$console_height" -lt "12" ]; then
    padd_size="pico"
  # Below Micro, Gives you Nano.
  elif [ "$console_width" -lt "30" ] || [ "$console_height" -lt "16" ]; then
    padd_size="nano"
  # Below Mini. Gives you Micro.
  elif [ "$console_width" -lt "40" ] || [ "$console_height" -lt "18" ]; then
    padd_size="micro"
  # Below Tiny. Gives you Mini.
  elif [ "$console_width" -lt "53" ] || [ "$console_height" -lt "20" ]; then
      padd_size="mini"
  # Below Slim. Gives you Tiny.
  elif [ "$console_width" -lt "60" ] || [ "$console_height" -lt "21" ]; then
      padd_size="tiny"
  # Below Regular. Gives you Slim.
  elif [ "$console_width" -lt "80" ] || [ "$console_height" -lt "26" ]; then
    if [ "$console_height" -lt "22" ]; then
      padd_size="slim"
    else
      padd_size="regular"
    fi
  # Mega
  else
    padd_size="mega"
  fi
}

CheckConnectivity() {
    local connectivity connection_attempts wait_timer

    connectivity="false"
    connection_attempts=1
    wait_timer=1

    while [ $connection_attempts -lt 9 ]; do

        if nc -zw1 google.com 443 2>/dev/null; then
            if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
                echo "Attempt #${connection_attempts} passed..."
            elif [ "$1" = "mini" ]; then
                echo "Attempt ${connection_attempts} passed."
            else
                echo "  - Attempt ${connection_attempts} passed...                                     "
            fi

            connectivity="true"
            connection_attempts=11
        else
            connection_attempts=$((connection_attempts+1))
            local inner_wait_timer
            inner_wait_timer=$((wait_timer*1))

            # echo "$wait_timer = $inner_wait_timer"
            while [ $inner_wait_timer -gt 0 ]; do
                if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
                    printf "%b" "Attempt #${connection_attempts} failed...\r"
                elif [ "$1" = "mini" ] || [ "$1" = "tiny" ]; then
                    printf "%b" "- Attempt ${connection_attempts} failed, wait ${inner_wait_timer}  \r"
                else
                    printf "%b" "  - Attempt ${connection_attempts} failed... waiting ${inner_wait_timer} seconds...  \r"
                fi
                sleep 1
                inner_wait_timer=$((inner_wait_timer-1))
            done

            # echo -ne "Attempt $connection_attempts failed... waiting $wait_timer seconds...\r"
            # sleep $wait_timer
            wait_timer=$((wait_timer*2))
        fi

    done

    if [ "$connectivity" = "false" ]; then
        if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
            echo "Check failed..."
        elif [ "$1" = "mini" ] || [ "$1" = "tiny" ]; then
            echo "- Connectivity check failed."
        else
            echo "  - Connectivity check failed..."
        fi
    else
        if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
            echo "Check passed..."
        elif [ "$1" = "mini" ] || [ "$1" = "tiny" ]; then
            echo "- Connectivity check passed."
        else
            echo "  - Connectivity check passed..."
        fi
    fi
}

# converts a given version string e.g. v3.7.1 to 3007001000 to allow for easier comparison of multi digit version numbers
# credits https://apple.stackexchange.com/a/123408
VersionConverter() {
  echo "$@" | tr -d '[:alpha:]' | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}

# get the Telnet API Port FTL is using by parsing `pihole-FTL.conf`
# same implementation as https://github.com/pi-hole/pi-hole/pull/4945
getFTLAPIPort(){
    local FTLCONFFILE="/etc/pihole/pihole-FTL.conf"
    local DEFAULT_FTL_PORT=4711
    local ftl_api_port

    if [ -s "$FTLCONFFILE" ]; then
        # if FTLPORT is not set in pihole-FTL.conf, use the default port
        ftl_api_port="$({ grep '^FTLPORT=' "${FTLCONFFILE}" || echo "${DEFAULT_FTL_PORT}"; } | cut -d'=' -f2-)"
        # Exploit prevention: set the port to the default port if there is malicious (non-numeric)
        # content set in pihole-FTL.conf
        expr "${ftl_api_port}" : "[^[:digit:]]" > /dev/null && ftl_api_port="${DEFAULT_FTL_PORT}"
    else
        # if there is no pihole-FTL.conf, use the default port
        ftl_api_port="${DEFAULT_FTL_PORT}"
    fi

    echo "${ftl_api_port}"

}

########################################## MAIN FUNCTIONS ##########################################

OutputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw},\"clients\": ${clients}}"
}

StartupRoutine(){
    # Get config variables
  . /etc/pihole/setupVars.conf

  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    PrintLogo "$1"
    printf "%b" "START-UP ===========\n"
    printf "%b" "Checking connection.\n"
    CheckConnectivity "$1"
    printf "%b" "Starting PADD...\n"

    printf "%b" " [■·········]  10%\r"

    # Check for updates
    printf "%b" " [■■········]  20%\r"
    printf "%b" " [■■■·······]  30%\r"

    # Get our information for the first time
    printf "%b" " [■■■■······]  40%\r"
    GetSystemInformation "$1"
    printf "%b" " [■■■■■·····]  50%\r"
    GetSummaryInformation "$1"
    printf "%b" " [■■■■■■····]  60%\r"
    GetPiholeInformation "$1"
    printf "%b" " [■■■■■■■···]  70%\r"
    GetNetworkInformation "$1"
    printf "%b" " [■■■■■■■■··]  80%\r"
    GetVersionInformation "$1"
    printf "%b" " [■■■■■■■■■·]  90%\r"
    printf "%b" " [■■■■■■■■■■] 100%\n"

  elif [ "$1" = "mini" ]; then
    PrintLogo "$1"
    echo "START UP ====================="
    echo "Checking connectivity."
    CheckConnectivity "$1"

    echo "Starting PADD."

    # Get our information for the first time
    echo "- Gathering system info."
    GetSystemInformation "mini"
    echo "- Gathering Pi-hole info."
    GetPiholeInformation "mini"
    GetSummaryInformation "mini"
    echo "- Gathering network info."
    GetNetworkInformation "mini"
    echo "- Gathering version info."
    GetVersionInformation "mini"
    echo "  - Core $core_version, Web $web_version"
    echo "  - FTL $ftl_version, PADD $padd_version"
    echo "  - $version_status"

  else
    printf "%b" "${padd_logo_retro_1}\n"
    printf "%b" "${padd_logo_retro_2}Pi-hole® Ad Detection Display\n"
    printf "%b" "${padd_logo_retro_3}A client for Pi-hole\n\n"
    if [ "$1" = "tiny" ]; then
      echo "START UP ============================================"
    else
      echo "START UP ==================================================="
    fi

    printf "%b" "- Checking internet connection...\n"
    CheckConnectivity "$1"

    # Get our information for the first time
    echo "- Gathering system information..."
    GetSystemInformation "$1"
    echo "- Gathering Pi-hole information..."
    GetSummaryInformation "$1"
    GetPiholeInformation "$1"
    echo "- Gathering network information..."
    GetNetworkInformation "$1"
    echo "- Gathering version information..."
    GetVersionInformation "$1"
    echo "  - Pi-hole Core $core_version"
    echo "  - Web Admin $web_version"
    echo "  - FTL $ftl_version"
    echo "  - PADD $padd_version"
    echo "  - $version_status"
  fi

  printf "%s" "- Starting in "

  for i in 3 2 1
  do
    printf "%s..." "$i"
    sleep 1
  done
}

NormalPADD() {
  while true; do

    console_width=$(tput cols)
    console_height=$(tput lines)

    # Sizing Checks
    SizeChecker

    # Clear to end of screen (below the drawn dashboard)
    tput ed

    # Move the cursor to top left of console to redraw
    tput cup 0 0

    # Output everything to the screen
    PrintDashboard ${padd_size}

    # Clear to end of screen (below the drawn dashboard)
    tput ed

    # Reset status indicator (can be overwritten by one of the GetXXXXInformation)
    pico_status=${pico_status_ok}
    mini_status=${mini_status_ok}
    tiny_status=${tiny_status_ok}
    full_status=${full_status_ok}
    mega_status=${mega_status_ok}

    # Sleep for 5 seconds
    sleep 5

    # Start getting our information for next round
    now=$(date +%s)

    # Get uptime, CPU load, temp, etc. every 5 seconds
    if [ $((now - LastCheckSystemInformation)) -ge 5 ]; then
      . /etc/pihole/setupVars.conf
      GetSystemInformation ${padd_size}
      LastCheckSystemInformation="${now}"
    fi

    # Get cache info, last ad domain, blocking percentage, etc. every 5 seconds
    if [ $((now - LastCheckSummaryInformation)) -ge 5 ]; then
      GetSummaryInformation ${padd_size}
      LastCheckSummaryInformation="${now}"
    fi

    # Get FTL status every 5 seconds
    if [ $((now - LastCheckPiholeInformation)) -ge 5 ]; then
      GetPiholeInformation ${padd_size}
      LastCheckPiholeInformation="${now}"
    fi

    # Get IPv4 address, DNS servers, DNSSEC, hostname, DHCP status, interface traffic, etc. every 30 seconds
    if [ $((now - LastCheckNetworkInformation)) -ge 30 ]; then
      GetNetworkInformation ${padd_size}
      LastCheckNetworkInformation="${now}"
    fi

    # Get Pi-hole components and PADD version information once every 24 hours
    if [ $((now - LastCheckVersionInformation)) -ge 86400 ]; then
      GetVersionInformation ${padd_size}
      LastCheckVersionInformation="${now}"
    fi

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

if [ $# = 0 ]; then
  # Turns off the cursor
  # (From Pull request #8 https://github.com/jpmck/PADD/pull/8)
  setterm -cursor off
  trap "{ setterm -cursor on ; echo "" ; exit 0 ; }" INT TERM EXIT

  clear

  console_width=$(tput cols)
  console_height=$(tput lines)

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
