#!/usr/bin/env sh
# shellcheck disable=SC1091

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
padd_version="v4.0.0"

# LastChecks
LastCheckVersionInformation=$(date +%s)
LastCheckNetworkInformation=$(date +%s)
LastCheckSummaryInformation=$(date +%s)
LastCheckPiholeInformation=$(date +%s)
LastCheckSystemInformation=$(date +%s)

# COLORS
CSI="$(printf '\033')["
red_text="${CSI}91m"     # Red
green_text="${CSI}92m"   # Green
yellow_text="${CSI}93m"  # Yellow
blue_text="${CSI}94m"    # Blue
magenta_text="${CSI}95m" # Magenta
cyan_text="${CSI}96m"    # Cyan
reset_text="${CSI}0m"    # Reset to default

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

# MINI STATUS
mini_status_ok="${check_box_good} System OK"
mini_status_update="${check_box_info} Update avail."
mini_status_hot="${check_box_bad} System is hot!"
mini_status_off="${check_box_bad} Pi-hole off!"
mini_status_ftl_down="${check_box_info} FTL down!"
mini_status_dns_down="${check_box_bad} DNS off!"

# REGULAR STATUS
full_status_ok="${check_box_good} System is healthy."
full_status_update="${check_box_info} Updates are available."
full_status_hot="${check_box_bad} System is hot!"
full_status_off="${check_box_bad} Pi-hole is offline"
full_status_ftl_down="${check_box_info} FTL is down!"
full_status_dns_down="${check_box_bad} DNS is off!"

# MEGA STATUS
mega_status_ok="${check_box_good} Your system is healthy."
mega_status_update="${check_box_info} Updates are available."
mega_status_hot="${check_box_bad} Your system is hot!"
mega_status_off="${check_box_bad} Pi-hole is offline."
mega_status_ftl_down="${check_box_info} FTLDNS service is not running."
mega_status_dns_down="${check_box_bad} Pi-hole's DNS server is off!"

# TINY STATUS
tiny_status_ok="${check_box_good} System is healthy."
tiny_status_update="${check_box_info} Updates are available."
tiny_status_hot="${check_box_bad} System is hot!"
tiny_status_off="${check_box_bad} Pi-hole is offline"
tiny_status_ftl_down="${check_box_info} FTL is down!"
tiny_status_dns_down="${check_box_bad} DNS is off!"

# Text only "logos"
padd_text="${green_text}${bold_text}PADD${reset_text}"

# PADD logos - regular and retro
padd_logo_1="${bold_text}${green_text} __      __  __   ${reset_text}"
padd_logo_2="${bold_text}${green_text}|__) /\\ |  \\|  \\  ${reset_text}"
padd_logo_3="${bold_text}${green_text}|   /--\\|__/|__/  ${reset_text}"
padd_logo_retro_1="${bold_text} ${yellow_text}_${green_text}_      ${blue_text}_${magenta_text}_  ${yellow_text}_${green_text}_   ${reset_text}"
padd_logo_retro_2="${bold_text}${yellow_text}|${green_text}_${blue_text}_${cyan_text}) ${red_text}/${yellow_text}\\ ${blue_text}|  ${red_text}\\${yellow_text}|  ${cyan_text}\\  ${reset_text}"
padd_logo_retro_3="${bold_text}${green_text}|   ${red_text}/${yellow_text}-${green_text}-${blue_text}\\${cyan_text}|${magenta_text}_${red_text}_${yellow_text}/${green_text}|${blue_text}_${cyan_text}_${magenta_text}/  ${reset_text}"

############################################# FTL ##################################################

ConstructAPI() {
	# If no arguments were supplied set them to default
	if [ -z "${URL}" ]; then
		URL=pi.hole
	fi
	if [ -z "${PORT}" ]; then
		PORT=8080
	fi
	if [ -z "${APIPATH}" ]; then
		APIPATH=api
	fi
}

TestAPIAvailability() {

    availabilityResonse=$(curl -s -o /dev/null -w "%{http_code}" http://${URL}:${PORT}/${APIPATH}/auth)

    # test if http status code was 200 (OK)
    if [ "${availabilityResonse}" = 200 ]; then
        printf "%b" "API available at: http://${URL}:${PORT}/${APIPATH}\n\n"
    else
        echo "API not available at: http://${URL}:${PORT}/${APIPATH}"
        echo "Exiting."
        exit 1
    fi
}

Authenthication() {
    # Try to authenticate
    ChallengeResponse

    while [ "${validSession}" = false ]; do
        echo "Authentication failed."

        # no password was supplied as argument
        if [ -z "${password}" ]; then
            echo "No password supplied. Please enter your password:"
        else
            echo "Wrong password supplied, please enter the correct password:"
        fi

        # POSIX's `read` does not support `-s` option (suppressing the input)
        # this workaround changes the terminal characteristics to not echo input and later rests this option
        # credits https://stackoverflow.com/a/4316765

        stty -echo
        read -r password
        stty "${stty_orig}"
        echo ""

        # Try to authenticate again
        ChallengeResponse
    done

    # Loop exited, authentication was successful
    echo "Authentication successful."

}

DeleteSession() {
    # if a valid Session exists (no password required or successful authenthication) and
    # SID is not null (successful authenthication only), delete the session
    if [ "${validSession}" = true ] && [ ! "${SID}" = null ]; then
        # Try to delte the session. Omitt the output, but get the http status code
        deleteResponse=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE http://${URL}:${PORT}/${APIPATH}/auth  -H "Accept: application/json" -H "sid: ${SID}")

        case "${deleteResponse}" in
            "200") printf "%b" "\nA session that was not created cannot be deleted (e.g., empty API password).\n";;
            "401") printf "%b" "\nLogout attempt without a valid session. Unauthorized!\n";;
            "410") printf "%b" "\n\nSession successfully deleted.\n";;
         esac;
    fi

}

ChallengeResponse() {
	# Challenge-response authentication

	# Compute password hash from user password
	# Compute password hash twice to avoid rainbow table vulnerability
    hash1=$(printf "%b" "$password" | sha256sum | sed 's/\s.*$//')
    pwhash=$(printf "%b" "$hash1" | sha256sum | sed 's/\s.*$//')


	# Get challenge from FTL
	# Calculate response based on challenge and password hash
	# Send response & get session response
	challenge="$(curl --silent -X GET http://${URL}:${PORT}/${APIPATH}/auth | jq --raw-output .challenge)"
	response="$(printf "%b" "${challenge}:${pwhash}" | sha256sum | sed 's/\s.*$//')"
	sessionResponse="$(curl --silent -X POST http://${URL}:${PORT}/${APIPATH}/auth --data "{\"response\":\"${response}\"}" )"

  if [ -z "${sessionResponse}" ]; then
    echo "No response from FTL server. Please check connectivity and use the options to set the API URL"
    echo "Usage: $0 [-u <URL>] [-p <port>] [-a <path>] "
    exit 1
  fi
	# obtain validity and session ID from session response
	validSession=$(echo "${sessionResponse}"| jq .session.valid)
	SID=$(echo "${sessionResponse}"| jq --raw-output .session.sid)
}

GetFTLData() {
	data=$(curl -sS -X GET "http://${URL}:${PORT}/${APIPATH}$1" -H "Accept: application/json" -H "sid: ${SID}" )
	echo "${data}"
}


############################################# GETTERS ##############################################

GetSummaryInformation() {
  summary=$(GetFTLData "/stats/summary")
  cache_info=$(GetFTLData "/dns/cache")

  clients=$(echo "${summary}" | jq .ftl.clients.active )

  blocking_status=$(echo "${summary}" | jq .system.dns.blocking )

  domains_being_blocked_raw=$(echo "${summary}" | jq .ftl.database.gravity )
  domains_being_blocked=$(printf "%.f" "${domains_being_blocked_raw}")

  dns_queries_today_raw=$(echo "$summary" | jq .queries.total )
  dns_queries_today=$(printf "%.f" "${dns_queries_today_raw}")

  ads_blocked_today_raw=$(echo "$summary" | jq .queries.blocked )
  ads_blocked_today=$(printf "%.f" "${ads_blocked_today_raw}")

  ads_percentage_today_raw=$(echo "$summary" | jq .queries.percent_blocked)
  ads_percentage_today=$(printf "%.1f" "${ads_percentage_today_raw}")

  cache_size=$(echo "$cache_info" | jq .size)
  cache_evictions=$(echo "$cache_info" | jq .evicted)
  cache_inserts=$(echo "$cache_info"| jq .inserted)

  latest_blocked=$(GetFTLData "/stats/recent_blocked?show=1" | jq --raw-output .blocked[0])

  top_blocked=$(GetFTLData "/stats/top_blocked" | jq --raw-output .top_domains[0].domain)

  top_domain=$(GetFTLData "/stats/top_domains" | jq --raw-output .top_domains[0].domain)

  top_client=$(GetFTLData "/stats/top_clients" | jq --raw-output .top_clients[0].name)

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
    system_uptime_raw=$(echo "${summary}" | jq .system.uptime )
    if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
        system_uptime="$(printf '%d days, %d hours' $((system_uptime_raw/86400)) $((system_uptime_raw%86400/3600)))"
    else
        system_uptime="$(printf '%d days, %d hours, %d minutes' $((system_uptime_raw/86400)) $((system_uptime_raw%86400/3600)) $((system_uptime_raw%3600/60)))"
    fi

    # CPU temperature is returned in °C
    cpu_temp=$(echo "${summary}" | jq .system.sensors[0].value )

    # Convert CPU temperature to correct unit
    if [ "${TEMPERATUREUNIT}" = "F" ]; then
        temperature="$(printf %.1f "$(echo "${cpu_temp}" | awk '{print $1 * 9 / 5 + 32}')")°F"
    elif [ "${TEMPERATUREUNIT}" = "K" ]; then
        temperature="$(printf %.1f "$(echo "${cpu_temp}" | awk '{print $1 + 273.15}')")°K"
    else
        temperature="$(printf %.1f "${cpu_temp}" )°C"
    fi

    # CPU, load, heatmap
    core_count=$(echo "${summary}" | jq .system.cpu.nprocs)
    cpu_load_1=$(printf %.2f "$(echo "${summary}" | jq .system.cpu.load.raw[0])")
    cpu_load_5=$(printf %.2f "$(echo "${summary}" | jq .system.cpu.load.raw[1])")
    cpu_load_15=$(printf %.2f "$(echo "${summary}" | jq .system.cpu.load.raw[2])")
    cpu_load_1_heatmap=$(HeatmapGenerator "${cpu_load_1}" "${core_count}")
    cpu_load_5_heatmap=$(HeatmapGenerator "${cpu_load_5}" "${core_count}")
    cpu_load_15_heatmap=$(HeatmapGenerator "${cpu_load_15}" "${core_count}")
    cpu_percent=$(printf %.1f "$(echo "${summary}" | jq .system.cpu.load.percent[0])")

    # CPU temperature heatmap
    # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)

    # Remove decimal accuracy
    cpu_temp=$(echo "${cpu_temp}" | cut -d '.' -f1)
    if [ "${cpu_temp}" -gt 80 ]; then
        temp_heatmap=${blinking_text}${red_text}
        pico_status="${pico_status_hot}"
        mini_status="${mini_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        tiny_status="${tiny_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        full_status="${full_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        mega_status="${mega_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
    elif [ "${cpu_temp}" -gt 70 ]; then
        temp_heatmap=${magenta_text}
    elif [ "${cpu_temp}" -gt 60 ]; then
        temp_heatmap=${blue_text}
    else
        temp_heatmap=${cyan_text}
    fi

  # Memory use, heatmap and bar
  memory_total=$(echo "${summary}" | jq .system.memory.ram.total)
  memory_available=$(echo "${summary}" | jq .system.memory.ram.available)
  memory_percent=$(printf %.1f $(((memory_total-memory_available)*100/memory_total)) )
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
    sys_model=$(echo "${summary}" | jq --raw-output .system.model)
}

GetNetworkInformation() {
    interfaces_raw=$(GetFTLData "/ftl/interfaces")
    # Get pi IPv4 address  of the default interface
    pi_ip4_addrs="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv4 | sed "s/127.0.0.1,//g" | tr "," " "  | wc -w)"
    if [ "${pi_ip4_addrs}" -eq 0 ]; then
        # No IPv4 address available
        pi_ip4_addr="N/A"
    elif [ "${pi_ip4_addrs}" -eq 1 ]; then
        # One IPv4 address available
        pi_ip4_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv4 | sed "s/127.0.0.1,//g" | awk -F ','  '{printf $1}')"
    else
        # More than one IPv4 address available
        pi_ip4_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv4 | sed "s/127.0.0.1,//g"| awk -F ','  '{printf $1}')+"
    fi

  # Get pi IPv6 address of the default interface
  pi_ip6_addrs="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv6 | sed "s/::1,//g" | tr "," " "  | wc -w)"
  if [ "${pi_ip6_addrs}" -eq 0 ]; then
    # No IPv6 address available
    pi_ip6_addr="N/A"
  elif [ "${pi_ip6_addrs}" -eq 1 ]; then
    # One IPv6 address available
    pi_ip6_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv6 | sed "s/::1,//g" | awk -F ','  '{printf $1}')"
  else
    # More than one IPv6 address available
    pi_ip6_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv6 | sed "s/::1,//g" | awk -F ','  '{printf $1}')+"
  fi

  # Get hostname and gateway
  pi_hostname=$(hostname)
  pi_gateway=$(echo "${interfaces_raw}" | jq --raw-output .gateway.address)

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
    if [ -z ${DHCP_ROUTER+x} ]; then
      DHCP_ROUTER=$(printf %b "${interfaces_raw}" | jq --raw-output .gateway.address)
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
    iface_name="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].name)"
    tx_bytes="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].tx.num)"
    tx_bytes_unit="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].tx.unit)"
    tx_bytes=$(printf "%.1f %b" "${tx_bytes}" "${tx_bytes_unit}")

    rx_bytes="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].rx.num)"
    rx_bytes_unit="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].rx.unit)"
    rx_bytes=$(printf "%.1f %b" "${rx_bytes}" "${rx_bytes_unit}")
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
  ftl_dns_port=$(GetFTLData "/dns/port" | jq .dns_port)

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
    if [ "${blocking_status}" = "true" ]; then
      pihole_status="Active"
      pihole_heatmap=${green_text}
      pihole_check_box=${check_box_good}
    fi
    if [ "${blocking_status}" = "false" ]; then
      pihole_status="Blocking disabled"
      pihole_heatmap=${red_text}
      pihole_check_box=${check_box_bad}
      pico_status=${pico_status_off}
      mini_status=${mini_status_off}
      tiny_status=${tiny_status_off}
      full_status=${full_status_off}
      mega_status=${mega_status_off}
    fi
  fi

}

GetVersionInformation() {

    versions_raw=$(GetFTLData "/version")

    # Check if core version
    core_branch="$(echo "${versions_raw}" | jq --raw-output .core.branch)"
    core_version=$(echo "${versions_raw}" | jq --raw-output .core.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')
    core_version_latest=$(pihole -v -p | awk '{print $(NF)}' | tr -d ')')

    # if core_version is something else then x.xx or x.xx.xxx or branch not master set it to N/A
    if ! echo "${core_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ ! "${core_branch}" = "master" ]; then
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
        web_branch="$(echo "${versions_raw}" | jq --raw-output .web.branch)"
        web_version=$(echo "${versions_raw}" | jq --raw-output .web.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')
        web_version_latest=$(pihole -v -a | awk '{print $(NF)}' | tr -d ')')

        # if web_version is something else then x.xx or x.xx.xxx or branch not master set it to N/A
        if ! echo "${web_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ ! "${web_branch}" = "master" ]; then
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
    ftl_branch="$(echo "${versions_raw}" | jq --raw-output .ftl.branch)"
    ftl_version=$(echo "${versions_raw}" | jq --raw-output .ftl.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')
    ftl_version_latest=$(pihole -v -f | awk '{print $(NF)}' | tr -d ')')

    # if ftl_version is something else then x.xx or x.xx.xxx or branch not master set it to N/A
    if ! echo "${ftl_version}" | grep -qE '^[0-9]+([.][0-9]+){1,2}$' || [ ! "${ftl_branch}" = "master" ]; then
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

# terminfo clr_eol (clears to end of line to erase artifacts after resizing smaller)
ceol=$(tput el)

# wrapper - echo with a clear eol afterwards to wipe any artifacts remaining from last print
CleanEcho() {
  echo "${ceol}$1"
}

# wrapper - printf
CleanPrintf() {
# tput el
# disabling shellcheck here because we pass formatting instructions within `"${@}"`
# shellcheck disable=SC2059
  printf "$@"
}

PrintLogo() {
  # Screen size checks
  if [ "$1" = "pico" ]; then
    CleanEcho "p${padd_text} ${pico_status}"
  elif [ "$1" = "nano" ]; then
    CleanEcho "n${padd_text} ${mini_status}"
  elif [ "$1" = "micro" ]; then
    CleanEcho "µ${padd_text}     ${mini_status}"
    CleanEcho ""
  elif [ "$1" = "mini" ]; then
    CleanEcho "${padd_text}${dim_text}mini${reset_text}  ${mini_status}"
    CleanEcho ""
  elif [ "$1" = "tiny" ]; then
    CleanEcho "${padd_text}${dim_text}tiny${reset_text}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}"
    CleanPrintf "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}\e[0K\\n"
  elif [ "$1" = "slim" ]; then
    CleanEcho "${padd_text}${dim_text}slim${reset_text}   ${full_status}"
    CleanEcho ""
  # For the next two, use printf to make sure spaces aren't collapsed
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    CleanPrintf "${padd_logo_1}\e[0K\\n"
    CleanPrintf "${padd_logo_2}Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}\e[0K\\n"
    CleanPrintf "${padd_logo_3}PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}\e[0K\\n"
    CleanEcho ""
  # normal or not defined
  else
    CleanPrintf "${padd_logo_retro_1}\e[0K\\n"
    CleanPrintf "${padd_logo_retro_2}   Pi-hole® ${core_version_heatmap}${core_version}${reset_text}, Web ${web_version_heatmap}${web_version}${reset_text}, FTL ${ftl_version_heatmap}${ftl_version}${reset_text}, PADD ${padd_version_heatmap}${padd_version}${reset_text}\e[0K\\n"
    CleanPrintf "${padd_logo_retro_3}   ${pihole_check_box} Core  ${ftl_check_box} FTL   ${mega_status}${reset_text}\e[0K\\n"

    CleanEcho ""
  fi
}

PrintNetworkInformation() {
  if [ "$1" = "pico" ]; then
    CleanEcho "${bold_text}NETWORK ============${reset_text}"
    CleanEcho " Hst: ${pi_hostname}"
    CleanEcho " IP:  ${pi_ip4_addr}"
    CleanEcho " DHCP ${dhcp_check_box} IPv6 ${dhcp_ipv6_check_box}"
  elif [ "$1" = "nano" ]; then
    CleanEcho "${bold_text}NETWORK ================${reset_text}"
    CleanEcho " Host: ${pi_hostname}"
    CleanEcho " IP:  ${pi_ip4_addr}"
    CleanEcho " DHCP: ${dhcp_check_box}    IPv6: ${dhcp_ipv6_check_box}"
  elif [ "$1" = "micro" ]; then
    CleanEcho "${bold_text}NETWORK ======================${reset_text}"
    CleanEcho " Host:    ${full_hostname}"
    CleanEcho " IP:      ${pi_ip4_addr}"
    CleanEcho " DHCP:    ${dhcp_check_box}     IPv6:  ${dhcp_ipv6_check_box}"
  elif [ "$1" = "mini" ]; then
    CleanEcho "${bold_text}NETWORK ================================${reset_text}"
    CleanPrintf " %-9s%-19s\e[0K\\n" "Host:" "${full_hostname}"
    CleanPrintf " %-9s%-19s\e[0K\\n" "IP:"   "${pi_ip4_addr}"
    CleanPrintf " %-9s%-8s %-4s%-5s %-4s%-5s\e[0K\\n" "Iface:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
    CleanPrintf " %-9s%-10s\e[0K\\n" "DNS:" "${dns_information}"

    if [ "${DHCP_ACTIVE}" = "true" ]; then
      CleanPrintf " %-9s${dhcp_heatmap}%-10s${reset_text} %-9s${dhcp_ipv6_heatmap}%-10s${reset_text}\e[0K\\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
    fi
  elif [ "$1" = "tiny" ]; then
    CleanEcho "${bold_text}NETWORK ============================================${reset_text}"
    CleanPrintf " %-10s%-16s %-8s%-16s\e[0K\\n" "Hostname:" "${full_hostname}" "IP:  " "${pi_ip4_addr}"
    CleanPrintf " %-10s%-16s %-8s%-16s\e[0K\\n" "IPv6:" "${pi_ip6_addr}"
    CleanPrintf " %-10s%-16s %-4s%-5s %-4s%-5s\e[0K\\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
    CleanPrintf " %-10s%-16s %-8s%-16s\e[0K\\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"

    if [ "${DHCP_ACTIVE}" = "true" ]; then
      CleanPrintf " %-10s${dhcp_heatmap}%-16s${reset_text} %-8s${dhcp_ipv6_heatmap}%-10s${reset_text}\e[0K\\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
      CleanPrintf "%s\e[0K\\n" "${dhcp_info}"
    fi
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    CleanEcho "${bold_text}NETWORK ===================================================${reset_text}"
    CleanPrintf " %-10s%-19s %-10s%-19s\e[0K\\n" "Hostname:" "${full_hostname}" "IP:" "${pi_ip4_addr}"
    CleanPrintf " %-10s%-19s %-10s%-19s\e[0K\\n" "IPv6:" "${pi_ip6_addr}"
    CleanPrintf " %-10s%-19s %-4s%-5s %-4s%-5s\e[0K\\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
    CleanPrintf " %-10s%-19s %-10s%-19s\e[0K\\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_heatmap}${dnssec_status}${reset_text}"

    if [ "${DHCP_ACTIVE}" = "true" ]; then
      CleanPrintf " %-10s${dhcp_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-19s${reset_text}\e[0K\\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
      CleanPrintf "%s\e[0K\\n" "${dhcp_info}"
    fi
  else
    CleanEcho "${bold_text}NETWORK =======================================================================${reset_text}"
    CleanPrintf " %-10s%-19s\e[0K\\n" "Hostname:" "${full_hostname}"
    CleanPrintf " %-11s%-14s %-4s%-9s %-4s%-9s\e[0K\\n" "Interface:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
    CleanPrintf " %-6s%-19s %-10s%-29s\e[0K\\n" "IPv4:" "${pi_ip4_addr}" "IPv6:" "${pi_ip6_addr}"
    CleanEcho "DNS ==========================================================================="
    CleanPrintf " %-10s%-39s\e[0K\\n" "Servers:" "${dns_information}"
    CleanPrintf " %-10s${dnssec_heatmap}%-19s${reset_text} %-20s${conditional_forwarding_heatmap}%-9s${reset_text}\e[0K\\n" "DNSSEC:" "${dnssec_status}" "Conditional Fwding:" "${conditional_forwarding_status}"

    CleanEcho "DHCP =========================================================================="
    CleanPrintf " %-10s${dhcp_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-9s${reset_text}\e[0K\\n" "DHCP:" "${dhcp_status}" "IPv6 Spt:" "${dhcp_ipv6_status}"
    CleanPrintf "%s\e[0K\\n" "${dhcp_info}"
  fi
}

PrintPiholeInformation() {
  # size checks
  if [ "$1" = "pico" ]; then
    :
  elif [ "$1" = "nano" ]; then
    CleanEcho "${bold_text}PI-HOLE ================${reset_text}"
    CleanEcho " Up:  ${pihole_check_box}      FTL: ${ftl_check_box}"
  elif [ "$1" = "micro" ]; then
    CleanEcho "${bold_text}PI-HOLE ======================${reset_text}"
    CleanEcho " Status:  ${pihole_check_box}      FTL:  ${ftl_check_box}"
  elif [ "$1" = "mini" ]; then
    CleanEcho "${bold_text}PI-HOLE ================================${reset_text}"
    CleanPrintf " %-9s${pihole_heatmap}%-10s${reset_text} %-9s${ftl_heatmap}%-10s${reset_text}\e[0K\\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
  elif [ "$1" = "tiny" ]; then
    CleanEcho "${bold_text}PI-HOLE ============================================${reset_text}"
    CleanPrintf " %-10s${pihole_heatmap}%-16s${reset_text} %-8s${ftl_heatmap}%-10s${reset_text}\e[0K\\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    CleanEcho "${bold_text}PI-HOLE ===================================================${reset_text}"
    CleanPrintf " %-10s${pihole_heatmap}%-19s${reset_text} %-10s${ftl_heatmap}%-19s${reset_text}\e[0K\\n" "Status:" "${pihole_status}" "FTL:" "${ftl_status}"
  else
    return
  fi
}

PrintPiholeStats() {
  # are we on a reduced screen size?
  if [ "$1" = "pico" ]; then
    CleanEcho "${bold_text}PI-HOLE ============${reset_text}"
    CleanEcho " [${ads_blocked_bar}] ${ads_percentage_today}%"
    CleanEcho " ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "nano" ]; then
    CleanEcho " Blk: [${ads_blocked_bar}] ${ads_percentage_today}%"
    CleanEcho " Blk: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "micro" ]; then
    CleanEcho "${bold_text}STATS ========================${reset_text}"
    CleanEcho " Blckng:  ${domains_being_blocked} domains"
    CleanEcho " Piholed: [${ads_blocked_bar}] ${ads_percentage_today}%"
    CleanEcho " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
  elif [ "$1" = "mini" ]; then
    CleanEcho "${bold_text}STATS ==================================${reset_text}"
    CleanPrintf " %-9s%-29s\e[0K\\n" "Blckng:" "${domains_being_blocked} domains"
    CleanPrintf " %-9s[%-20s] %-5s\e[0K\\n" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    CleanPrintf " %-9s%-29s\e[0K\\n" "Piholed:" "${ads_blocked_today} out of ${dns_queries_today}"
    CleanPrintf " %-9s%-29s\e[0K\\n" "Latest:" "${latest_blocked}"
    if [ "${DHCP_ACTIVE}" != "true" ]; then
      CleanPrintf " %-9s%-29s\\n" "Top Ad:" "${top_blocked}"
    fi
  elif [ "$1" = "tiny" ]; then
    CleanEcho "${bold_text}STATS ==============================================${reset_text}"
    CleanPrintf " %-10s%-29s\e[0K\\n" "Blocking:" "${domains_being_blocked} domains"
    CleanPrintf " %-10s[%-30s] %-5s\e[0K\\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Latest:" "${latest_blocked}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Top Ad:" "${top_blocked}"
    if [ "${DHCP_ACTIVE}" != "true" ]; then
      CleanPrintf " %-10s%-39s\e[0K\\n" "Top Dmn:" "${top_domain}"
      CleanPrintf " %-10s%-39s\e[0K\\n" "Top Clnt:" "${top_client}"
    fi
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    CleanEcho "${bold_text}STATS =====================================================${reset_text}"
    CleanPrintf " %-10s%-49s\e[0K\\n" "Blocking:" "${domains_being_blocked} domains"
    CleanPrintf " %-10s[%-40s] %-5s\e[0K\\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    CleanPrintf " %-10s%-49s\e[0K\\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Latest:" "${latest_blocked}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Top Ad:" "${top_blocked}"
    if [ "${DHCP_ACTIVE}" != "true" ]; then
      CleanPrintf " %-10s%-39s\e[0K\\n" "Top Dmn:" "${top_domain}"
      CleanPrintf " %-10s%-39s\e[0K\\n" "Top Clnt:" "${top_client}"
    fi
  else
    CleanEcho "${bold_text}STATS =========================================================================${reset_text}"
    CleanPrintf " %-10s%-19s %-10s[%-40s] %-5s\e[0K\\n" "Blocking:" "${domains_being_blocked} domains" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
    CleanPrintf " %-10s%-30s%-29s\e[0K\\n" "Clients:" "${clients}" " ${ads_blocked_today} out of ${dns_queries_today} queries"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Latest:" "${latest_blocked}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Top Ad:" "${top_blocked}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Top Dmn:" "${top_domain}"
    CleanPrintf " %-10s%-39s\e[0K\\n" "Top Clnt:" "${top_client}"
    CleanEcho "FTL ==========================================================================="
    CleanPrintf " %-10s%-9s %-10s%-9s %-10s%-9s\e[0K\\n" "PID:" "${ftlPID}" "CPU Use:" "${ftl_cpu}%" "Mem. Use:" "${ftl_mem_percentage}%"
    CleanPrintf " %-10s%-69s\e[0K\\n" "DNSCache:" "${cache_inserts} insertions, ${cache_evictions} evictions, ${cache_size} total entries"
  fi
}

PrintSystemInformation() {
  if [ "$1" = "pico" ]; then
    CleanEcho "${bold_text}CPU ================${reset_text}"
    printf "%b" "${ceol} [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
  elif [ "$1" = "nano" ]; then
    CleanEcho "${ceol}${bold_text}SYSTEM =================${reset_text}"
    CleanEcho " Up:  ${system_uptime}"
    printf "%b"  "${ceol} CPU: [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
  elif [ "$1" = "micro" ]; then
    CleanEcho "${bold_text}SYSTEM =======================${reset_text}"
    CleanEcho " Uptime:  ${system_uptime}"
    CleanEcho " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    printf "%b" "${ceol} Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
  elif [ "$1" = "mini" ]; then
    CleanEcho "${bold_text}SYSTEM =================================${reset_text}"
    CleanPrintf " %-9s%-29s\\n" "Uptime:" "${system_uptime}"
    CleanEcho " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    printf "%b" "${ceol} Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
  elif [ "$1" = "tiny" ]; then
    CleanEcho "${bold_text}SYSTEM =============================================${reset_text}"
    CleanPrintf " %-10s%-29s\e[0K\\n" "Uptime:" "${system_uptime}"
    CleanPrintf " %-10s${temp_heatmap}%-17s${reset_text} %-8s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}\e[0K\\n" "CPU Temp:" "${temperature}" "Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
    # Memory and CPU bar
    CleanPrintf " %-10s[${memory_heatmap}%-7s${reset_text}] %-6s %-8s[${cpu_load_1_heatmap}%-7s${reset_text}] %-5s" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU:" "${cpu_bar}" "${cpu_percent}%"
  # else we're not
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    CleanEcho "${bold_text}SYSTEM ====================================================${reset_text}"
    # Device
    CleanPrintf " %-10s%-39s\e[0K\\n" "Device:" "${sys_model}"
    # Uptime
    CleanPrintf " %-10s%-39s\e[0K\\n" "Uptime:" "${system_uptime}"

    # Temp and Loads
    CleanPrintf " %-10s${temp_heatmap}%-20s${reset_text}" "CPU Temp:" "${temperature}"
    CleanPrintf " %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}\e[0K\\n" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"

    # Memory and CPU bar
    CleanPrintf " %-10s[${memory_heatmap}%-10s${reset_text}] %-6s %-10s[${cpu_load_1_heatmap}%-10s${reset_text}] %-5s" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
  else
    CleanEcho "${bold_text}SYSTEM ========================================================================${reset_text}"
    # Device
    CleanPrintf " %-10s%-39s\e[0K\\n" "Device:" "${sys_model}"

    # Uptime and memory
    CleanPrintf " %-10s%-39s %-10s[${memory_heatmap}%-10s${reset_text}] %-6s\\n" "Uptime:" "${system_uptime}" "Memory:" "${memory_bar}" "${memory_percent}%"

    # CPU temp, load, percentage
    CleanPrintf " %-10s${temp_heatmap}%-10s${reset_text} %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-7s${reset_text} %-10s[${memory_heatmap}%-10s${reset_text}] %-6s" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
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
    printf "%b" "${check_box_bad} Error!\\n    PADD isn't\\n    for ants!\n"
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

# converts a given version string e.g. v3.7.1 to 3007001000 to allow for easier comparison of multi digit version numbers
# credits https://apple.stackexchange.com/a/123408
VersionConverter() {
  echo "$@" | tr -d '[:alpha:]' | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}

########################################## MAIN FUNCTIONS ##########################################

OutputJSON() {
  GetSummaryInformation
  echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today_raw},\"clients\": ${clients}}"
  exit 0
}

StartupRoutine(){

  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    PrintLogo "$1"
    printf "%b" "START-UP ===========\n"

    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication

    printf "%b" "Starting PADD...\n"

    printf "%b" " [■·········]  10%\\r"

    # Check for updates
    printf "%b" " [■■········]  20%\\r"
    printf "%b" " [■■■·······]  30%\\r"

    # Get our information for the first time
    printf "%b" " [■■■■······]  40%\\r"
    GetSummaryInformation "$1"
    printf "%b" " [■■■■■·····]  50%\\r"
    GetSystemInformation "$1"
    printf "%b" " [■■■■■■····]  60%\\r"
    GetPiholeInformation "$1"
    printf "%b" " [■■■■■■■···]  70%\\r"
    GetNetworkInformation "$1"
    printf "%b" " [■■■■■■■■··]  80%\\r"
    GetVersionInformation "$1"
    printf "%b" " [■■■■■■■■■·]  90%\\r"
    printf "%b" " [■■■■■■■■■■] 100%\\n"

  elif [ "$1" = "mini" ]; then
    PrintLogo "$1"
    echo "START UP ====================="

    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication


    echo "Starting PADD."

    # Get our information for the first time
    echo "- Gathering Summary info."
    GetSummaryInformation "mini"
    echo "- Gathering system info."
    GetSystemInformation "mini"
    echo "- Gathering Pi-hole info."
    GetPiholeInformation "mini"
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


    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication


    # Get our information for the first time
    echo "- Gathering Summary information..."
    GetSummaryInformation "$1"
    echo "- Gathering system information..."
    GetSystemInformation "$1"
    echo "- Gathering Pi-hole information..."
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

    # Move the cursor to top left of console to redraw
    tput cup 0 0

    # Output everything to the screen
    PrintLogo ${padd_size}
    PrintPiholeInformation ${padd_size}
    PrintPiholeStats ${padd_size}
    PrintNetworkInformation ${padd_size}
    PrintSystemInformation ${padd_size}

    # Clear to end of screen (below the drawn dashboard)
    tput ed

    pico_status=${pico_status_ok}
    mini_status=${mini_status_ok}
    tiny_status=${tiny_status_ok}
    full_status=${full_status_ok}
    mega_status=${mega_status_ok}

    # Sleep for 5 seconds
    sleep 5

    # Start getting our information for next round
    now=$(date +%s)

    # Get cache info, last ad domain, blocking percentage, etc. every 5 seconds
    if [ $((now - LastCheckSummaryInformation)) -ge 5 ]; then
      GetSummaryInformation ${padd_size}
      LastCheckSummaryInformation="${now}"
    fi

    # Get uptime, CPU load, temp, etc. every 5 seconds
    if [ $((now - LastCheckSystemInformation)) -ge 5 ]; then
      GetSystemInformation ${padd_size}
      LastCheckSystemInformation="${now}"
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

  DeleteSession
}

DisplayHelp() {
  cat << EOM
::: PADD displays stats about your piHole!
:::
:::
::: Options:
:::
:::   -u <URL|IP>             URL or address of your Pi-hole (default: pi.hole)
:::   -p <port>               Port of your Pi-hole's API (default: 8080)
:::   -a <api>                Path where your Pi-hole's API is hosted (default: api)
:::   -s <secret password>    Your Pi-hole's password, required to access the API
:::  -j                       output stats as JSON formatted string and exit
:::  -h                       display this help text
EOM
    exit 0
}

# Called on signals INT QUIT TERM
sig_cleanup() {
    # save error code (130 for SIGINT, 143 for SIGTERM, 131 for SIGQUIT)
    err=$?

    # some shells will call EXIT after the INT signal
    # causing EXIT trap to be executed, so we trap EXIT after INT
    trap '' EXIT

    (exit $err) # execute in a subshell just to pass $? to clean_exit()
    clean_exit
}

# Called on signal EXIT, or indirectly on INT QUIT TERM
clean_exit() {
    # save the return code of the script
    err=$?

    # reset trap for all signals to not interrupt clean_tempfiles() on any next signal
    trap '' EXIT INT QUIT TERM

    # restore terminal settings if they have been changed (e.g. user cancled script while at password  input prompt)
    if [ "$(stty -g)" != "${stty_orig}" ]; then
        stty "${stty_orig}"
    fi

    # Turn cursor on
    setterm -cursor on

    #  Delete session from FTL server
    DeleteSession
    exit $err # exit the script with saved $?
}

# Get supplied options

while getopts ":u:p:a:s:jh" args; do
	case "${args}" in
	u)	URL="${OPTARG}" ;;
    p)	PORT="${OPTARG}" ;;
	a)	APIPATH="${OPTARG}" ;;
	s)	password="${OPTARG}" ;;
    j)  OutputJSON;;
	h)  DisplayHelp;;
	\?)	echo "Invalid option: -${OPTARG}"
		  exit 1 ;;
	:)	echo "Option -$OPTARG requires an argument."
     	exit 1 ;;
	*)	DisplayHelp;;
	esac
done

# Save current terminal settings (needed for later restore after password prompt)
stty_orig=$(stty -g)

# Turns off the cursor
# (From Pull request #8 https://github.com/jpmck/PADD/pull/8)
setterm -cursor off

# Construct FTL's API address depending on the arguments supplied
ConstructAPI

# Test if the authentication endpoint is availabe
TestAPIAvailability

# Traps for graceful shutdown
# https://unix.stackexchange.com/a/681201
trap clean_exit EXIT
trap sig_cleanup INT QUIT TERM

clear

console_width=$(tput cols)
console_height=$(tput lines)

SizeChecker

StartupRoutine ${padd_size}

# Run PADD
clear
NormalPADD
