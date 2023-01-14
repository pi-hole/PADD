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
padd_version="v4.0.0"

# LastChecks
LastCheckVersionInformation=$(date +%s)
LastCheckNetworkInformation=$(date +%s)
LastCheckSummaryInformation=$(date +%s)
LastCheckPiholeInformation=$(date +%s)
LastCheckSystemInformation=$(date +%s)
LastCheckPADDInformation=$(date +%s)

# CORES
core_count=$(nproc --all 2> /dev/null)

# COLORS
CSI="$(printf '\033')["  # Control Sequence Introducer
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
pico_status_off="${check_box_info} No blck"
pico_status_ftl_down="${check_box_bad} FTL Down"
pico_status_dns_down="${check_box_bad} DNS Down"

# MINI STATUS
mini_status_ok="${check_box_good} System OK"
mini_status_update="${check_box_info} Update avail."
mini_status_hot="${check_box_bad} System is hot!"
mini_status_off="${check_box_info} No blocking!"
mini_status_ftl_down="${check_box_bad} FTL down!"
mini_status_dns_down="${check_box_bad} DNS off!"

# REGULAR STATUS
full_status_ok="${check_box_good} System is healthy"
full_status_update="${check_box_info} Updates are available"
full_status_hot="${check_box_bad} System is hot!"
full_status_off="${check_box_info} Blocking is disabled"
full_status_ftl_down="${check_box_bad} FTL is down!"
full_status_dns_down="${check_box_bad} DNS is off!"

# MEGA STATUS
mega_status_ok="${check_box_good} Your system is healthy"
mega_status_update="${check_box_info} Updates are available"
mega_status_hot="${check_box_bad} Your system is hot!"
mega_status_off="${check_box_info} Blocking is disabled!"
mega_status_ftl_down="${check_box_bad} FTLDNS service is not running!"
mega_status_dns_down="${check_box_bad} Pi-hole's DNS server is off!"
mega_status_unknown="${check_box_question} Unable to determine Pi-hole status!"

# TINY STATUS
tiny_status_ok="${check_box_good} System is healthy"
tiny_status_update="${check_box_info} Updates are available"
tiny_status_hot="${check_box_bad} System is hot!"
tiny_status_off="${check_box_info} Blocking is disabled"
tiny_status_ftl_down="${check_box_bad} FTL is down!"
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
        printf "%b" "API available at: http://${URL}:${PORT}/${APIPATH}\n"
    else
        echo "API not available at: http://${URL}:${PORT}/${APIPATH}"
        echo "Exiting."
        exit 1
    fi
}

Authenthication() {
    # Try to authenticate
    ChallengeResponse

    while [ "${validSession}" = false ] || [ -z "${validSession}" ] ; do
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

  latest_blocked_raw=$(GetFTLData "/stats/recent_blocked?show=1" | jq --raw-output .blocked[0])

  top_blocked_raw=$(GetFTLData "/stats/top_blocked" | jq --raw-output .top_domains[0].domain)

  top_domain_raw=$(GetFTLData "/stats/top_domains" | jq --raw-output .top_domains[0].domain)

  top_client_raw=$(GetFTLData "/stats/top_clients" | jq --raw-output .clients[0].name))
  if [ -z "${top_client_raw}" ]; then
    # if no hostname was supplied, use IP
    top_client_raw=$(GetFTLData "/stats/top_clients" | jq --raw-output .clients[0].ip))
  fi
}

GetSystemInformation() {
    # System uptime
    system_uptime_raw=$(echo "${summary}" | jq .system.uptime )

    # CPU temperature is returned in °C
    cpu_temp=$(echo "${summary}" | jq .system.sensors[0].value )

  # Convert CPU temperature to correct unit
  if [ "${TEMPERATUREUNIT}" = "F" ]; then
    temperature="$(printf %.1f "$(echo "${cpu_temp}" | awk '{print $1 * 9 / 5000 + 32}')")°F"
  elif [ "${TEMPERATUREUNIT}" = "K" ]; then
    temperature="$(printf %.1f "$(echo "${cpu_temp}" | awk '{print $1 / 1000 + 273.15}')")°K"
  # Addresses Issue 1: https://github.com/jpmck/PAD/issues/1
  else
    temperature="$(printf %.1f "$(echo "${cpu_temp}" | awk '{print $1 / 1000}')")°C"
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
  hot_flag=false
  # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)
  if [ ${cpu_tmp} -gt 80000 ]; then
    temp_heatmap=${blinking_text}${red_text}
    # set flag to change the status message in SetStatusMessage()
    hot_flag=true
  elif [ ${cpu_temp} -gt 70000 ]; then
    temp_heatmap=${magenta_text}
  elif [ ${cpu_temp} -gt 60000 ]; then
    temp_heatmap=${blue_text}
  else
    temp_heatmap=${cyan_text}
  fi

  # Memory use, heatmap and bar
  memory_total=$(echo "${summary}" | jq .system.memory.ram.total)
  memory_available=$(echo "${summary}" | jq .system.memory.ram.available)
  memory_percent=$(printf %.1f $(((memory_total-memory_available)*100/memory_total)) )
  memory_heatmap=$(HeatmapGenerator "${memory_percent}")

  # Get product name and family
  product_name=
  product_family=
  if [ -f /sys/devices/virtual/dmi/id/product_name ]; then
    # Get product name, remove possible null byte
    product_name=$(tr -d '\0' < /sys/devices/virtual/dmi/id/product_name)
  fi
  if [ -f /sys/devices/virtual/dmi/id/product_family ]; then
    # Get product family, remove possible null byte
    product_family=$(tr -d '\0' < /sys/devices/virtual/dmi/id/product_family)
  fi

  board_vendor=
  board_name=
  if [ -f /sys/devices/virtual/dmi/id/board_vendor ]; then
    board_vendor=$(tr -d '\0' < /sys/devices/virtual/dmi/id/board_vendor)
  fi
  if [ -f /sys/devices/virtual/dmi/id/board_name ]; then
    board_name="$(tr -d '\0' < /sys/devices/virtual/dmi/id/board_name)"
  fi


  if [ -n "$product_name" ] || [ -n "$product_family" ]; then
    if echo "$product_family" | grep -q "$product_name"; then
      # If product_name is contained in product_family, only show product_family
      sys_model="${product_family}"
    else
      # If product_name is not contained in product_family, both are shown
      sys_model="${product_family} ${product_name}"
    fi
  elif [ -f /sys/firmware/devicetree/base/model ]; then
    sys_model=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
  elif [ -n "$board_vendor" ] || [ -n "$board_name" ]; then
    sys_model="${board_vendor} ${board_name}"
  elif [ -f /tmp/sysinfo/model ]; then
    sys_model=$(tr -d '\0' < /tmp/sysinfo/model)
  elif [ -n "${DOCKER_VERSION}" ]; then
    # Docker image. DOCKER_VERSION is read from /etc/pihole/versions
    sys_model="Docker tag ${DOCKER_VERSION}"
  fi

  # Cleaning device model from useless OEM information
  sys_model=$(filterModel "${sys_model}")

  if [  -z "$sys_model" ]; then
    sys_model="Unknown"
  fi
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
    ipv6_check_box=${check_box_bad}
  elif [ "${pi_ip6_addrs}" -eq 1 ]; then
    # One IPv6 address available
    pi_ip6_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv6 | sed "s/::1,//g" | awk -F ','  '{printf $1}')"
    ipv6_check_box=${check_box_good}
  else
    # More than one IPv6 address available
    pi_ip6_addr="$(echo "${interfaces_raw}" | jq --raw-output .interfaces[0].ipv6 | sed "s/::1,//g" | awk -F ','  '{printf $1}')+"
    ipv6_check_box=${check_box_good}
  fi

  # Get hostname and gateway
  pi_hostname=$(hostname)

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
      dns_information="1 server"
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

  # Get FTL's current PID
  ftlPID="$(getFTLPID)"

  # If FTL is not running (getFTLPID returns -1), set all variables to "not running"
  ftl_down_flag=false
  if [ "${ftlPID}" = "-1" ]; then
    ftl_status="Not running"
    ftl_heatmap=${red_text}
    ftl_check_box=${check_box_bad}
    # set flag to change the status message in SetStatusMessage()
    ftl_down_flag=true
    ftl_cpu="N/A"
    ftl_mem_percentage="N/A"
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
  dns_down_flag=false
  if [ "${ftl_dns_port}" = 0 ] || [ "${ftl_status}" = "Not running" ]; then
    dns_status="DNS offline"
    dns_heatmap=${red_text}
    dns_check_box=${check_box_bad}
    # set flag to change the status message in SetStatusMessage()
    dns_down_flag=true
  else
    dns_check_box=${check_box_good}
    dns_status="Active"
    dns_heatmap=${green_text}
fi
}

GetVersionInformation() {

    versions_raw=$(GetFTLData "/version")

    # Check if core version
    core_branch="$(echo "${versions_raw}" | jq --raw-output .core.branch)"
    core_version=$(echo "${versions_raw}" | jq --raw-output .core.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')
    core_version_latest=$(pihole -v -p | awk '{print $(NF)}' | tr -d ')')

  out_of_date_flag=false

  # Gather CORE version information...
  # Extract vx.xx or vx.xx.xxx version
  CORE_VERSION="$(echo "${CORE_VERSION}" | grep -oE '^v[0-9]+([.][0-9]+){1,2}')"
  if [ "${CORE_BRANCH}" = "master" ]; then
    core_version_converted="$(VersionConverter "${CORE_VERSION}")"
    core_version_latest_converted=$(VersionConverter "${GITHUB_CORE_VERSION}")

    if [ "${core_version_converted}" -lt "${core_version_latest_converted}" ]; then
      out_of_date_flag="true"
      core_version_heatmap=${red_text}
    else
      core_version_heatmap=${green_text}
    fi

  else
    # Custom branch
    if [ -z "${CORE_BRANCH}"  ]; then
      # Branch name is empty, something went wrong
      core_version_heatmap=${red_text}
      CORE_VERSION="?"
    else
      if [ "${CORE_HASH}" = "${GITHUB_CORE_HASH}" ]; then
        # up-to-date
        core_version_heatmap=${green_text}
      else
        # out-of-date
        out_of_date_flag="true"
        core_version_heatmap=${red_text}
      fi
      # shorten common branch names (fix/, tweak/, new/)
      # use the first 7 characters of the branch name as version
      CORE_VERSION="$(printf '%s' "$CORE_BRANCH" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
    fi
  fi

  # Gather web version information...
  # Extract vx.xx or vx.xx.xxx version
  if [ "$INSTALL_WEB_INTERFACE" = true ]; then
    WEB_BRANCH="$(echo "${versions_raw}" | jq --raw-output .web.branch)"
    WEB_VERSION=$(echo "${versions_raw}" | jq --raw-output .web.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')

    if [ "${WEB_BRANCH}" = "master" ]; then
      web_version_converted="$(VersionConverter "${WEB_VERSION}")"
      web_version_latest_converted=$(VersionConverter "${GITHUB_WEB_VERSION}")

      if [ "${web_version_converted}" -lt "${web_version_latest_converted}" ]; then
        out_of_date_flag="true"
        web_version_heatmap=${red_text}
      else
        web_version_heatmap=${green_text}
      fi

    else
    # Custom branch
      if [ -z "${WEB_BRANCH}"  ]; then
        # Branch name is empty, something went wrong
        web_version_heatmap=${red_text}
        WEB_VERSION="?"
      else
        if [ "${WEB_HASH}" = "${GITHUB_WEB_HASH}" ]; then
          # up-to-date
          web_version_heatmap=${green_text}
        else
          # out-of-date
          out_of_date_flag="true"
          web_version_heatmap=${red_text}
        fi
        # shorten common branch names (fix/, tweak/, new/)
        # use the first 7 characters of the branch name as version
        WEB_VERSION="$(printf '%s' "$WEB_BRANCH" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
      fi
    fi
  else
    # Web interface not installed
    WEB_VERSION="N/A"
    web_version_heatmap=${yellow_text}
  fi

  # Gather FTL version information...
   # Extract vx.xx or vx.xx.xxx version
  FTL_BRANCH="$(echo "${versions_raw}" | jq --raw-output .ftl.branch)"
  FTL_VERSION=$(echo "${versions_raw}" | jq --raw-output .ftl.tag | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')

  if [ "${FTL_BRANCH}" = "master" ]; then
    ftl_version_converted="$(VersionConverter "${FTL_VERSION}")"
    ftl_version_latest_converted=$(VersionConverter "${GITHUB_FTL_VERSION}")

    if [ "${ftl_version_converted}" -lt "${ftl_version_latest_converted}" ]; then
      out_of_date_flag="true"
      ftl_version_heatmap=${red_text}
    else
      ftl_version_heatmap=${green_text}
    fi
  else
    # Custom branch
    if [ -z "${FTL_BRANCH}"  ]; then
      # Branch name is empty, something went wrong
      ftl_version_heatmap=${red_text}
      FTL_VERSION="?"
    else
      if [ "${FTL_HASH}" = "${GITHUB_FTL_HASH}" ]; then
        # up-to-date
        ftl_version_heatmap=${green_text}
      else
        # out-of-date
        out_of_date_flag="true"
        ftl_version_heatmap=${red_text}
      fi
      # shorten common branch names (fix/, tweak/, new/)
      # use the first 7 characters of the branch name as version
      FTL_VERSION="$(printf '%s' "$FTL_BRANCH" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
    fi
  fi

}

GetPADDInformation() {

  # PADD version information...
  padd_version_latest="$(curl --silent https://api.github.com/repos/pi-hole/PADD/releases/latest | grep '"tag_name":' | awk -F \" '{print $4}')"
  # is PADD up-to-date?
  padd_out_of_date_flag=false
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
}

GenerateSizeDependendOutput() {
  if [ "$1" = "pico" ] || [ "$1" = "nano" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 9 "color")

  elif  [ "$1" = "micro" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 10 "color")

  elif [ "$1" = "mini" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 20 "color")

    latest_blocked=$(truncateString "$latest_blocked_raw" 29)
    top_blocked=$(truncateString "$top_blocked_raw" 29)

  elif [ "$1" = "tiny" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 30 "color")

    latest_blocked=$(truncateString "$latest_blocked_raw" 41)
    top_blocked=$(truncateString "$top_blocked_raw" 41)
    top_domain=$(truncateString "$top_domain_raw" 41)
    top_client=$(truncateString "$top_client_raw" 41)

  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 40 "color")

    latest_blocked=$(truncateString "$latest_blocked_raw" 48)
    top_blocked=$(truncateString "$top_blocked_raw" 48)
    top_domain=$(truncateString "$top_domain_raw" 48)
    top_client=$(truncateString "$top_client_raw" 48)


  elif [ "$1" = "mega" ]; then
    ads_blocked_bar=$(BarGenerator "$ads_percentage_today" 30 "color")

    latest_blocked=$(truncateString "$latest_blocked_raw" 68)
    top_blocked=$(truncateString "$top_blocked_raw" 68)
    top_domain=$(truncateString "$top_domain_raw" 68)
    top_client=$(truncateString "$top_client_raw" 68)

  fi

  # System uptime
  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    system_uptime=$(echo "${system_uptime_raw}" | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/){if ($9=="min") {d=$6;m=$8} else {d=$6;h=$8;m=$9}} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours"}')
  else
    system_uptime=$(echo "${system_uptime_raw}" | awk -F'( |,|:)+' '{if ($7=="min") m=$6; else {if ($7~/^day/){if ($9=="min") {d=$6;m=$8} else {d=$6;h=$8;m=$9}} else {h=$6;m=$7}}} {print d+0,"days,",h+0,"hours,",m+0,"minutes"}')
  fi

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
}

SetStatusMessage() {
    # depending on which flags are set, the "message field" shows a different output
    # 7 messages are possible (from highest to lowest priority):

    #   - System is hot
    #   - FTLDNS service is not running
    #   - Pi-hole's DNS server is off (FTL running, but not providing DNS)
    #   - Unable to determine Pi-hole blocking status
    #   - Pi-hole blocking disabled
    #   - Updates are available
    #   - Everything is fine


    if [ "${hot_flag}" = true ]; then
        # Check if CPU temperature is high
        pico_status="${pico_status_hot}"
        mini_status="${mini_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        tiny_status="${tiny_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        full_status="${full_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"
        mega_status="${mega_status_hot} ${blinking_text}${red_text}${temperature}${reset_text}"

    elif [ "${ftl_down_flag}" = true ]; then
        # Check if FTL is down
        pico_status=${pico_status_ftl_down}
        mini_status=${mini_status_ftl_down}
        tiny_status=${tiny_status_ftl_down}
        full_status=${full_status_ftl_down}
        mega_status=${mega_status_ftl_down}

    elif [ "${dns_down_flag}" = true ]; then
        # Check if DNS is down
        pico_status=${pico_status_dns_down}
        mini_status=${mini_status_dns_down}
        tiny_status=${tiny_status_dns_down}
        full_status=${full_status_dns_down}
        mega_status=${mega_status_dns_down}

    elif [ "${blocking_status}" = "unknown" ]; then
        # Check if blocking status is unknown
        pico_status=${pico_status_unknown}
        mini_status=${mini_status_unknown}
        tiny_status=${tiny_status_unknown}
        full_status=${full_status_unknown}
        mega_status=${mega_status_unknown}

    elif [ "${blocking_status}" = "disabled" ]; then
        # Check if blocking status is disabled
        pico_status=${pico_status_off}
        mini_status=${mini_status_off}
        tiny_status=${tiny_status_off}
        full_status=${full_status_off}
        mega_status=${mega_status_off}

    elif [ "${out_of_date_flag}" = "true" ] || [ "${padd_out_of_date_flag}" = "true" ]; then
        # Check if one of the components of Pi-hole (or PADD itself) is out of date
        pico_status=${pico_status_update}
        mini_status=${mini_status_update}
        tiny_status=${tiny_status_update}
        full_status=${full_status_update}
        mega_status=${mega_status_update}

    elif [ "${blocking_status}" = "enabled" ]; then
        # if we reach this point and blocking is enabled, everything is fine
        pico_status=${pico_status_ok}
        mini_status=${mini_status_ok}
        tiny_status=${tiny_status_ok}
        full_status=${full_status_ok}
        mega_status=${mega_status_ok}
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
    printf "%s${clear_line}\n" "${padd_text}${dim_text}tiny${reset_text}   Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
    printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}"
  elif [ "$1" = "slim" ]; then
    printf "%s${clear_line}\n${clear_line}\n" "${padd_text}${dim_text}slim${reset_text}   ${full_status}"
  elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
    printf "%s${clear_line}\n" "${padd_logo_1}"
    printf "%s${clear_line}\n" "${padd_logo_2}Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
    printf "%s${clear_line}\n${clear_line}\n" "${padd_logo_3}PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
  # normal or not defined
  else
    printf "%s${clear_line}\n" "${padd_logo_retro_1}"
    printf "%s${clear_line}\n" "${padd_logo_retro_2}   Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}, PADD ${padd_version_heatmap}${padd_version}${reset_text}"
    printf "%s${clear_line}\n${clear_line}\n" "${padd_logo_retro_3}   ${dns_check_box} DNS   ${ftl_check_box} FTL   ${mega_status}${reset_text}"
  fi
}

PrintDashboard() {
    # Move cursor to (0,0).
    printf '\e[H'

    # adds the y-offset
    moveYOffset

    if [ "$1" = "pico" ]; then
        # pico is a screen at least 20x10 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "p${padd_text} ${pico_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ============${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " [${ads_blocked_bar}] ${ads_percentage_today}%"
        moveXOffset; printf "%s${clear_line}\n" " ${ads_blocked_today} / ${dns_queries_today}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ============${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Hst: ${pi_hostname}"
        moveXOffset; printf "%s${clear_line}\n" " IP:  ${pi_ip4_addr}"
        moveXOffset; printf "%s${clear_line}\n" " DHCP ${dhcp_check_box} IPv6 ${dhcp_ipv6_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}CPU ================${reset_text}"
        moveXOffset; printf "%s${clear_line}" " [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    elif [ "$1" = "nano" ]; then
        # nano is a screen at least 24x12 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "n${padd_text} ${mini_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " DNS: ${dns_check_box}      FTL: ${ftl_check_box}"
        moveXOffset; printf "%s${clear_line}\n" " Blk: [${ads_blocked_bar}] ${ads_percentage_today}%"
        moveXOffset; printf "%s${clear_line}\n" " Blk: ${ads_blocked_today} / ${dns_queries_today}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Host: ${pi_hostname}"
        moveXOffset; printf "%s${clear_line}\n" " IP:   ${pi_ip4_addr}"
        moveXOffset; printf "%s${clear_line}\n" " DHCP: ${dhcp_check_box}    IPv6: ${dhcp_ipv6_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Up:  ${system_uptime}"
        moveXOffset; printf "%s${clear_line}"  " CPU: [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    elif [ "$1" = "micro" ]; then
        # micro is a screen at least 30x16 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "µ${padd_text}     ${mini_status}"
        moveXOffset; printf "%s${clear_line}\n" ""
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ======================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " DNS:  ${dns_check_box}      FTL:  ${ftl_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ========================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Blckng:  ${domains_being_blocked} domains"
        moveXOffset; printf "%s${clear_line}\n" " Piholed: [${ads_blocked_bar}] ${ads_percentage_today}%"
        moveXOffset; printf "%s${clear_line}\n" " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ======================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Host:    ${full_hostname}"
        moveXOffset; printf "%s${clear_line}\n" " IP:      ${pi_ip4_addr}"
        moveXOffset; printf "%s${clear_line}\n" " DHCP:    ${dhcp_check_box}     IPv6:  ${dhcp_ipv6_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =======================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Uptime:  ${system_uptime}"
        moveXOffset; printf "%s${clear_line}\n" " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
        moveXOffset; printf "%s${clear_line}" " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
    elif [ "$1" = "mini" ]; then
        # mini is a screen at least 40x18 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}mini${reset_text}  ${mini_status}"
        moveXOffset; printf "%s${clear_line}\n" ""
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ================================${reset_text}"
        moveXOffset; printf " %-9s${dns_heatmap}%-10s${reset_text} %-5s${ftl_heatmap}%-10s${reset_text}${clear_line}\n" "DNS:" "${dns_status}" "FTL:" "${ftl_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ==================================${reset_text}"
        moveXOffset; printf " %-9s%-29s${clear_line}\n" "Blckng:" "${domains_being_blocked} domains"
        moveXOffset; printf " %-9s[%-20s] %-5s${clear_line}\n" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        moveXOffset; printf " %-9s%-29s${clear_line}\n" "Piholed:" "${ads_blocked_today} out of ${dns_queries_today}"
        moveXOffset; printf " %-9s%-29s${clear_line}\n" "Latest:" "${latest_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            moveXOffset; printf " %-9s%-29s${clear_line}\n" "Top Ad:" "${top_blocked}"
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ================================${reset_text}"
        moveXOffset; printf " %-9s%-16s%-5s%-9s${clear_line}\n" "Host:" "${full_hostname}" "DNS:" "${dns_information}"
        moveXOffset; printf " %-9s%s${clear_line}\n" "IP:" "${pi_ip4_addr} (${iface_name})"
        moveXOffset; printf " %-9s%-4s%-12s%-4s%-5s${clear_line}\n" "Traffic:" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            moveXOffset; printf " %-9s${dhcp_heatmap}%-10s${reset_text} %-9s${dhcp_ipv6_heatmap}%-10s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =================================${reset_text}"
        moveXOffset; printf " %-9s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf "%s${clear_line}\n" " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
        moveXOffset; printf "%s${clear_line}" " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
    elif [ "$1" = "tiny" ]; then
         # tiny is a screen at least 53x20 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}tiny${reset_text}   Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE =============================================${reset_text}"
        moveXOffset; printf " %-10s${dns_heatmap}%-16s${reset_text} %-8s${ftl_heatmap}%-10s${reset_text}${clear_line}\n" "DNS:" "${dns_status}" "FTL:" "${ftl_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ===============================================${reset_text}"
        moveXOffset; printf " %-10s%-29s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains"
        moveXOffset; printf " %-10s[%-30s] %-5s${clear_line}\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
            moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK =============================================${reset_text}"
        moveXOffset; printf " %-10s%-16s %-8s%-16s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:  " "${pi_ip4_addr}"
        moveXOffset; printf " %-10s%-16s %-4s%-7s %-4s%-5s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-10s%-16s %-8s${dnssec_heatmap}%-16s${reset_text}${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_status}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            moveXOffset; printf " %-10s${dhcp_heatmap}%-16s${reset_text} %-8s${dhcp_ipv6_heatmap}%-10s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
            moveXOffset; printf "%s${clear_line}\n" "${dhcp_info}"
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM ==============================================${reset_text}"
        moveXOffset; printf " %-10s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf " %-10s${temp_heatmap}%-17s${reset_text} %-8s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Temp:" "${temperature}" "Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        moveXOffset; printf " %-10s[${memory_heatmap}%-7s${reset_text}] %-6s %-8s[${cpu_load_1_heatmap}%-7s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU:" "${cpu_bar}" "${cpu_percent}%"
    elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
        # slim is a screen with at least 60 columns and exactly 21 lines
        # regular is a screen at least 60x22 (columns x lines)
        if [ "$1" = "slim" ]; then
           moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}slim${reset_text}   Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
           moveXOffset; printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
           moveXOffset; printf "%s${clear_line}\n" ""
        else
            moveXOffset; printf "%s${clear_line}\n" "${padd_logo_1}"
            moveXOffset; printf "%s${clear_line}\n" "${padd_logo_2}Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
            moveXOffset; printf "%s${clear_line}\n" "${padd_logo_3}PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
            moveXOffset; printf "%s${clear_line}\n" ""
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ====================================================${reset_text}"
        moveXOffset; printf " %-10s${dns_heatmap}%-19s${reset_text} %-10s${ftl_heatmap}%-19s${reset_text}${clear_line}\n" "DNS:" "${dns_status}" "FTL:" "${ftl_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ======================================================${reset_text}"
        moveXOffset; printf " %-10s%-49s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains"
        moveXOffset; printf " %-10s[%-40s] %-5s${clear_line}\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        moveXOffset; printf " %-10s%-49s${clear_line}\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today} queries"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        if [ "${DHCP_ACTIVE}" != "true" ]; then
            moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
            moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ====================================================${reset_text}"
        moveXOffset; printf " %-10s%-15s %-4s%-17s%-6s%s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:" "${pi_ip4_addr}" "IPv6:" "${ipv6_check_box}"
        moveXOffset; printf " %-10s%-15s %-4s%-17s%-4s%s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-10s%-15s %-10s${dnssec_heatmap}%-19s${reset_text}${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_status}"
        if [ "${DHCP_ACTIVE}" = "true" ]; then
            moveXOffset; printf " %-10s${dhcp_heatmap}%-15s${reset_text} %-10s${dhcp_ipv6_heatmap}%-19s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_status}" "IPv6:" ${dhcp_ipv6_status}
            moveXOffset; printf "%s${clear_line}\n" "${dhcp_info}"
        fi
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =====================================================${reset_text}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf " %-10s${temp_heatmap}%-21s${reset_text}%-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        moveXOffset; printf " %-10s[${memory_heatmap}%-10s${reset_text}] %-6s %-10s[${cpu_load_1_heatmap}%-10s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
    else # ${padd_size} = mega
         # mega is a screen with at least 80 columns and 26 lines
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_retro_1}"
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_retro_2}   Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}, PADD ${padd_version_heatmap}${padd_version}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_retro_3}   ${dns_check_box} DNS   ${ftl_check_box} FTL   ${mega_status}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" ""
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ==========================================================================${reset_text}"
        moveXOffset; printf " %-10s%-19s %-10s[%-40s] %-5s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains" "Piholed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        moveXOffset; printf " %-10s%-30s%-29s${clear_line}\n" "Clients:" "${clients}" " ${ads_blocked_today} out of ${dns_queries_today} queries"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Dmn:" "${top_domain}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Clnt:" "${top_client}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}FTL ============================================================================${reset_text}"
        moveXOffset; printf " %-10s%-9s %-10s%-9s %-10s%-9s${clear_line}\n" "PID:" "${ftlPID}" "CPU Use:" "${ftl_cpu}" "Mem. Use:" "${ftl_mem_percentage}"
        moveXOffset; printf " %-10s%-69s${clear_line}\n" "DNSCache:" "${cache_inserts} insertions, ${cache_deletes} deletions, ${cache_size} total entries"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ========================================================================${reset_text}"
        moveXOffset; printf " %-10s%-19s${clear_line}\n" "Hostname:" "${full_hostname}"
        moveXOffset; printf " %-10s%-15s %-4s%-9s %-4s%-9s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-6s%-19s %-10s%-29s${clear_line}\n" "IPv4:" "${pi_ip4_addr}" "IPv6:" "${pi_ip6_addr}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}DNS ==========================DHCP==============================================${reset_text}"
        moveXOffset; printf " %-10s%-19s %-6s${dhcp_heatmap}%-19s${reset_text}${clear_line}\n" "Servers:" "${dns_information}" "DHCP:" "${dhcp_status}"
        moveXOffset; printf " %-10s${dnssec_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-9s${reset_text}${clear_line}\n" "DNSSEC:" "${dnssec_status}" "IPv6 Spt:" "${dhcp_ipv6_status}"
        moveXOffset; printf " %-10s${conditional_forwarding_heatmap}%-19s${reset_text}%s${clear_line}\n" "CdFwding:" "${conditional_forwarding_status}" "${dhcp_info}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =========================================================================${reset_text}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Device:" "${sys_model}"
        moveXOffset; printf " %-10s%-39s %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}\n" "Uptime:" "${system_uptime}" "Memory:" "${memory_bar}" "${memory_percent}%"
        moveXOffset; printf " %-10s${temp_heatmap}%-10s${reset_text} %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-7s${reset_text} %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
    fi

    # Clear to end of screen (below the drawn dashboard)
    # https://vt100.net/docs/vt510-rm/ED.html
    printf '\e[0J'
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

# Checks the size of the screen and sets the value of $padd_size
SizeChecker(){
    # adding a tiny delay here to to give the kernel a bit time to
    # report new sizes correctly after a terminal resize
    # this reduces "flickering" of GenerateSizeDependendOutput() items
    # after a terminal re-size
    sleep 0.1
    console_width=$(tput cols)
    console_height=$(tput lines)

    # Mega
    if [ "$console_width" -ge "80" ] && [ "$console_height" -ge "26" ]; then
        padd_size="mega"
        width=80
        height=26
    # Below Mega. Gives you Regular.
    elif [ "$console_width" -ge "60" ] && [ "$console_height" -ge "22" ]; then
        padd_size="regular"
        width=60
        height=22
    # Below Regular. Gives you Slim.
    elif [ "$console_width" -ge "60" ] && [ "$console_height" -ge "21" ]; then
        padd_size="slim"
        width=60
        height=21
    # Below Slim. Gives you Tiny.
    elif [ "$console_width" -ge "53" ] && [ "$console_height" -ge "20" ]; then
        padd_size="tiny"
        width=53
        height=20
    # Below Tiny. Gives you Mini.
    elif [ "$console_width" -ge "40" ] && [ "$console_height" -ge "18" ]; then
        padd_size="mini"
        width=40
        height=18
    # Below Mini. Gives you Micro.
    elif [ "$console_width" -ge "30" ] && [ "$console_height" -ge "16" ]; then
        padd_size="micro"
        width=30
        height=16
    # Below Micro, Gives you Nano.
    elif [ "$console_width" -ge "24" ] && [ "$console_height" -ge "12" ]; then
        padd_size="nano"
        width=24
        height=12
    # Below Nano. Gives you Pico.
    elif [ "$console_width" -ge "20" ] && [ "$console_height" -ge "10" ]; then
        padd_size="pico"
        width=20
        height=10
    # Below Pico. Gives you nothing...
    else
        # Nothing is this small, sorry
        printf "%b" "${check_box_bad} Error!\n    PADD isn't\n    for ants!\n"
        exit 1
    fi

    # Center the output (default position)
    xOffset="$(( (console_width - width) / 2 ))"
    yOffset="$(( (console_height - height) / 2 ))"

    # If the user sets an offset option, use it.
    if [ -n "$xOffOrig" ]; then
        xOffset=$xOffOrig

        # Limit the offset to avoid breaks
        xMaxOffset=$((console_width - width))
        if [ "$xOffset" -gt "$xMaxOffset" ]; then
            xOffset="$xMaxOffset"
        fi
    fi
    if [ -n "$yOffOrig" ]; then
        yOffset=$yOffOrig

        # Limit the offset to avoid breaks
        yMaxOffset=$((console_height - height))
        if [ "$yOffset" -gt "$yMaxOffset" ]; then
            yOffset="$yMaxOffset"
        fi
    fi
}
# converts a given version string e.g. v3.7.1 to 3007001000 to allow for easier comparison of multi digit version numbers
# credits https://apple.stackexchange.com/a/123408
VersionConverter() {
  echo "$@" | tr -d '[:alpha:]' | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }';
}

moveYOffset(){
    # moves the cursor yOffset-times down
    # https://vt100.net/docs/vt510-rm/CUD.html
    # this needs to be guarded, because if the amount is 0, it is adjusted to 1
    # https://terminalguide.namepad.de/seq/csi_cb/

    if [ "${yOffset}" -gt 0 ]; then
        printf '\e[%sB' "${yOffset}"
    fi
}

moveXOffset(){
    # moves the cursor xOffset-times to the right
    # https://vt100.net/docs/vt510-rm/CUF.html
    # this needs to be guarded, because if the amount is 0, it is adjusted to 1
    # https://terminalguide.namepad.de/seq/csi_cb/

    if [ "${xOffset}" -gt 0 ]; then
        printf '\e[%sC' "${xOffset}"
    fi

# Remove undesired strings from sys_model variable - used in GetSystemInformation() function
filterModel() {
    FILTERLIST="To be filled by O.E.M.|Not Applicable|System Product Name|System Version|Undefined|Default string|Not Specified|Type1ProductConfigId|INVALID|All Series|�"

    # Description:
    #    `-v`      : set $FILTERLIST into a variable called `list`
    #    `gsub()`  : replace all list items (ignoring case) with an empty string, deleting them
    #    `{$1=$1}1`: remove all extra spaces. The last "1" evaluates as true, printing the result
    echo "$1" | awk -v list="$FILTERLIST" '{IGNORECASE=1; gsub(list,"")}; {$1=$1}1'
}

# Truncates a given string and appends three '...'
# takes two parameters
# $1: string to truncate
# $2: max length of the string
truncateString() {
    local truncatedString length shorted

    length=${#1}
    shorted=$(($2-3)) # shorten max allowed length by 3 to make room for the dots
    if [ "${length}" -gt "$2" ]; then
        # if length of the string is larger then the specified max length
        # cut every char from the string exceeding length $shorted and add three dots
        truncatedString=$(echo "$1" | cut -c1-$shorted)"..."
        echo "${truncatedString}"
    else
        echo "$1"
    fi
}



########################################## MAIN FUNCTIONS ##########################################

OutputJSON() {
    # Traps for graceful shutdown
    # https://unix.stackexchange.com/a/681201
    trap clean_exit EXIT
    trap sig_cleanup INT QUIT TERM

    # Save current terminal settings (needed for later restore after password prompt)
    stty_orig=$(stty -g)
    # Construct FTL's API address depending on the arguments supplied
    ConstructAPI
    # Test if the authentication endpoint is availabe
    TestAPIAvailability
    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication

    GetSummaryInformation
    echo "{\"domains_being_blocked\":${domains_being_blocked_raw},\"dns_queries_today\":${dns_queries_today_raw},\"ads_blocked_today\":${ads_blocked_today_raw},\"ads_percentage_today\":${ads_percentage_today},\"clients\": ${clients}}"
    exit 0
}

StartupRoutine(){
  # Get config variables
  . /etc/pihole/setupVars.conf

  # Clear the screen and move cursor to (0,0).
  # This mimics the 'clear' command.
  # https://vt100.net/docs/vt510-rm/ED.html
  # https://vt100.net/docs/vt510-rm/CUP.html
  # E3 extension `\e[3J` to clear the scrollback buffer see 'man clear'
  printf '\e[H\e[2J\e[3J'

  # adds the y-offset
  moveYOffset

  # Get versions information
  . /etc/pihole/versions

  if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
    moveXOffset; PrintLogo "$1"
    moveXOffset; printf "%b" "START-UP ===========\n"

    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication

    printf "%b" "Starting PADD...\n"

    moveXOffset; printf "%b" " [■·········]  10%\r"

    # Check for updates
    moveXOffset; printf "%b" " [■■········]  20%\r"
    moveXOffset; printf "%b" " [■■■·······]  30%\r"

    # Get our information for the first time
    moveXOffset; printf "%b" " [■■■■······]  40%\r"
    GetSystemInformation
    moveXOffset; printf "%b" " [■■■■■·····]  50%\r"
    GetSummaryInformation
    moveXOffset; printf "%b" " [■■■■■■····]  60%\r"
    GetPiholeInformation
    moveXOffset; printf "%b" " [■■■■■■■···]  70%\r"
    GetNetworkInformation
    moveXOffset; printf "%b" " [■■■■■■■■··]  80%\r"
    GetVersionInformation
    moveXOffset; printf "%b" " [■■■■■■■■■·]  90%\r"
    GetPADDInformation
    moveXOffset; printf "%b" " [■■■■■■■■■■] 100%\n"

  elif [ "$1" = "mini" ]; then
    moveXOffset; PrintLogo "$1"
    moveXOffset; echo "START UP ====================="
    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication

    # Get our information for the first time
    moveXOffset; echo "- Gathering system info."
    GetSystemInformation
    moveXOffset; echo "- Gathering Pi-hole info."
    GetPiholeInformation
    GetSummaryInformation
    moveXOffset; echo "- Gathering network info."
    GetNetworkInformation
    moveXOffset; echo "- Gathering version info."
    GetVersionInformation
    GetPADDInformation
    moveXOffset; echo "  - Core $CORE_VERSION, Web $WEB_VERSION"
    moveXOffset; echo "  - FTL $FTL_VERSION, PADD $padd_version"


  else
    moveXOffset; printf "%b" "${padd_logo_retro_1}\n"
    moveXOffset; printf "%b" "${padd_logo_retro_2}Pi-hole® Ad Detection Display\n"
    moveXOffset; printf "%b" "${padd_logo_retro_3}A client for Pi-hole\n\n"
    if [ "$1" = "tiny" ]; then
      moveXOffset; echo "START UP ============================================"
    else
      moveXOffset; echo "START UP ==================================================="
    fi


    # Authenticate with the FTL server
    printf "%b" "Establishing connection with FTL...\n"
    Authenthication


    # Get our information for the first time
    moveXOffset; echo "- Gathering system information..."
    GetSystemInformation
    moveXOffset; echo "- Gathering Pi-hole information..."
    GetSummaryInformation
    GetPiholeInformation
    moveXOffset; echo "- Gathering network information..."
    GetNetworkInformation
    moveXOffset; echo "- Gathering version information..."
    GetVersionInformation
    GetPADDInformation
    moveXOffset; echo "  - Pi-hole Core $CORE_VERSION"
    moveXOffset; echo "  - Web Admin $WEB_VERSION"
    moveXOffset; echo "  - FTL $FTL_VERSION"
    moveXOffset; echo "  - PADD $padd_version"
  fi

  moveXOffset; printf "%s" "- Starting in "
  for i in 3 2 1
  do
    printf "%s..." "$i"
    sleep 1
  done
}

NormalPADD() {

    # Trap the window resize signal (handle window resize events)
    trap 'TerminalResize' WINCH

    while true; do

    # Generate output that depends on the terminal size
    # e.g. Heatmap and barchart
    GenerateSizeDependendOutput ${padd_size}

    # Sets the message displayed in the "status field" depending on the set flags
    SetStatusMessage

    # Output everything to the screen
    PrintDashboard ${padd_size}

    # Sleep for 5 seconds
    # sending sleep in the background and wait for it
    # this way the TerminalResize trap can kill the sleep
    # and force a instant re-draw of the dashboard
    # https://stackoverflow.com/questions/32041674/linux-how-to-kill-sleep
    #
    # saving the PID of the background sleep process to kill it on exit and resize
    sleep 5 &
    sleepPID=$!
    wait $!

    # Start getting our information for next round
    now=$(date +%s)

    # Get uptime, CPU load, temp, etc. every 5 seconds
    if [ $((now - LastCheckSystemInformation)) -ge 5 ]; then
      . /etc/pihole/setupVars.conf
      GetSystemInformation
      LastCheckSystemInformation="${now}"
    fi

    # Get cache info, last ad domain, blocking percentage, etc. every 5 seconds
    if [ $((now - LastCheckSummaryInformation)) -ge 5 ]; then
      GetSummaryInformation
      LastCheckSummaryInformation="${now}"
    fi

    # Get uptime, CPU load, temp, etc. every 5 seconds
    if [ $((now - LastCheckSystemInformation)) -ge 5 ]; then
      GetSystemInformation ${padd_size}
      LastCheckSystemInformation="${now}"
    fi

    # Get FTL status every 5 seconds
    if [ $((now - LastCheckPiholeInformation)) -ge 5 ]; then
      GetPiholeInformation
      LastCheckPiholeInformation="${now}"
    fi

    # Get IPv4 address, DNS servers, DNSSEC, hostname, DHCP status, interface traffic, etc. every 30 seconds
    if [ $((now - LastCheckNetworkInformation)) -ge 30 ]; then
      GetNetworkInformation
      LastCheckNetworkInformation="${now}"
    fi

    # Get Pi-hole components version information every 30 seconds
    if [ $((now - LastCheckVersionInformation)) -ge 30 ]; then
      . /etc/pihole/versions
      GetVersionInformation
      LastCheckVersionInformation="${now}"
    fi

    # Get PADD version information every 24hours
    if [ $((now - LastCheckPADDInformation)) -ge 86400 ]; then
      GetPADDInformation
      LastCheckPADDInformation="${now}"
    fi

  done

  DeleteSession
}

DisplayHelp() {
    cat << EOM

::: PADD displays stats about your Pi-hole!
:::
:::
::: Options:
:::  -xoff [num]    set the x-offset, reference is the upper left corner, disables auto-centering
:::  -yoff [num]    set the y-offset, reference is the upper left corner, disables auto-centering
:::
:::   -u <URL|IP>             URL or address of your Pi-hole (default: pi.hole)
:::   -p <port>               Port of your Pi-hole's API (default: 8080)
:::   -a <api>                Path where your  Pi-hole's API is hosted (default: api)
:::   -s <secret password>    Your Pi-hole's password, required to access the API
:::   -j                      output stats as JSON formatted string and exit and exit
:::   -h                      display this help text

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

    # Show the cursor
    # https://vt100.net/docs/vt510-rm/DECTCEM.html
    printf '\e[?25h'

    # if background sleep is running, kill it
    # http://mywiki.wooledge.org/SignalTrap#When_is_the_signal_handled.3F
    kill $sleepPID > /dev/null 2>&1

    exit $err # exit the script with saved $?
}

TerminalResize(){
    # if a terminal resize is trapped, check the new terminal size and
    # kill the sleep function within NormalPADD() to trigger redrawing
    # of the Dashboard
    SizeChecker

    # Clear the screen and move cursor to (0,0).
    # This mimics the 'clear' command.
    # https://vt100.net/docs/vt510-rm/ED.html
    # https://vt100.net/docs/vt510-rm/CUP.html
    # E3 extension `\e[3J` to clear the scrollback buffer (see 'man clear')

    printf '\e[H\e[2J\e[3J'

    kill $sleepPID > /dev/null 2>&1
}

main(){
    # Hiding the cursor.
    # https://vt100.net/docs/vt510-rm/DECTCEM.html
    printf '\e[?25l'

    # Trap on exit
    trap 'CleanExit' INT TERM EXIT

    # If setupVars.conf is not present, then PADD is not running on a Pi-hole
    # and we are not able to start as StartupRoutine() will fail below
    if [ ! -f /etc/pihole/setupVars.conf ]; then
      printf "%b" "${check_box_bad} Error!\n    PADD only works in conjunction with Pi-hole!\n"
      exit 1
    fi

    SizeChecker

    StartupRoutine ${padd_size}

    # Run PADD
    NormalPADD
}

# Process all options (if present)
while [ "$#" -gt 0 ]; do
  case "$1" in
    "-j" | "--json"     ) OutputJSON; exit 0;;
    "-h" | "--help"     ) DisplayHelp; exit 0;;
    "-xoff"             ) xOffset="$2"; xOffOrig="$2"; shift;;
    "-yoff"             ) yOffset="$2"; yOffOrig="$2"; shift;;
    *                   ) DisplayHelp; exit 1;;
  esac
  shift
done

main
