#!/usr/bin/env sh

# PADD
# A more advanced version of the chronometer provided with Pihole

# SETS LOCALE
export LC_ALL=C
export LC_NUMERIC=C

############################################ VARIABLES #############################################

# VERSION
padd_version="v4.1.0"

# LastChecks
LastCheckPADDInformation=$(date +%s)
LastCheckFullInformation=$(date +%s)
LastCheckNetworkInformation=$(date +%s)

# padd_data holds the data returned by FTL's /padd endpoint globally
padd_data=""

# should PADD run only once?
runOnce=false

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
check_box_disabled="[${blue_text}-${reset_text}]"    # Disabled, but not an error
check_box_question="[${yellow_text}?${reset_text}]"  # Question / ?
check_box_info="[${yellow_text}i${reset_text}]"      # Info / i

# PICO STATUSES
pico_status_ok="${check_box_good} Sys. OK"
pico_status_update="${check_box_info} Update"
pico_status_hot="${check_box_bad} Sys. Hot!"
pico_status_off="${check_box_info} No blck"
pico_status_ftl_down="${check_box_bad} No CXN"
pico_status_dns_down="${check_box_bad} DNS Down"

# MINI STATUS
mini_status_ok="${check_box_good} System OK"
mini_status_update="${check_box_info} Update avail."
mini_status_hot="${check_box_bad} System is hot!"
mini_status_off="${check_box_info} No blocking!"
mini_status_ftl_down="${check_box_bad} No connection!"
mini_status_dns_down="${check_box_bad} DNS off!"

# REGULAR STATUS
full_status_ok="${check_box_good} System is healthy"
full_status_update="${check_box_info} Updates are available"
full_status_hot="${check_box_bad} System is hot!"
full_status_off="${check_box_info} Blocking is disabled"
full_status_ftl_down="${check_box_bad} No connection!"
full_status_dns_down="${check_box_bad} DNS is off!"

# MEGA STATUS
mega_status_ok="${check_box_good} Your system is healthy"
mega_status_update="${check_box_info} Updates are available"
mega_status_hot="${check_box_bad} Your system is hot!"
mega_status_off="${check_box_info} Blocking is disabled!"
mega_status_ftl_down="${check_box_bad} No connection to FTL!"
mega_status_dns_down="${check_box_bad} Pi-hole's DNS server is off!"

# TINY STATUS
tiny_status_ok="${check_box_good} System is healthy"
tiny_status_update="${check_box_info} Updates are available"
tiny_status_hot="${check_box_bad} System is hot!"
tiny_status_off="${check_box_info} Blocking is disabled"
tiny_status_ftl_down="${check_box_bad} No connection to FTL!"
tiny_status_dns_down="${check_box_bad} DNS is off!"

# Text only "logos"
padd_text="${green_text}${bold_text}PADD${reset_text}"

# PADD logos - regular and retro
padd_logo_1="${bold_text} ${yellow_text}_${green_text}_      ${blue_text}_${magenta_text}_  ${yellow_text}_${green_text}_   ${reset_text}"
padd_logo_2="${bold_text}${yellow_text}|${green_text}_${blue_text}_${cyan_text}) ${red_text}/${yellow_text}\\ ${blue_text}|  ${red_text}\\${yellow_text}|  ${cyan_text}\\  ${reset_text}"
padd_logo_3="${bold_text}${green_text}|   ${red_text}/${yellow_text}-${green_text}-${blue_text}\\${cyan_text}|${magenta_text}_${red_text}_${yellow_text}/${green_text}|${blue_text}_${cyan_text}_${magenta_text}/  ${reset_text}"

############################################# FTL ##################################################

TestAPIAvailability() {

    local chaos_api_list authResponse cmdResult digReturnCode authStatus authData apiAvailable

    # Check if an API location was specified with --api
    if [ -n "${API_LOCATION}" ]; then
        # The list of available API URLs is just the provided URL
        chaos_api_list="${API_LOCATION}"
    else
        # Query the API URLs from FTL using CHAOS TXT
        # The result is a space-separated enumeration of full URLs
        # e.g., "http://localhost:80/api" or "https://domain.com:443/api"
        if [ -z "${SERVER}" ] || [ "${SERVER}" = "localhost" ] || [ "${SERVER}" = "127.0.0.1" ]; then
            # --server was not set or set to local, assuming we're running locally
            cmdResult="$(dig +short chaos txt local.api.ftl @localhost 2>&1; echo $?)"
        else
            # --server was set, try to get response from there
            cmdResult="$(dig +short chaos txt domain.api.ftl @"${SERVER}" 2>&1; echo $?)"
        fi

        # Gets the return code of the dig command (last line)
        # We can't use${cmdResult##*$'\n'*} here as $'..' is not POSIX
        digReturnCode="$(echo "${cmdResult}" | tail -n 1)"

        if [ "${digReturnCode}" != "0" ]; then
            # If the query was not successful
            moveXOffset; echo "API not available. Please check server address and connectivity"
            exit 1
        else
            # Dig returned 0 (success), so get the actual response (first line)
            chaos_api_list="$(echo "${cmdResult}" | head -n 1)"
        fi
    fi

    # Iterate over space-separated list of URLs
    while [ -n "${chaos_api_list}" ]; do
        # Get the first URL
        API_URL="${chaos_api_list%% *}"
        # Strip leading and trailing quotes
        API_URL="${API_URL%\"}"
        API_URL="${API_URL#\"}"

        # If $SERVER is user-specified by IP, the returned API_URL might contain a domain which can't be resolved by the host
        # Therefore, we substitute the domain with the IP
        if [ -n "${SERVER}" ]; then
            # Check if SERVER is an IPv6
            case "${SERVER}" in
                *:*)
                    # Replace the domain with the IP
                    # Add square brackets for IPv6 (as recommended by RFC2732)
                    API_URL=$(echo "${API_URL}" | sed -E "s#(https?://)[^/:]+(:[0-9]+)#\1[${SERVER}]\2#");;
                *)
                    # Replace the domain with the IP
                    API_URL=$(echo "${API_URL}" | sed -E "s#(https?://)[^/:]+(:[0-9]+)#\1${SERVER}\2#");;
            esac
        fi

        # Test if the API is available at this URL, include delimiter for ease in splitting payload
        authResponse=$(curl --connect-timeout 2 -skS -w ">>%{http_code}" "${API_URL}auth")

        # authStatus is the response http_code, eg. 200, 401.
        # Shell parameter expansion, remove everything up to and including the >> delim
        authStatus=${authResponse#*>>}
        # data is everything from response
        # Shell parameter expansion, remove the >> delim and everything after
        authData=${authResponse%>>*}

        # Test if http status code was 200 (OK) or 401 (authentication required)
        if [ "${authStatus}" = 200 ]; then
            # API is available without authentication
            apiAvailable=true
            needAuth=false
            break

        elif [ "${authStatus}" = 401 ]; then
            # API is available with authentication
            apiAvailable=true
            needAuth=true
            # Check if 2FA is required
            needTOTP=$(echo "${authData}"| jq --raw-output .session.totp 2>/dev/null)
            break
        else
            # API is not available at this port/protocol combination
            apiAvailable=false

            # Remove the first URL from the list
            local last_api_list
            last_api_list="${chaos_api_list}"
            chaos_api_list="${chaos_api_list#* }"

            # If the list did not change, we are at the last element
            if [ "${last_api_list}" = "${chaos_api_list}" ]; then
                # Remove the last element
                chaos_api_list=""
            fi
        fi
    done

    # if apiAvailable is false, no working API was found
    if [ "${apiAvailable}" = false ]; then
        moveXOffset; echo "API not available. Please check FTL.log"
        moveXOffset; echo "Exiting."
        exit 1
    fi
}

LoginAPI() {
    # Exit early if no authentication is required
    if [ "${needAuth}" = false ]; then
        moveXOffset; echo "No authentication required."
        return
    fi

    # Check if we are running locally before checking for the CLI password
    if [ -z "${SERVER}" ] || [ "${SERVER}" = "localhost" ] || [ "${SERVER}" = "127.0.0.1" ]; then
        # Try to read the CLI password (if enabled and readable by the current user)
        if [ -r /etc/pihole/cli_pw ]; then
            password=$(cat /etc/pihole/cli_pw)
            # If we can read the CLI password, we can skip 2FA even when it's required otherwise
            needTOTP=false
        fi
    fi

    if [ -z "${password}" ]; then
        # no password was supplied as argument or read from CLI file
        moveXOffset; echo "No password supplied. Please enter your password:"
        # secretly read the password
        moveXOffset; secretRead; printf '\n'
    fi

    if [ "${needTOTP}" = true ] && [ -z "${totp}" ]; then
        # 2FA required, but no TOTP was supplied as argument
        moveXOffset; echo "Please enter the correct second factor."
        moveXOffset; echo "(Can be any number if you used the app password)"
        moveXOffset; read -r totp
    fi

    # Try to authenticate using the supplied password (CLI file, argument or user input) and TOTP
    Authenticate

    # Try to login again until the session is valid
    while [ "${validSession}" = false ]  ; do
        moveXOffset; echo "Authentication failed."

        # Print the error message if there is one
        if  [ "${sessionError}" != "null"  ]; then
            moveXOffset; echo "Error: ${sessionError}"
        fi
        # Print the session message if there is one
        if  [ "${sessionMessage}" != "null"  ]; then
            moveXOffset; echo "Error: ${sessionMessage}"
        fi

        moveXOffset; echo "Please enter the correct password:"

        # secretly read the password
        moveXOffset; secretRead; printf '\n'

        if [ "${needTOTP}" = true ]; then
            moveXOffset; echo "Please enter the correct second factor:"
            moveXOffset; echo "(Can be any number if you used the app password)"
            moveXOffset; read -r totp
        fi

        # Try to authenticate again
        Authenticate
    done

    # Loop exited, authentication was successful
    moveXOffset; echo "Authentication successful."

}

DeleteSession() {
    # if a valid Session exists (no password required or successful authenthication) and
    # SID is not null (successful authenthication only), delete the session
    if [ "${validSession}" = true ] && [ "${SID}" != null ]; then
        # Try to delete the session. Omit the output, but get the http status code
        deleteResponse=$(curl --connect-timeout 2 -skS -o /dev/null -w "%{http_code}" -X DELETE "${API_URL}auth"  -H "Accept: application/json" -H "sid: ${SID}")

        printf "\n\n"
        case "${deleteResponse}" in
            "204") moveXOffset; printf "%b" "Session successfully deleted.\n";;
            "401") moveXOffset; printf "%b" "Logout attempt without a valid session. Unauthorized!\n";;
         esac;
    else
        # no session to delete, just print a newline for nicer output
        echo
    fi

}

Authenticate() {
    sessionResponse="$(curl --connect-timeout 2 -skS -X POST "${API_URL}auth" --user-agent "PADD ${padd_version}" --data "{\"password\":\"${password}\", \"totp\":${totp:-null}}" )"

    if [ -z "${sessionResponse}" ]; then
        moveXOffset; echo "No response from FTL server. Please check connectivity and use the options to set the API URL"
        moveXOffset; echo "Usage: $0 [--server <domain|IP>] or [--api <API URL>]"
        exit 1
    fi
    # obtain validity, session ID and sessionMessage from session response
    validSession=$(echo "${sessionResponse}"| jq .session.valid 2>/dev/null)
    SID=$(echo "${sessionResponse}"| jq --raw-output .session.sid 2>/dev/null)
    sessionMessage=$(echo "${sessionResponse}"| jq --raw-output .session.message 2>/dev/null)

    # obtain the error message from the session response
    sessionError=$(echo "${sessionResponse}"| jq --raw-output .error.message 2>/dev/null)
}

GetFTLData() {
    local response
    local data
    local status

    # get the data from querying the API as well as the http status code, include delimiter for ease in splitting payload
    response=$(curl --connect-timeout 2 -sk -w ">>%{http_code}" -X GET "${API_URL}$1$2" -H "Accept: application/json" -H "sid: ${SID}" )

    # status is the response http_code, eg. 200, 401.
    # Shell parameter expansion, remove everything up to and including the >> delim
    status=${response#*>>}
    # data is everything from response
    # Shell parameter expansion, remove the >> delim and everything after
    data=${response%>>*}

    if [ "${status}" = 200 ]; then
        echo "${data}"
    elif [ "${status}" = 000 ]; then
        # connection lost
        echo "000"
    elif [ "${status}" = 401 ]; then
        # unauthorized
        echo "401"
    fi
}


############################################# GETTERS ##############################################

GetPADDData() {
    local response
    response=$(GetFTLData "padd" "$1")

    if [ "${response}" = 000 ]; then
        # connection lost
        padd_data="000"
    elif [ "${response}" = 401 ]; then
        # unauthorized
        padd_data="401"
    else
        # Iterate over all the leaf paths in the JSON object and creates key-value
        # pairs in the format "key=value". Nested objects are flattened using the dot
        # notation, e.g., { "a": { "b": 1 } } becomes "a.b=1".
        # We cannot use leaf_paths here as it was deprecated in jq 1.6 and removed in
        # current master
        # Using "paths(scalars | true)" will return null and false values.
        # We also check if the value is exactly `null` and, in this case, return the
        # string "null", as jq would return an empty string for nulls.
        padd_data=$(echo "${response}" | jq -r 'paths(scalars | true) as $p | [$p | join(".")] + [if getpath($p)!=null then getpath($p) else "null" end] | join("=")' 2>/dev/null)
    fi
}

GetPADDValue() {
    echo "${padd_data}" | sed -n "s/^$1=//p" 2>/dev/null
}

GetSummaryInformation() {
    if [ "${connection_down_flag}" = true ]; then
        clients="N/A"
        blocking_enabled="N/A"
        domains_being_blocked="N/A"
        dns_queries_today="N/A"
        ads_blocked_today="N/A"
        ads_percentage_today="N/A"
        cache_size="N/A"
        cache_evictions="N/A"
        cache_inserts="N/A"
        latest_blocked_raw="N/A"
        top_blocked_raw="N/A"
        top_domain_raw="N/A"
        top_client_raw="N/A"
        return
    fi


    clients=$(GetPADDValue active_clients)

    blocking_enabled=$(GetPADDValue blocking)

    domains_being_blocked_raw=$(GetPADDValue gravity_size)
    domains_being_blocked=$(printf "%.f" "${domains_being_blocked_raw}")

    dns_queries_today_raw=$(GetPADDValue queries.total)
    dns_queries_today=$(printf "%.f" "${dns_queries_today_raw}")

    ads_blocked_today_raw=$(GetPADDValue queries.blocked)
    ads_blocked_today=$(printf "%.f" "${ads_blocked_today_raw}")

    ads_percentage_today_raw=$(GetPADDValue queries.percent_blocked)
    ads_percentage_today=$(printf "%.1f" "${ads_percentage_today_raw}")

    cache_size=$(GetPADDValue cache.size)
    cache_evictions=$(GetPADDValue cache.evicted)
    cache_inserts=$(echo "${padd_data}"| GetPADDValue cache.inserted)

    latest_blocked_raw=$(GetPADDValue recent_blocked)

    top_blocked_raw=$(GetPADDValue top_blocked)

    top_domain_raw=$(GetPADDValue top_domain)

    top_client_raw=$(GetPADDValue top_client)

    privacy_level=$(GetPADDValue config.privacy_level)

    # Substitute 'null' values returned by FTL for privacy level >1
    if [ "${privacy_level}" -ge "1" ]; then
        top_domain_raw="hidden by privacy level"
        top_blocked_raw="hidden by privacy level"
        latest_blocked_raw="hidden by privacy level"
    fi
    if [ "${privacy_level}" -ge "2" ]; then
        top_client_raw="hidden by privacy level"
    fi

}

GetSystemInformation() {

    if [ "${connection_down_flag}" = true ]; then
        system_uptime_raw=0
        temperature="N/A"
        temp_heatmap=${reset_text}

        cpu_load_1="N/A"
        cpu_load_5="N/A"
        cpu_load_15="N/A"
        cpu_load_1_heatmap=${reset_text}
        cpu_load_5_heatmap=${reset_text}
        cpu_load_15_heatmap=${reset_text}
        cpu_percent=0

        memory_percent=0
        memory_heatmap=${reset_text}

        sys_model="N/A"
        return
    fi

    # System uptime
    system_uptime_raw=$(GetPADDValue system.uptime)

    # CPU temperature and unit
    cpu_temp_raw=$(GetPADDValue sensors.cpu_temp)
    if [ "${cpu_temp_raw}" != null ]; then
        cpu_temp=$(printf "%.1f" "${cpu_temp_raw}")
        temp_unit=$(echo "${padd_data}" | GetPADDValue sensors.unit)
    fi

    # Temp + Unit
    if [ "${temp_unit}" = "C" ]; then
        temperature="${cpu_temp}°${temp_unit}"
        # no conversion needed
        cpu_temp_celsius="$(echo "${cpu_temp}" | awk -F '.' '{print $1}')"
        temp_unicode=true
    elif [ "${temp_unit}" = "F" ]; then
        temperature="${cpu_temp}°${temp_unit}"
        # convert to Celsius for limit checking
        cpu_temp_celsius="$(echo "${cpu_temp}" | awk '{print ($1-32) * 5 / 9}' | awk -F '.' '{print $1}')"
        temp_unicode=true
    elif [ "${temp_unit}" = "K" ]; then
        # no ° for Kelvin
        temperature="${cpu_temp}${temp_unit}"
        # convert to Celsius for limit checking
        cpu_temp_celsius="$(echo "${cpu_temp}" | awk '{print $1 - 273.15}' | awk -F '.' '{print $1}')"
        temp_unicode=false
    else # unknown unit
        temperature="N/A"
        # no conversion needed
        cpu_temp_celsius=-274
        temp_unicode=false
    fi

    # CPU temperature heatmap
    hot_flag=false
    # If we're getting close to 85°C... (https://www.raspberrypi.org/blog/introducing-turbo-mode-up-to-50-more-performance-for-free/)
    if [ "${cpu_temp_celsius}" -gt 80 ]; then
        temp_heatmap=${blinking_text}${red_text}
        # set flag to change the status message in SetStatusMessage()
        hot_flag=true
    elif [ "${cpu_temp_celsius}" -gt 70 ]; then
        temp_heatmap=${magenta_text}
    elif [ "${cpu_temp_celsius}" -gt 60 ]; then
        temp_heatmap=${blue_text}
    elif [ "${cpu_temp_celsius}" -gt -274 ]; then
        temp_heatmap=${cyan_text}
    else
        temp_heatmap=${reset_text}
    fi

    # CPU, load, heatmap
    core_count=$(GetPADDValue system.cpu.nprocs)
    cpu_load_1=$(printf %.2f "$(GetPADDValue system.cpu.load.raw.[0])")
    cpu_load_5=$(printf %.2f "$(GetPADDValue system.cpu.load.raw.[1])")
    cpu_load_15=$(printf %.2f "$(GetPADDValue system.cpu.load.raw.[2])")
    cpu_load_1_heatmap=$(HeatmapGenerator "${cpu_load_1}" "${core_count}")
    cpu_load_5_heatmap=$(HeatmapGenerator "${cpu_load_5}" "${core_count}")
    cpu_load_15_heatmap=$(HeatmapGenerator "${cpu_load_15}" "${core_count}")
    cpu_percent=$(printf %.1f "$(GetPADDValue system.cpu.load.percent.0)")

    # Memory use, heatmap and bar
    memory_percent_raw="$(GetPADDValue system.memory.ram.%used)"
    memory_percent=$(printf %.1f "${memory_percent_raw}")
    memory_heatmap="$(HeatmapGenerator "${memory_percent}")"

    # Get device model
    sys_model="$(GetPADDValue host_model)"

    # DOCKER_VERSION is set during GetVersionInformation, so this needs to run first during startup
    if [ "${DOCKER_VERSION}" != "null" ]; then
        # Docker image
        sys_model="Container"
    fi

    # Cleaning device model from useless OEM information
    sys_model=$(filterModel "${sys_model}")

    # FTL returns null if device information is not available
    if [  -z "${sys_model}" ] || [  "${sys_model}" = "null" ]; then
        sys_model="N/A"
    fi
}

GetNetworkInformation() {
    if [ "${connection_down_flag}" = true ]; then
        iface_name="N/A"
        pi_ip4_addr="N/A"
        pi_ip6_addr="N/A"
        ipv6_status="N/A"
        ipv6_heatmap=${reset_text}
        ipv6_check_box=${check_box_question}

        dhcp_status="N/A"
        dhcp_heatmap=${reset_text}
        dhcp_range="N/A"
        dhcp_range_heatmap=${reset_text}
        dhcp_ipv6_status="N/A"
        dhcp_ipv6_heatmap=${reset_text}
        dhcp_check_box=${check_box_question}

        pi_hostname="N/A"
        full_hostname="N/A"

        dns_count="N/A"
        dns_information="N/A"

        dnssec_status="N/A"
        dnssec_heatmap=${reset_text}

        conditional_forwarding_status="N/A"
        conditional_forwarding_heatmap=${reset_text}

        tx_bytes="N/A"
        rx_bytes="N/A"
        return
    fi

    gateway_v4_iface=$(GetPADDValue iface.v4.name)
    gateway_v6_iface=$(GetPADDValue iface.v4.name)

    # Get IPv4 address of the default interface
    pi_ip4_addrs="$(GetPADDValue iface.v4.num_addrs)"
    pi_ip4_addr="$(GetPADDValue iface.v4.addr)"
    if [ "${pi_ip4_addrs}" -eq 0 ]; then
        # No IPv4 address available
        pi_ip4_addr="N/A"
    elif [ "${pi_ip4_addrs}" -eq 1 ]; then
        # One IPv4 address available
        : # Do nothing as the address is already set
    else
        # More than one IPv4 address available
        pi_ip4_addr="${pi_ip4_addr}+"
    fi

    # Get IPv6 address of the default interface
    pi_ip6_addrs="$(GetPADDValue iface.v6.num_addrs)"
    pi_ip6_addr="$(GetPADDValue iface.v6.addr)"
    if [ "${pi_ip6_addrs}" -eq 0 ]; then
        # No IPv6 address available
        pi_ip6_addr="N/A"
        ipv6_check_box=${check_box_disabled}
        ipv6_status="Disabled"
        ipv6_heatmap=${blue_text}
    elif [ "${pi_ip6_addrs}" -eq 1 ]; then
        # One IPv6 address available
        ipv6_check_box=${check_box_good}
        ipv6_status="Enabled"
        ipv6_heatmap=${green_text}
    else
        # More than one IPv6 address available
        pi_ip6_addr="${pi_ip6_addr}+"
        ipv6_check_box=${check_box_good}
        ipv6_status="Enabled"
        ipv6_heatmap=${green_text}
    fi

    # Is Pi-Hole acting as the DHCP server?
    DHCP_ACTIVE="$(GetPADDValue config.dhcp_active )"

    if [ "${DHCP_ACTIVE}" = "true" ]; then
        DHCP_START="$(GetPADDValue config.dhcp_start)"
        DHCP_END="$(GetPADDValue config.dhcp_end)"

        dhcp_status="Enabled"
        dhcp_range="${DHCP_START} - ${DHCP_END}"
        dhcp_range_heatmap=${reset_text}
        dhcp_heatmap=${green_text}
        dhcp_check_box=${check_box_good}

        # Is DHCP handling IPv6?
        DHCP_IPv6="$(GetPADDValue config.dhcp_ipv6)"
        if [ "${DHCP_IPv6}" = "true" ]; then
            dhcp_ipv6_status="Enabled"
            dhcp_ipv6_heatmap=${green_text}
        else
            dhcp_ipv6_status="Disabled"
            dhcp_ipv6_heatmap=${blue_text}
        fi
    else
        dhcp_status="Disabled"
        dhcp_heatmap=${blue_text}
        dhcp_check_box=${check_box_disabled}
        dhcp_range="N/A"

        dhcp_ipv6_status="N/A"
        dhcp_range_heatmap=${yellow_text}
        dhcp_ipv6_heatmap=${yellow_text}
    fi

    # Get hostname
    pi_hostname="$(GetPADDValue node_name)"
    full_hostname=${pi_hostname}
    # when PI-hole is the DHCP server, append the domain to the hostname
    if [ "${DHCP_ACTIVE}" = "true" ]; then
        PIHOLE_DOMAIN="$(GetPADDValue config.dns_domain)"
        if [  -n "${PIHOLE_DOMAIN}" ]; then
            count=${pi_hostname}"."${PIHOLE_DOMAIN}
            count=${#count}
            if [ "${count}" -lt "18" ]; then
                full_hostname=${pi_hostname}"."${PIHOLE_DOMAIN}
            fi
        fi
    fi

    # Get the number of configured upstream DNS servers
    dns_count="$(GetPADDValue config.dns_num_upstreams)"
    # if there's only one DNS server
    if [ "${dns_count}" -eq 1 ]; then
        dns_information="1 server"
    else
        dns_information="${dns_count} servers"
    fi


    # DNSSEC
    DNSSEC="$(GetPADDValue config.dns_dnssec)"
    if [ "${DNSSEC}" = "true" ]; then
        dnssec_status="Enabled"
        dnssec_heatmap=${green_text}
    else
        dnssec_status="Disabled"
        dnssec_heatmap=${blue_text}
    fi

    # Conditional forwarding
    CONDITIONAL_FORWARDING="$(GetPADDValue config.dns_revServer_active)"
    if [ "${CONDITIONAL_FORWARDING}" = "true" ]; then
        conditional_forwarding_status="Enabled"
        conditional_forwarding_heatmap=${green_text}
    else
        conditional_forwarding_status="Disabled"
        conditional_forwarding_heatmap=${blue_text}
    fi

    # Default interface data (use IPv4 interface - we cannot show both and assume they are the same)
    iface_name="${gateway_v4_iface}"
    tx_bytes="$(GetPADDValue iface.v4.tx_bytes.value)"
    tx_bytes_unit="$(GetPADDValue iface.v4.tx_bytes.unit)"
    tx_bytes=$(printf "%.1f %b" "${tx_bytes}" "${tx_bytes_unit}")

    rx_bytes="$(GetPADDValue iface.v4.rx_bytes.value)"
    rx_bytes_unit="$(GetPADDValue iface.v4.rx_bytes.unit)"
    rx_bytes=$(printf "%.1f %b" "${rx_bytes}" "${rx_bytes_unit}")

    # If IPv4 and IPv6 interfaces are not the same, add a "*" to the interface
    # name to highlight that there are two different interfaces and the
    # displayed statistics are only for the IPv4 interface, while the IPv6
    # address correctly corresponds to the default IPv6 interface
    if [ "${gateway_v4_iface}" != "${gateway_v6_iface}" ]; then
        iface_name="${iface_name}*"
    fi
}

GetPiholeInformation() {
    if [ "${connection_down_flag}" = true ]; then
        ftl_status="No connection"
        ftl_heatmap=${red_text}
        ftl_check_box=${check_box_bad}
        ftl_cpu="N/A"
        ftl_mem_percentage="N/A"
        dns_status="DNS offline"
        dns_heatmap=${red_text}
        dns_check_box=${check_box_bad}
        ftlPID="N/A"
        dns_down_flag=true

        return
    fi

    ftl_status="Running"
    ftl_heatmap=${green_text}
    ftl_check_box=${check_box_good}
    # Get FTL CPU and memory usage
    ftl_cpu_raw="$(GetPADDValue "%cpu")"
    ftl_mem_percentage_raw="$(GetPADDValue "%mem")"
    ftl_cpu="$(printf "%.1f" "${ftl_cpu_raw}")%"
    ftl_mem_percentage="$(printf "%.1f" "${ftl_mem_percentage_raw}")%"
    # Get Pi-hole (blocking) status
    ftl_dns_port=$(GetPADDValue config.dns_port)
    # Get FTL's current PID
    ftlPID="$(GetPADDValue pid)"



    # ${ftl_dns_port} == 0 DNS server part of dnsmasq disabled
    dns_down_flag=false
    if [ "${ftl_dns_port}" = 0 ]; then
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
    if [ "${connection_down_flag}" = true ]; then
        DOCKER_VERSION=null
        CORE_VERSION="N/A"
        WEB_VERSION="N/A"
        FTL_VERSION="N/A"
        core_version_heatmap=${reset_text}
        web_version_heatmap=${reset_text}
        ftl_version_heatmap=${reset_text}
        return
    fi

    out_of_date_flag=false

    # Gather DOCKER version information...
    # returns "null" if not running Pi-hole in Docker container
    DOCKER_VERSION="$(GetPADDValue version.docker.local)"

    # If PADD is running inside docker, immediately return without checking for updated component versions
    if [ "${DOCKER_VERSION}" != "null" ] ; then
        GITHUB_DOCKER_VERSION="$(GetPADDValue version.docker.remote)"
        docker_version_converted="$(VersionConverter "${DOCKER_VERSION}")"
        docker_version_latest_converted="$(VersionConverter "${GITHUB_DOCKER_VERSION}")"

    # Note: the version comparison will fail for any Docker tag not following a 'YYYY.MM.VV' scheme
    #       e.g. 'nightly', 'beta', 'v6-pre-alpha' and might set a false out_of_date_flag
    #       As those versions are not meant to be used in production, we ignore this small bug
        if [ "${docker_version_converted}" -lt "${docker_version_latest_converted}" ]; then
            out_of_date_flag="true"
            docker_version_heatmap=${red_text}
        else
            docker_version_heatmap=${green_text}
        fi
        return
    fi

    # Gather core version information...
    CORE_BRANCH="$(GetPADDValue version.core.local.branch)"
    CORE_VERSION="$(GetPADDValue version.core.local.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
    GITHUB_CORE_VERSION="$(GetPADDValue version.core.remote.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
    CORE_HASH="$(GetPADDValue version.core.local.hash)"
    GITHUB_CORE_HASH="$(GetPADDValue version.core.remote.hash)"

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
            CORE_VERSION="$(printf '%s' "${CORE_BRANCH}" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
        fi
    fi

  # Gather web version information...
    WEB_VERSION="$(GetPADDValue version.web.local.version)"

    if [ "${WEB_VERSION}" != "null" ]; then
        WEB_BRANCH="$(GetPADDValue version.web.local.branch)"
        WEB_VERSION="$(GetPADDValue version.web.local.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
        GITHUB_WEB_VERSION="$(GetPADDValue version.web.remote.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
        WEB_HASH="$(GetPADDValue version.web.local.hash)"
        GITHUB_WEB_HASH="$(GetPADDValue version.web.remote.hash)"

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
                WEB_VERSION="$(printf '%s' "${WEB_BRANCH}" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
            fi
        fi
    else
        # Web interface not installed
        WEB_VERSION="N/A"
        web_version_heatmap=${yellow_text}
    fi

    # Gather FTL version information...
    FTL_BRANCH="$(GetPADDValue version.ftl.local.branch)"
    FTL_VERSION="$(GetPADDValue version.ftl.local.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
    GITHUB_FTL_VERSION="$(GetPADDValue version.ftl.remote.version | tr -d '[:alpha:]' | awk -F '-' '{printf $1}')"
    FTL_HASH="$(GetPADDValue version.ftl.local.hash)"
    GITHUB_FTL_HASH="$(GetPADDValue version.ftl.remote.hash)"


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
            FTL_VERSION="$(printf '%s' "${FTL_BRANCH}" | sed 's/fix\//f\//;s/new\//n\//;s/tweak\//t\//' | cut -c 1-7)"
        fi
    fi

}

GetPADDInformation() {

    # PADD version information...
    padd_version_latest="$(curl --connect-timeout 5 --silent https://api.github.com/repos/pi-hole/PADD/releases/latest | grep '"tag_name":' | awk -F \" '{print $4}')"
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
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 9 "color")

    elif  [ "$1" = "micro" ]; then
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 10 "color")

    elif [ "$1" = "mini" ]; then
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 20 "color")

        latest_blocked=$(truncateString "${latest_blocked_raw}" 29)
        top_blocked=$(truncateString "${top_blocked_raw}" 29)

    elif [ "$1" = "tiny" ]; then
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 30 "color")

        latest_blocked=$(truncateString "${latest_blocked_raw}" 41)
        top_blocked=$(truncateString "${top_blocked_raw}" 41)
        top_domain=$(truncateString "${top_domain_raw}" 41)
        top_client=$(truncateString "${top_client_raw}" 41)

    elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 40 "color")

        latest_blocked=$(truncateString "${latest_blocked_raw}" 48)
        top_blocked=$(truncateString "${top_blocked_raw}" 48)
        top_domain=$(truncateString "${top_domain_raw}" 48)
        top_client=$(truncateString "${top_client_raw}" 48)

        if [ "${temp_unicode}" = true ]; then
            temp_padding=21
        else
            temp_padding=20
        fi

    elif [ "$1" = "mega" ]; then
        ads_blocked_bar=$(BarGenerator "${ads_percentage_today}" 30 "color")

        latest_blocked=$(truncateString "${latest_blocked_raw}" 68)
        top_blocked=$(truncateString "${top_blocked_raw}" 68)
        top_domain=$(truncateString "${top_domain_raw}" 68)
        top_client=$(truncateString "${top_client_raw}" 68)

        if [ "${temp_unicode}" = true ]; then
            temp_padding=10
        else
            temp_padding=9
        fi

    fi

    # System uptime
    if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
        system_uptime="$(convertUptime "${system_uptime_raw}" | awk -F ',' '{print $1 "," $2}')"
    else
        system_uptime="$(convertUptime "${system_uptime_raw}")"
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

    elif [ "${connection_down_flag}" = true ]; then
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

    elif [ "${blocking_enabled}" = "disabled" ]; then
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

    elif [ "${blocking_enabled}" = "enabled" ]; then
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
        moveXOffset; printf "%s${clear_line}\n" "p${padd_text}"
    elif [ "$1" = "nano" ]; then
        moveXOffset; printf "%s${clear_line}\n" "n${padd_text}"
    elif [ "$1" = "micro" ]; then
        moveXOffset; printf "%s${clear_line}\n\n" "µ${padd_text}"
    elif [ "$1" = "mini" ]; then
        moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}mini${reset_text} Pi-hole® Ad Detection Display"
        moveXOffset; printf "%s${clear_line}\n" "         A client for Pi-hole®"
    else
        moveXOffset; printf "%b" "${padd_logo_1}\n"
        moveXOffset; printf "%b" "${padd_logo_2}Pi-hole® Ad Detection Display\n"
        moveXOffset; printf "%b" "${padd_logo_3}A client for Pi-hole\n\n"
    fi
}

PrintDashboard() {
    if [ "${DOCKER_VERSION}" != "null" ]; then
        version_info="Docker ${docker_version_heatmap}${DOCKER_VERSION}${reset_text}"
    else
        version_info="Pi-hole® ${core_version_heatmap}${CORE_VERSION}${reset_text}, Web ${web_version_heatmap}${WEB_VERSION}${reset_text}, FTL ${ftl_version_heatmap}${FTL_VERSION}${reset_text}"
    fi
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
        moveXOffset; printf "%s${clear_line}\n" " IPv6 ${ipv6_check_box} DHCP ${dhcp_check_box}"
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
        moveXOffset; printf "%s${clear_line}\n" " IPv6: ${ipv6_check_box}    DHCP: ${dhcp_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Up:  ${system_uptime}"
        moveXOffset; printf "%s${clear_line}"  " CPU: [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
    elif [ "$1" = "micro" ]; then
        # micro is a screen at least 30x16 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "µ${padd_text}     ${mini_status}"
        moveXOffset; printf "%s${clear_line}\n" ""
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE ======================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " DNS:  ${dns_check_box}        FTL:  ${ftl_check_box}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ========================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Blckng:  ${domains_being_blocked} domains"
        moveXOffset; printf "%s${clear_line}\n" " Piholed: [${ads_blocked_bar}] ${ads_percentage_today}%"
        moveXOffset; printf "%s${clear_line}\n" " Piholed: ${ads_blocked_today} / ${dns_queries_today}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ======================${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" " Host:    ${full_hostname}"
        moveXOffset; printf "%s${clear_line}\n" " IP:      ${pi_ip4_addr}"
        moveXOffset; printf "%s${clear_line}\n" " IPv6: ${ipv6_check_box}       DHCP:  ${dhcp_check_box}"
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
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ================================${reset_text}"
        moveXOffset; printf " %-9s%-16s%-5s%-9s${clear_line}\n" "Host:" "${full_hostname}" "DNS:" "${dns_information}"
        moveXOffset; printf " %-9s%s${clear_line}\n" "IP:" "${pi_ip4_addr} (${iface_name})"
        moveXOffset; printf " %-9s${ipv6_heatmap}%-10s${reset_text} %-8s${dhcp_heatmap}%-10s${reset_text}${clear_line}\n" "IPv6:" "${ipv6_status}" "DHCP:" "${dhcp_status}"

        moveXOffset; printf " %-9s%-4s%-12s%-4s%-5s${clear_line}\n" "Traffic:" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =================================${reset_text}"
        moveXOffset; printf " %-9s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf "%s${clear_line}\n" " Load:    [${cpu_load_1_heatmap}${cpu_bar}${reset_text}] ${cpu_percent}%"
        moveXOffset; printf "%s${clear_line}" " Memory:  [${memory_heatmap}${memory_bar}${reset_text}] ${memory_percent}%"
    elif [ "$1" = "tiny" ]; then
         # tiny is a screen at least 53x20 (columns x lines)
        moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}tiny${reset_text}   ${version_info}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text} ${tiny_status}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}PI-HOLE =============================================${reset_text}"
        moveXOffset; printf " %-10s${dns_heatmap}%-16s${reset_text} %-8s${ftl_heatmap}%-10s${reset_text}${clear_line}\n" "DNS:" "${dns_status}" "FTL:" "${ftl_status}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}STATS ===============================================${reset_text}"
        moveXOffset; printf " %-10s%-29s${clear_line}\n" "Blocking:" "${domains_being_blocked} domains"
        moveXOffset; printf " %-10s[%-30s] %-5s${clear_line}\n" "Pi-holed:" "${ads_blocked_bar}" "${ads_percentage_today}%"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Pi-holed:" "${ads_blocked_today} out of ${dns_queries_today}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Latest:" "${latest_blocked}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Top Ad:" "${top_blocked}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK =============================================${reset_text}"
        moveXOffset; printf " %-10s%-16s %-8s%-16s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:  " "${pi_ip4_addr}"
        moveXOffset; printf " %-10s%-16s %-4s%-7s %-4s%-5s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-10s%-16s %-8s${dnssec_heatmap}%-16s${reset_text}${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_status}"
        moveXOffset; printf " %-10s%s${clear_line}\n" "IPv6:" "${pi_ip6_addr}"
        moveXOffset; printf " %-10s%-5s %-4s${dhcp_range_heatmap}%-33s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_check_box}" "Rng" "${dhcp_range}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM ==============================================${reset_text}"
        moveXOffset; printf " %-10s%-29s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf " %-10s${temp_heatmap}%-17s${reset_text} %-8s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Temp:" "${temperature}" "Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        moveXOffset; printf " %-10s[${memory_heatmap}%-7s${reset_text}] %-6s %-8s[${cpu_load_1_heatmap}%-7s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU:" "${cpu_bar}" "${cpu_percent}%"
    elif [ "$1" = "regular" ] || [ "$1" = "slim" ]; then
        # slim is a screen with at least 60 columns and exactly 21 lines
        # regular is a screen at least 60x22 (columns x lines)
        if [ "$1" = "slim" ]; then
           moveXOffset; printf "%s${clear_line}\n" "${padd_text}${dim_text}slim${reset_text}   ${version_info}${reset_text}"
           moveXOffset; printf "%s${clear_line}\n" "           PADD ${padd_version_heatmap}${padd_version}${reset_text}   ${full_status}${reset_text}"
           moveXOffset; printf "%s${clear_line}\n" ""
        else
            moveXOffset; printf "%s${clear_line}\n" "${padd_logo_1}"
            moveXOffset; printf "%s${clear_line}\n" "${padd_logo_2}${version_info}${reset_text}"
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
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ====================================================${reset_text}"
        moveXOffset; printf " %-10s%-15s %-4s%-17s${clear_line}\n" "Hostname:" "${full_hostname}" "IP:" "${pi_ip4_addr}"
        moveXOffset; printf " %-10s%-15s %-4s%-17s%-4s%s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-10s%s${clear_line}\n" "IPv6:" "${pi_ip6_addr}"
        moveXOffset; printf " %-10s%-15s %-10s${dnssec_heatmap}%-19s${reset_text}${clear_line}\n" "DNS:" "${dns_information}" "DNSSEC:" "${dnssec_status}"
        moveXOffset; printf " %-10s%-16s%-6s${dhcp_range_heatmap}%-36s${reset_text}${clear_line}\n" "DHCP:" "${dhcp_check_box}" "Range" "${dhcp_range}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =====================================================${reset_text}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Uptime:" "${system_uptime}"
        moveXOffset; printf " %-10s${temp_heatmap}%-""${temp_padding}""s${reset_text}%-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-4s${reset_text}${clear_line}\n" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}"
        moveXOffset; printf " %-10s[${memory_heatmap}%-10s${reset_text}] %-6s %-10s[${cpu_load_1_heatmap}%-10s${reset_text}] %-5s${clear_line}" "Memory:" "${memory_bar}" "${memory_percent}%" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
    else # ${padd_size} = mega
         # mega is a screen with at least 80 columns and 26 lines
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_1}"
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_2}   ${version_info}, PADD ${padd_version_heatmap}${padd_version}${reset_text}"
        moveXOffset; printf "%s${clear_line}\n" "${padd_logo_3}   ${dns_check_box} DNS   ${ftl_check_box} FTL   ${mega_status}${reset_text}"
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
        moveXOffset; printf " %-10s%-69s${clear_line}\n" "DNSCache:" "${cache_inserts} insertions, ${cache_evictions} deletions, ${cache_size} total entries"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}NETWORK ========================================================================${reset_text}"
        moveXOffset; printf " %-10s%-19s${clear_line}\n" "Hostname:" "${full_hostname}"
        moveXOffset; printf " %-10s%-15s %-4s%-9s %-4s%-9s${clear_line}\n" "Interfce:" "${iface_name}" "TX:" "${tx_bytes}" "RX:" "${rx_bytes}"
        moveXOffset; printf " %-6s%-19s %-10s%-29s${clear_line}\n" "IPv4:" "${pi_ip4_addr}" "IPv6:" "${pi_ip6_addr}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}DNS ==========================DHCP==============================================${reset_text}"
        moveXOffset; printf " %-10s%-19s %-6s${dhcp_heatmap}%-19s${reset_text}${clear_line}\n" "Servers:" "${dns_information}" "DHCP:" "${dhcp_status}"
        moveXOffset; printf " %-10s${dnssec_heatmap}%-19s${reset_text} %-10s${dhcp_ipv6_heatmap}%-9s${reset_text}${clear_line}\n" "DNSSEC:" "${dnssec_status}" "IPv6 Spt:" "${dhcp_ipv6_status}"
        moveXOffset; printf " %-10s${conditional_forwarding_heatmap}%-20s${reset_text}%-6s${dhcp_range_heatmap}%-36s${reset_text}${clear_line}\n" "CdFwding:" "${conditional_forwarding_status}" "Range" "${dhcp_range}"
        moveXOffset; printf "%s${clear_line}\n" "${bold_text}SYSTEM =========================================================================${reset_text}"
        moveXOffset; printf " %-10s%-39s${clear_line}\n" "Device:" "${sys_model}"
        moveXOffset; printf " %-10s%-39s %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}\n" "Uptime:" "${system_uptime}" "Memory:" "${memory_bar}" "${memory_percent}%"
        moveXOffset; printf " %-10s${temp_heatmap}%-""${temp_padding}""s${reset_text} %-10s${cpu_load_1_heatmap}%-4s${reset_text}, ${cpu_load_5_heatmap}%-4s${reset_text}, ${cpu_load_15_heatmap}%-7s${reset_text} %-10s[${memory_heatmap}%-10s${reset_text}] %-6s${clear_line}" "CPU Temp:" "${temperature}" "CPU Load:" "${cpu_load_1}" "${cpu_load_5}" "${cpu_load_15}" "CPU Load:" "${cpu_bar}" "${cpu_percent}%"
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
    if [ -z "${2}" ]; then
        load=$(printf "%.0f" "${1}")
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

    echo "${out}"
}

# Provides a "bar graph"
# takes in two or three parameters
# $1: percentage filled
# $2: max length of the bar
# $3: colored flag, if "color" backfill with color
BarGenerator() {
    # number of filled in cells in the bar
    barNumber=$(printf %.f "$(echo "$1 $2" | awk '{print ($1 / 100) * $2}')")
    frontFill=$(for i in $(seq "${barNumber}"); do printf "%b" "■"; done)

    # remaining "unfilled" cells in the bar
    backfillNumber=$(($2-barNumber))

    # if the filled in cells is less than the max length of the bar, fill it
    if [ "${barNumber}" -lt "${2}" ]; then
        # if the bar should be colored
        if [ "$3" = "color" ]; then
        # fill the rest in color
        backFill=$(for i in $(seq ${backfillNumber}); do printf "%b" "■"; done)
        out="${red_text}${frontFill}${green_text}${backFill}${reset_text}"
        # else, it shouldn't be colored in
        else
        # fill the rest with "space"
        backFill=$(for i in $(seq ${backfillNumber}); do printf "%b" "·"; done)
        out="${frontFill}${reset_text}${backFill}"
        fi
    # else, fill it all the way
    else
        out=$(for i in $(seq "${2}"); do printf "%b" "■"; done)
    fi

    echo "${out}"
}

# Checks the size of the screen and sets the value of ${padd_data}_size
SizeChecker(){
    # adding a tiny delay here to to give the kernel a bit time to
    # report new sizes correctly after a terminal resize
    # this reduces "flickering" of GenerateSizeDependendOutput() items
    # after a terminal re-size
    sleep 0.1
    console_width=$(tput cols)
    console_height=$(tput lines)

    # Mega
    if [ "${console_width}" -ge "80" ] && [ "${console_height}" -ge "26" ]; then
        padd_size="mega"
        width=80
        height=26
    # Below Mega. Gives you Regular.
    elif [ "${console_width}" -ge "60" ] && [ "${console_height}" -ge "22" ]; then
        padd_size="regular"
        width=60
        height=22
    # Below Regular. Gives you Slim.
    elif [ "${console_width}" -ge "60" ] && [ "${console_height}" -ge "21" ]; then
        padd_size="slim"
        width=60
        height=21
    # Below Slim. Gives you Tiny.
    elif [ "${console_width}" -ge "53" ] && [ "${console_height}" -ge "20" ]; then
        padd_size="tiny"
        width=53
        height=20
    # Below Tiny. Gives you Mini.
    elif [ "${console_width}" -ge "40" ] && [ "${console_height}" -ge "18" ]; then
        padd_size="mini"
        width=40
        height=18
    # Below Mini. Gives you Micro.
    elif [ "${console_width}" -ge "30" ] && [ "${console_height}" -ge "16" ]; then
        padd_size="micro"
        width=30
        height=16
    # Below Micro, Gives you Nano.
    elif [ "${console_width}" -ge "24" ] && [ "${console_height}" -ge "12" ]; then
        padd_size="nano"
        width=24
        height=12
    # Below Nano. Gives you Pico.
    elif [ "${console_width}" -ge "20" ] && [ "${console_height}" -ge "10" ]; then
        padd_size="pico"
        width=20
        height=10
    # Below Pico. Gives you nothing...
    else
        padd_size="ants"
    fi

    # Center the output (default position)
    xOffset="$(( (console_width - width) / 2 ))"
    yOffset="$(( (console_height - height) / 2 ))"

    # If the user sets an offset option, use it.
    if [ -n "${xOffOrig}" ]; then
        xOffset=${xOffOrig}

        # Limit the offset to avoid breaks
        xMaxOffset=$((console_width - width))
        if [ "${xOffset}" -gt "${xMaxOffset}" ]; then
            xOffset="${xMaxOffset}"
        fi
    fi
    if [ -n "${yOffOrig}" ]; then
        yOffset=${yOffOrig}

        # Limit the offset to avoid breaks
        yMaxOffset=$((console_height - height))
        if [ "${yOffset}" -gt "${yMaxOffset}" ]; then
            yOffset="${yMaxOffset}"
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
}

# Remove undesired strings from sys_model variable - used in GetSystemInformation() function
filterModel() {
    FILTERLIST="To be filled by O.E.M.|Not Applicable|System Product Name|System Version|Undefined|Default string|Not Specified|Type1ProductConfigId|INVALID|All Series|�"

    # Description:
    #    `-v`      : set $FILTERLIST into a variable called `list`
    #    `gsub()`  : replace all list items (ignoring case) with an empty string, deleting them
    #    `{$1=$1}1`: remove all extra spaces. The last "1" evaluates as true, printing the result
    echo "$1" | awk -v list="${FILTERLIST}" '{IGNORECASE=1; gsub(list,"")}; {$1=$1}1'
}

# Truncates a given string and appends three '...'
# takes two parameters
# $1: string to truncate
# $2: max length of the string
truncateString() {
    local truncatedString length shorted

    length=${#1}
    shorted=$(($2-3)) # shorten max allowed length by 3 to make room for the dots
    if [ "${length}" -gt "${2}" ]; then
        # if length of the string is larger then the specified max length
        # cut every char from the string exceeding length $shorted and add three dots
        truncatedString=$(echo "$1" | cut -c1-${shorted})"..."
        echo "${truncatedString}"
    else
        echo "$1"
    fi
}

# Converts seconds to days, hours, minutes
# https://unix.stackexchange.com/a/338844
convertUptime() {

    local D=$(($1/60/60/24))
    local H=$(($1/60/60%24))
    local M=$(($1/60%60))

    printf "%d days, %02d hours, %02d minutes" "${D}" "${H}" "${M}"
}

secretRead() {

    # POSIX compliant function to read user-input and
    # mask every character entered by (*)
    #
    # This is challenging, because in POSIX, `read` does not support
    # `-s` option (suppressing the input) or
    # `-n` option (reading n chars)


    # This workaround changes the terminal characteristics to not echo input and later resets this option
    # credits https://stackoverflow.com/a/4316765
    # showing asterisk instead of password
    # https://stackoverflow.com/a/24600839
    # https://unix.stackexchange.com/a/464963

    stty -echo # do not echo user input
    stty -icanon min 1 time 0 # disable canonical mode https://man7.org/linux/man-pages/man3/termios.3.html

    unset password
    unset key
    unset charcount
    charcount=0
    while key=$(dd ibs=1 count=1 2>/dev/null); do #read one byte of input
        if [ "${key}" = "$(printf '\0' | tr -d '\0')" ] ; then
            # Enter - accept password
            break
        fi
        if [ "${key}" = "$(printf '\177')" ] ; then
            # Backspace
            if [ ${charcount} -gt 0 ] ; then
                charcount=$((charcount-1))
                printf '\b \b'
                password="${password%?}"
            fi
        else
            # any other character
            charcount=$((charcount+1))
            printf '*'
            password="${password}${key}"
        fi
    done

    # restore original terminal settings
    stty "${stty_orig}"
}

check_dependencies() {
    local hasDeps=true
    # Check for required dependencies
    if ! command -v curl >/dev/null 2>&1; then
        printf "%b" "${check_box_bad} Error!\n    'curl' is missing but required.\n"
        hasDeps=false
    fi

    if ! command -v jq >/dev/null 2>&1; then
        printf "%b" "${check_box_bad} Error!\n    'jq' is missing but required.\n"
        hasDeps=false
    fi

    if ! command -v dig >/dev/null 2>&1; then
        printf "%b" "${check_box_bad} Error!\n    'dig' is missing but required.\n"
        hasDeps=false
    fi

    if ! command -v tput >/dev/null 2>&1; then
        printf "%b" "${check_box_bad} Error!\n    'tput' is missing but required.\n"
        hasDeps=false
     fi

    if [ "${hasDeps}" = false ]; then
        printf "%b" "\n Please install the missing dependencies noted above.\n"
        exit 1
    fi
}

########################################## MAIN FUNCTIONS ##########################################

ShowVersion() {

    GetPADDInformation

    if [ -z "${padd_version_latest}" ]; then
        padd_version_latest="N/A"
    fi

    printf "\n%s${clear_line}\n" "PADD version is ${padd_version_heatmap}${padd_version}${reset_text} (Latest: ${padd_version_latest})"

    exit 0
}

StartupRoutine(){

    if [ "$1" = "ants" ]; then
        # If the screen is too small from the beginning, exit
        printf "%b" "${check_box_bad} Error!\n    PADD isn't\n    for ants!\n"
        exit 1
    fi

    # Clear the screen and move cursor to (0,0).
    # This mimics the 'clear' command.
    # https://vt100.net/docs/vt510-rm/ED.html
    # https://vt100.net/docs/vt510-rm/CUP.html
    # E3 extension `\e[3J` to clear the scrollback buffer see 'man clear'
    printf '\e[H\e[2J\e[3J'

    # adds the y-offset
    moveYOffset

    if [ "$1" = "pico" ] || [ "$1" = "nano" ] || [ "$1" = "micro" ]; then
        PrintLogo "$1"
        if [ "$1" = "pico" ]; then
            moveXOffset; printf "%b" "START-UP ===========\n"
        elif [ "$1" = "nano" ]; then
            moveXOffset; printf "%b" "START-UP ===============\n"
        else
            moveXOffset; printf "%b" "START-UP =====================\n"
        fi

        # Test if the authentication endpoint is available
        TestAPIAvailability

        # Authenticate with the FTL server
        moveXOffset; printf "%b" "Establishing connection with FTL...\n"
        LoginAPI

        moveXOffset; printf "%b" "Starting PADD...\n"

        moveXOffset; printf "%b" " [■·········]  10%\r"

        # Request PADD data
        GetPADDData

        # Check for updates
        moveXOffset; printf "%b" " [■■········]  20%\r"
        moveXOffset; printf "%b" " [■■■·······]  30%\r"

        # Get our information for the first time
        moveXOffset; printf "%b" " [■■■■······]  40%\r"
        GetVersionInformation
        moveXOffset; printf "%b" " [■■■■■·····]  50%\r"
        GetSummaryInformation
        moveXOffset; printf "%b" " [■■■■■■····]  60%\r"
        GetPiholeInformation
        moveXOffset; printf "%b" " [■■■■■■■···]  70%\r"
        GetNetworkInformation
        moveXOffset; printf "%b" " [■■■■■■■■··]  80%\r"
        GetSystemInformation
        moveXOffset; printf "%b" " [■■■■■■■■■·]  90%\r"
        GetPADDInformation
        moveXOffset; printf "%b" " [■■■■■■■■■■] 100%\n"

    elif [ "$1" = "mini" ]; then
        PrintLogo "$1"
        moveXOffset; echo "START UP ==============================="
        # Test if the authentication endpoint is available
        TestAPIAvailability
        # Authenticate with the FTL server
        moveXOffset; printf "%b" "Establishing connection with FTL...\n"
        LoginAPI

        # Request PADD data
        moveXOffset; echo "- Requesting PADD information..."
        GetPADDData

        # Get our information for the first time
        moveXOffset; echo "- Gathering version info."
        GetVersionInformation
        moveXOffset; echo "- Gathering system info."
        GetSystemInformation
        moveXOffset; echo "- Gathering CPU/DNS info."
        GetPiholeInformation
        GetSummaryInformation
        moveXOffset; echo "- Gathering network info."
        GetNetworkInformation
        GetPADDInformation
        if [ "${DOCKER_VERSION}" != "null" ]; then
        moveXOffset; echo "  - Docker Tag ${DOCKER_VERSION}"
        else
        moveXOffset; echo "  - Core ${CORE_VERSION}, Web ${WEB_VERSION}"
        moveXOffset; echo "  - FTL ${FTL_VERSION}, PADD ${padd_version}"
        fi

    else
        PrintLogo "$1"
        if [ "$1" = "tiny" ]; then
        moveXOffset; echo "START UP ============================================"
        else
        moveXOffset; echo "START UP ==================================================="
        fi

        # Test if the authentication endpoint is available
        TestAPIAvailability

        # Authenticate with the FTL server
        moveXOffset; printf "%b" "Establishing connection with FTL...\n"
        LoginAPI

        # Request PADD data
        moveXOffset; echo "- Requesting PADD information..."
        GetPADDData

        # Get our information for the first time
        moveXOffset; echo "- Gathering version information..."
        GetVersionInformation
        moveXOffset; echo "- Gathering system information..."
        GetSystemInformation
        moveXOffset; echo "- Gathering CPU/DNS information..."
        GetSummaryInformation
        GetPiholeInformation
        moveXOffset; echo "- Gathering network information..."
        GetNetworkInformation

        GetPADDInformation
        if [ "${DOCKER_VERSION}" != "null" ]; then
        moveXOffset; echo "  - Docker Tag ${DOCKER_VERSION}"
        else
        moveXOffset; echo "  - Pi-hole Core ${CORE_VERSION}"
        moveXOffset; echo "  - Web Admin ${WEB_VERSION}"
        moveXOffset; echo "  - FTL ${FTL_VERSION}"
        moveXOffset; echo "  - PADD ${padd_version}"
        fi
    fi

    if [ "${runOnce}" = "false" ]; then
        moveXOffset; printf "%s" "- Starting in "
        for i in 3 2 1
        do
            printf "%s..." "${i}"
            sleep 1
        done
    fi

}

NormalPADD() {

    # Trap the window resize signal (handle window resize events)
    trap 'TerminalResize' WINCH


    # Clear the screen once on startup to remove overflow from the startup routine
    printf '\033[2J'

    while true; do

    # Generate output that depends on the terminal size
    # e.g. Heatmap and barchart
    GenerateSizeDependendOutput ${padd_size}

    # Sets the message displayed in the "status field" depending on the set flags
    SetStatusMessage

    # Output everything to the screen
    PrintDashboard ${padd_size}

    # Should we only run once?
    if [ "${runOnce}" = "true" ]; then
        break
    fi

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

    # check if a new authentication is required (e.g. after connection to FTL has re-established)
    # GetFTLData() will return a 401 if a 401 http status code is returned
    # as $password should be set already, PADD should automatically re-authenticate
    authenthication_required=$(GetFTLData "info/ftl")
    if [ "${authenthication_required}" = 401 ]; then
      Authenticate
    fi

    # Request PADD data after 30 seconds or if the connection was lost
    if [ $((now - LastCheckFullInformation)) -ge 30 ] || [ "${connection_down_flag}" = true ] ; then
        GetPADDData
        LastCheckFullInformation="${now}"
    else
        # Request only a subset of the data
        GetPADDData "?full=false"
    fi

    connection_down_flag=false
    # If the connection was lost, set connection_down_flag
    if [ "${padd_data}" = "000" ]; then
        connection_down_flag=true
        GetSystemInformation
        GetSummaryInformation
        GetPiholeInformation
        GetNetworkInformation
        GetVersionInformation
        # set flag to update network information in the next loop in case the connection is re-established
        get_network_information_requried=true
    else
        # Get uptime, CPU load, temp, etc. every 5 seconds
        GetSystemInformation
        GetSummaryInformation
        GetPiholeInformation

        if [ $((now - LastCheckNetworkInformation)) -ge 30 ] || [ "${get_network_information_requried}" = true ]; then
            GetNetworkInformation
            GetVersionInformation
            LastCheckNetworkInformation="${now}"
            get_network_information_requried=false
        fi

        # Get PADD version information every 24hours
        if [ $((now - LastCheckPADDInformation)) -ge 86400 ]; then
            GetPADDInformation
            LastCheckPADDInformation="${now}"
        fi
    fi

  done
}

Update() {

    GetPADDInformation

    if [ "${padd_out_of_date_flag}" = "true" ]; then
        echo "${check_box_info} Updating PADD from ${padd_version} to ${padd_version_latest}"

        padd_script_path=$(realpath "$0")

        echo "${check_box_info} Downloading PADD update ..."

        if  curl --connect-timeout 5 -sSL https://install.padd.sh -o "${padd_script_path}" > /dev/null 2>&1; then
            echo "${check_box_good} ... done. Restart PADD for the update to take effect"
        else
            echo "${check_box_bad} Cannot download PADD update"
            echo "${check_box_info} Go to https://install.padd.sh to download the update manually"
            exit 1
        fi
    else
        echo "${check_box_good} You are already using the latest PADD version ${padd_version}"
    fi

    exit 0
}

DisplayHelp() {
    cat << EOM

::: PADD displays stats about your Pi-hole!
:::
:::
::: Options:
:::  --xoff [num]    set the x-offset, reference is the upper left corner, disables auto-centering
:::  --yoff [num]    set the y-offset, reference is the upper left corner, disables auto-centering
:::
:::  --server <DOMAIN|IP>    domain or IP of your Pi-hole (default: localhost)
:::  --api <API URL>         API URL location of your Pi-hole (example: https://pi.hole/api/)
:::  --secret <password>     your Pi-hole's password, required to access the API
:::  --2fa <2fa>             your Pi-hole's 2FA code, if 2FA is enabled
:::  --runonce               display output once and exit
:::  -u, --update            update to the latest version
:::  -v, --version           show PADD version info
:::  -h, --help              display this help text

EOM
}

# Called on signals INT QUIT TERM
sig_cleanup() {
    # save error code (130 for SIGINT, 143 for SIGTERM, 131 for SIGQUIT)
    err=$?

    # some shells will call EXIT after the INT signal
    # causing EXIT trap to be executed, so we trap EXIT after INT
    trap '' EXIT

    (exit ${err}) # execute in a subshell just to pass $? to CleanExit()
    CleanExit
}

# Called on signal EXIT, or indirectly on INT QUIT TERM
CleanExit() {
    # save the return code of the script
    err=$?

    # reset trap for all signals to not interrupt clean_tempfiles() on any next signal
    trap '' EXIT INT QUIT TERM

    # restore terminal settings if they have been changed (e.g. user canceled script while at password input prompt)
    if [ "$(stty -g)" != "${stty_orig}" ]; then
        stty "${stty_orig}"
    fi

    # Show the cursor
    # https://vt100.net/docs/vt510-rm/DECTCEM.html
    printf '\e[?25h'

    # if background sleep is running, kill it
    # http://mywiki.wooledge.org/SignalTrap#When_is_the_signal_handled.3F
    kill "${sleepPID}" > /dev/null 2>&1

    #  Delete session from FTL server
    DeleteSession
    exit ${err} # exit the script with saved $?
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

    kill "${sleepPID}" > /dev/null 2>&1
}

main(){

    check_dependencies

    # Hiding the cursor.
    # https://vt100.net/docs/vt510-rm/DECTCEM.html
    printf '\e[?25l'

    # Traps for graceful shutdown
    # https://unix.stackexchange.com/a/681201
    trap CleanExit EXIT
    trap sig_cleanup INT QUIT TERM

    # Save current terminal settings (needed for later restore after password prompt)
    stty_orig=$(stty -g)


    SizeChecker

    StartupRoutine ${padd_size}

    # Run SizeChecker again to account for resizing during startup
    SizeChecker

    # Run PADD
    NormalPADD
}

# Process all options (if present)
while [ "$#" -gt 0 ]; do
    case "$1" in
        "-u" | "--update"   ) xOffset=0; doUpdate=true;;
        "-h" | "--help"     ) DisplayHelp; exit 0;;
        "-v" | "--version"  ) xOffset=0; versionOnly=true ;;
        "--runonce"         ) runOnce=true;;
        "--xoff"            ) xOffset="${2}"; xOffOrig="${2}"; shift;;
        "--yoff"            ) yOffset="${2}"; yOffOrig="${2}"; shift;;
        "--server"          ) SERVER="${2}"; shift;;
        "--api"             ) API_LOCATION="${2}"; shift;;
        "--secret"          ) password="${2}"; shift;;
        "--2fa"             ) totp="${2}"; shift;;
        *                   ) DisplayHelp; exit 1;;
    esac
    shift
done

if [ -n "${API_LOCATION}" ] && [ -n "${SERVER}" ]; then
    moveXOffset; echo "Do not set --server and --api simultaneously."
    moveXOffset; echo "Exiting."
    exit 1
fi

if [ "${versionOnly}" ]; then
    ShowVersion
fi

if [ "${doUpdate}" ]; then
    Update
fi

main
