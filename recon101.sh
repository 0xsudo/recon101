#!/bin/sh
#author @0xsudo

# script timer
initTimer="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"

# Display script usage menu and exit
usage() {
        echo
        echo
        figlet R E C O N - 1 0 1
        echo
        echo
        printf "${GREEN}[+] Usage: ${CYAN}$(basename $0) -h/--host ${NOCOLOR}<TARGET-IP/URL> ${CYAN}-t/--type ${NOCOLOR}<SCAN-TYPE>\n"
        printf "${GREEN}[+] Optional: [${CYAN}-d/--dns ${NOCOLOR}<DNS-SERVER>] [${CYAN}-o/--output ${NOCOLOR}<OUTPUT-DIRECTORY>]\n\n"
        printf "${GREEN}[+] Scan Types Available:\n\n${NOCOLOR}"
        printf "${CYAN}\t[+] Host               : ${NOCOLOR}Displays up hosts in the host's network\n"
        printf "${CYAN}\t[+] Port               : ${NOCOLOR}Displays top 1000 common ports\n"
        printf "${CYAN}\t[+] Script             : ${NOCOLOR}Uses result of port scan to run script scan\n"
        printf "${CYAN}\t[+] Allports           : ${NOCOLOR}Runs a combination of all-port scan and script scan on discovered ports ${CYAN}(Initial Enumeration)\n"
        printf "${CYAN}\t[+] CVE                : ${NOCOLOR}Performs a CVE scan on all discovered ports ${CYAN}(Vulnerability Assessment)\n"
        printf "${CYAN}\t[+] Reconnaissance     : ${NOCOLOR}Suggests Reconnaissance commands and automatically runs them if no preference is given ${CYAN}(Further Enumeration)\n"
        printf "${CYAN}\t[+] UDP                : ${NOCOLOR}Requires elevated priviledges to run a UDP scan ${CYAN}(Takes Some Time)\n"
        printf "${CYAN}\t[+] All                : ${NOCOLOR}Makes use of all the available scans ${CYAN}(Combined Scan)\n"
        printf "${NOCOLOR}\n"
        printf "${NOCOLOR}\n"
        exit 1
}

# parsed flags at command prompt
while [ $# -gt 0 ]; do
        pstn="$1"

        case "${pstn}" in
        -h | --host)
                HOST="$2"
                shift
                shift
                ;;
        -t | --type)
                TYPE="$2"
                shift
                shift
                ;;
        -d | --dns)
                DNS="$2"
                shift
                shift
                ;;
        -o | --output)
                OUTDIR="$2"
                shift
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac 
done

# enables assigning one or more digits to a parameter
set -- ${POSITIONAL}

# set output directory to host-based directory name
if [ -z "${OUTDIR}" ]; then
        OUTDIR="${HOST}"
fi

# sets devices to available locally
LOCAL=true

# Defined ANSI color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NOCOLOR='\033[0m'

# define internal field separator
initIFS="${IFS}"

# set DNS mannually or use system DNS
if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
        ALTDNS="--dns-server=${DNSSERVER}"
else
        DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
        ALTDNS="--system-dns"
fi

# set nmappath to default nmap binary
if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk {'print $NF'})"
else
        printf "${RED}\n\t [-] Nmap is not installed\n"
        printf "${RED}\t [-] Please visit https://github.com/nmap/nmap for installation instructions\n"
fi

# set legacy flags as -h & -t if not parsed
if [ -z "${HOST}" ]; then
        HOST="$1"
fi

if [ -z "${TYPE}" ]; then
        TYPE="$2"
fi

# Display initial header and set initial parameters for scan to begin
header() {
        echo
        figlet R E C O N - 1 0 1
        echo
        echo

        # Displays scan type selected to run
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "${CYAN}[+] SELECTED ALL SCAN MODULE RUNNING ON ${NOCOLOR}${HOST}"
        else
                printf "${CYAN}[+] SELECTED ${TYPE} SCAN MODULE RUNNING ON ${NOCOLOR}${HOST}\n"
        fi
        
        #check validity of IP or url supplied and optional dnsserver preference
        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlResolved="$(host -4 -W 1 ${HOST} ${DNSSERVER} 2>/dev/null | grep ${HOST} | head -n 1 | awk {'print $NF'})"
                if [ -n "${urlResolved}" ]; then
                        printf "${CYAN}[+] Target IP ${NOCOLOR}${urlResolved}\n\n"
                else
                        printf "${RED}[+] Cannot resolve provided IP: ${NOCOLOR}${HOST}\n\n"
                fi
        else
                printf "\n"
        fi

        # Set the subnet variables to be utilized
        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnetVar="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
        fi

        # Set pingType variable based on ping
        kernel="$(uname -s)"
        validatePing="$(checkPing "${urlResolved:-$HOST}")"
        pingType="$(echo "${validatePing}" | head -n 1)"

        # Check if host is pingable and if so for enable ping scans
        if expr "${pingType}" : ".*-Pn$" >/dev/null; then
                pingable=false
                printf "${NOCOLOR}\n"
                printf "${RED}[-] Ping undetected\n"
                printf "${RED}[-] Ping scans will be skipped\n"
                printf "${NOCOLOR}\n"
        else
                pingable=true

        fi

        # OS Type Detection
        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                OS="$(checkOS "${ttl}")"
                printf "${NOCOLOR}\n"
                printf "${GREEN}[+] Operating system on target host is likely ${OS}\n"
        fi
        echo
        echo
}

# Dispaly the nmap progress bar
# first argument $scanType, the second $2 is $percentage, the third $3 is $elapsed, and the fourth $4 is $reminder
progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        full="$(printf "%-$((width == 100 ? ${2} : (${2} / 2)))s" "#" | tr ' ' '#')"
        null="$(printf "%-$((width - (width == 100 ? ${2} : (${2} / 2))))s" " ")"
        printf "In progress: ${TYPE} scan (${3} elapsed - ${4} reminder)\n"
        printf "[${full}>${null}] ${2}%% done\n"
        printf "\e[2A"
}

# uses nmap flag --stats-every to calculate progress
# first argument $1 is run nmap command, $2 is $refreshIn of the progress bar
scanBar() {
        outFile="$(echo $1 | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpoutFile="${outFile}.tmp"
        refreshIn="${2:-1}"

        # execute nmap command
        if [ ! -e "${outFile}" ]; then
                $1 --stats-every "${refreshIn}s" >"${tmpoutFile}" 2>&1 &
        fi

        # continously check nmap stats while calling progressBar() every $refreshIn
        while { [ ! -e "${outFile}" ] || ! grep -q "Nmap done at" "${outFile}"; } && { [ ! -e "${tmpoutFile}" ] || ! grep -i -q "quitting" "${tmpoutFile}"; }; do
                scanType="$(tail -n 2 "${tmpoutFile}" 2>/dev/null | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percentage="$(tail -n 2 "${tmpoutFile}" 2>/dev/null | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpoutFile}" 2>/dev/null | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                reminder="$(tail -n 2 "${tmpoutFile}" 2>/dev/null | sed -ne '/reminder/{s/.* (\(.*\) reminder.*/\1/p}')"
                progressBar "${scanType:-No}" "${percentage:-0}" "${elapsed:-0:00:00}" "${reminder:-0:00:00}"
                sleep "${refreshIn}"
        done

        LINECLEAR="\033[0K\r"
        printf "${LINECLEAR}\n${LINECLEAR}\n"

        # dispaly final output and remove unnecessary nmap details
        if [ ! -e "${outFile}" ]; then
                cat "${tmpoutFile}"
        else
                sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outFile}" | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
        fi

        rm -f "${tmpoutFile}"
}

# keeps discovered ports consistent throught the script
# first argument $1 is $HOST
allocatePorts() {
        # Set allPort variable based on both AllPorts and Port or AllPorts scans only
        if [ -f "recon101/AllPorts_$1.nmap" ]; then
                if [ ! -f "recon101/TopPorts_$1.nmap" ]; then
                        allPort="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "recon101/AllPorts_$1.nmap" | sed 's/.$//')"
                else
                        allPort="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "recon101/TopPorts_$1.nmap" "recon101/AllPorts_$1.nmap" | sed 's/.$//')"
                fi
        fi

        # Set top 1000 common Ports based on Port scan
        if [ -f "recon101/TopPorts_$1.nmap" ]; then
                topPort="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "recon101/TopPorts_$1.nmap" | sed 's/.$//')"
        fi

        # Set UDPPort variable according on UDP scan
        if [ -f "recon101/UDP_$1.nmap" ]; then
                UDPPort="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "recon101/UDP_$1.nmap" | sed 's/.$//')"
                if [ "${UDPPort}" = "Al" ]; then
                        UDPPort=""
                fi
        fi
}

# add the extra ports found in AllPorts scan
findExtraPorts() {
        #new allports are allocated new variable extraPorts

        extraPorts="$(echo ",${allPort}," | sed 's/,\('"$(echo "${topPort}" | sed 's/,/,\\|/g')"',\)\+/,/g; s/^,\|,$//g')"
}

# test whether the host is pingable, and return pingType and ttl
# first argument $1 is $HOST
checkPing() {
        # disables ping scan with -Pn, if a ping response is not returned in a second
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -${TW} 1 "$1" 2>/dev/null | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "${NMAPPATH} -Pn"
        else
                echo "${NMAPPATH}"
                if expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

# determine type of OS based ttl results
# first argument $1 is $ttl
checkOS() {
        case "$1" in
        6[34]) echo "Linux" ;;
        12[78]) echo "Windows" ;;
        25[456]) echo "Cisco/Oracle/OpenBSD" ;;
        *) echo "Unknown!" ;;
        esac
}

# scanning for live hosts in a network using nmap
hostScan() {
        printf "${GREEN}\t [+] Initiating Host Scan\n"
        printf "${NOCOLOR}\n"

        initHOST="${HOST}"
        HOST="${urlResolved:-$HOST}"
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi

        if $LOCAL; then
                # use nmap to discover live hosts
                scanBar "${pingType} --max-scan-delay 20 -n -sn -T4 --max-retries 1 -oN recon101/Host_${HOST}.nmap ${subnetVar}/24"
                printf "${CYAN}\t [+] Discovered the following live hosts: ${NOCOLOR}\n\n"
                cat recon101/Host_${HOST}.nmap | grep -v '#' | grep "$(echo $subnetVar | sed 's/..$//')" | awk {'print $5'}
        elif $pingable; then
                # use ping to discover live hosts
                echo >"recon101/Host_${HOST}.nmap"
                for ip in $(seq 0 254); do
                        (ping -c 1 -${TW} 1 "$(echo $subnetVar | sed 's/..$//').$ip" 2>/dev/null | grep 'stat' -A1 | xargs | grep -v ', 0.*received' | awk {'print $2'} >>"recon101/Host_${HOST}.nmap") &
                done
                wait
                sed -i '/^$/d' "recon101/Host_${HOST}.nmap"
                sort -t . -k 3,3n -k 4,4n "recon101/Host_${HOST}.nmap"
        else
                printf "${RED}\t [-] No ping returned, probably no hosts present!\n${NOCOLOR}"
        fi

        HOST="${initHOST}"

        echo
        echo
}

# scanning for top 1000 ports in a network using nmap
portScan() {
        printf "${GREEN}\t [+] Initiating Port Scan\n"
        printf "${NOCOLOR}\n"

        if $LOCAL; then
                scanBar "${pingType} --max-scan-delay 20 --open -T4 --max-retries 1 -oN recon101/TopPorts_${HOST}.nmap ${HOST} ${ALTDNS}"
                allocatePorts "${HOST}"
        else
                printf "${RED}\t [-] No open ports on network!\n${NOCOLOR}"
        fi

        echo
        echo
}

# performing version and default script scan on discovered top ports
nmapScriptScan() {
        printf "${GREEN}\t [+] Initiating Script Scan on Discovered Ports\n"
        printf "${NOCOLOR}\n"

        if $LOCAL; then
                if [ -n "${topPort}" ]; then
                        scanBar "${pingType} --open -sCV -p${topPort} -oN recon101/Script_${HOST}.nmap ${HOST} ${ALTDNS}" 2
                else
                        printf "${RED}\t [-] No ports were discovered. Skipping Script Scan!\n"
                fi

                # Modify OS according to new nmap scan result
                if [ -f "recon101/Script_${HOST}.nmap" ] && grep -q "Service Info: OS:" "recon101/Script_${HOST}.nmap"; then
                        discoveredOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "recon101/Script_${HOST}.nmap")"
                        if [ "${OS}" != "${discoveredOS}" ]; then
                                OS="${discoveredOS}"
                                printf "${NOCOLOR}\n"
                                printf "${NOCOLOR}\n"
                                printf "${GREEN}\t [+] OS Detection modified to: ${OS}\n"
                                printf "${NOCOLOR}\n"
                        fi
                fi
        else
                printf "${RED}\t [-] Script scan unable to initiate\n${NOCOLOR}"
        fi

        echo
        echo
}

# performing all ports, version and default script scan using nmap
allPortsScan() {
        printf "${GREEN}\t [+] Initiating All Port Scan and Script Scan\n"
        printf "${NOCOLOR}\n"

        if $LOCAL; then
                scanBar "${pingType} -p- -v --open --max-retries 1 --max-rate 600 --max-scan-delay 20 -T4 -oN recon101/AllPorts_${HOST}.nmap ${HOST} ${ALTDNS}" 3
                allocatePorts "${HOST}"

                # performing version and default script scan on all ports if Script scan has not been run
                if [ -z "${topPort}" ]; then
                        echo
                        echo
                        printf "${GREEN}\t [+] Performing all ports script scan\n"
                        printf "${NOCOLOR}\n"
                        scanBar "${pingType} -sCV --open -p${allPort} -oN recon101/AllPorts_Extra_${HOST}.nmap ${HOST} ${ALTDNS}" 2
                        allocatePorts "${HOST}"
                # performing version and default nmap script scan for any extra ports found

                else
                        findExtraPorts
                        if [ -n "${extraPorts}" ]; then
                                echo
                                printf "${CYAN}\t [+] Performing a script scan on discovered extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')\n"
                                printf "${NOCOLOR}\n"
                                scanBar "${pingType} -sCV --open -p${extraPorts} -oN recon101/AllPorts_Extra_${HOST}.nmap ${HOST} ${ALTDNS}" 2
                                allocatePorts "${HOST}"
                        else
                                echo
                                allPort=""
                                printf "${CYAN}\t [+] No extra ports found!\n"
                                printf "${NOCOLOR}\n"
                        fi
                                
                fi
        else
                printf "${RED}\t [-] AllPorts Scan unable to initiate!\n${NOCOLOR}"
        fi

        echo
        echo
}

# performing vulnerability detection scan using nmap
CVEScan() {
        printf "${GREEN}\t [+] Initiating CVE Scan\n"
        printf "${NOCOLOR}\n"

        if $LOCAL; then
                # select either to scan top or all ports
                if [ -z "${topPort}" ]; then
                        portType="all"
                        targetPorts="${allPort}"
                else
                        portType="top"
                        targetPorts="${topPort}"
                fi

                # check if the vulners script is available then run it with nmap
                if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                        printf "${CYAN}\t [+] Performing CVE scan on ${portType} ports\n"
                        printf "${NOCOLOR}\n"
                        scanBar "${pingType} --open -sV --script vulners --script-args mincvss=7.0 -p${targetPorts} -oN recon101/CVE_${HOST}.nmap ${HOST} ${ALTDNS}" 3
                        echo
                        
                else
                        printf "${RED}\t [-] Vulners.nse is not installed\n"
                        printf "${RED}\t [-] Please visit https://github.com/vulnersCom/nmap-vulners for installation instructions\n"
                        printf "${NOCOLOR}\n"
                        printf "${RED}\t [-] CVE scan will be skipped!\n"
                        printf "${NOCOLOR}\n"
                        echo
                fi

                # performing vulnerability analysis using nmap
                echo
                printf "${CYAN}\t [+] Running CVE scan on all ports\n"
                printf "${CYAN}\t [+] This may takes time depending on discovered services\n"
                printf "${NOCOLOR}\n"
                scanBar "${pingType}  --open -sV --script vuln --script-args mincvss=7.0 -p${targetPorts} -oN recon101/VULNS_${HOST}.nmap ${HOST} ${ALTDNS}" 3
        else
                printf "${RED}\t [-] CVE Scan unable to initiate!\n${NOCOLOR}"
        fi

        echo
        echo
}

# run reconnaissanceRecommend(), ask user for tools to run, then reconnaissance()
reconnaissance() {

        #internal field separator as next line
        IFS="
"

        # run reconnaissanceRecommend()
        reconnaissanceRecommend "${HOST}" | tee "recon101/Reconnaissance_${HOST}.nmap"
        allTools="$(grep "${HOST}" "recon101/Reconnaissance_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

        # detect missing reconnaissance tools
        for tool in ${allTools}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTool="$(echo ${missingTool} ${tool} | awk '{$1=$1};1')"
                fi
        done

        # while executing exclude missing reconnaisance tools, and show guide for installing them
        if [ -n "${missingTool}" ]; then
                printf "${RED}\t [-] Missing tools:${NOCOLOR}${missingTool}\n"
                printf "\n${RED}\t [-] Run the following command to install:\n"
                printf "${GREEN}\t [+] sudo apt install ${missingTool} -y\n"
                printf "${NOCOLOR}\n\n"

                reconTool="$(echo "${allTools}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTool}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                reconTool="$(echo "${allTools}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
        fi


        # prompt user for which reconnaissance tool to run, if none is given it defaults to all
        waitTime=10
        count=0
        if [ -n "${reconTool}" ]; then
                while [ "${selectedRecon}" != "!" ]; do
                        printf "${CYAN}\n"
                        printf "${CYAN}\t [+] Specify recconnaissance to run:${BLUE}\nAll (Default), ${reconTool}, ${CYAN}Skip\n\n"
                        while [ ${count} -lt ${waitTime} ]; do
                                remainder=$((waitTime - count))
                                LINEREFRESH="\033[2K\r"
                                printf "${CYAN}${LINEREFRESH}\t [+] Running Default in (${remainder})s: "

                                # POSIX read for 1 second incrimentally till waitTime is over
                                selectedRecon="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1))
                                [ -n "${selectedRecon}" ] && break
                        done
                        if expr "${selectedRecon}" : '^\([Aa]ll\)$' >/dev/null || [ -z "${selectedRecon}" ]; then
                                initReconnaissanse "${HOST}" "All"
                                selectedRecon="!"
                        elif expr " ${reconTool}," : ".* ${selectedRecon}," >/dev/null; then
                                initReconnaissanse "${HOST}" "${selectedRecon}"
                                selectedRecon="!"
                        elif [ "${selectedRecon}" = "Skip" ] || [ "${selectedRecon}" = "!" ]; then
                                selectedRecon="!"
                                echo
                                echo
                        else
                                printf "${NOCOLOR}\n"
                                printf "${RED}\t [-] Incorrect type selected!\n"
                                printf "${NOCOLOR}\n"
                        fi
                done
        else
                printf "${RED}\t [-] Reconnaissance recommendations not found\n"
                printf "${NOCOLOR}\n"
                echo
                echo
        fi

        IFS="${initIFS}"
}

# run reconnaissance based on selected option
initReconnaissanse() {
        echo
        echo
        printf "${GREEN}\t [+] Initiating reconnaissance with selected types\n"
        printf "${NOCOLOR}\n"

        IFS="
"

        if [ "$2" = "All" ]; then
                reconOption="$(grep "${HOST}" "recon101/Reconnaissance_${HOST}.nmap")"
        else
                reconOption="$(grep "${HOST}" "recon101/Reconnaissance_${HOST}.nmap" | grep "$2")"
        fi

        mkdir -p Reconnaissance/

        # run all selected scans
        for line in ${reconOption}; do
                scanRunning="$(echo "${line}" | cut -d ' ' -f 1)"
                outFile="$(echo "${line}" | awk -F "Reconnaissance/" '{print $2}')"
                if [ -n "${outFile}" ] && [ ! -f Reconnaissance/"${outFile}" ]; then
                        printf "${NOCOLOR}\n"
                        printf "${GREEN}\t [+] Initiating ${scanRunning} scan\n"
                        printf "${NOCOLOR}\n"
                        eval "${line}"
                        printf "${NOCOLOR}\n"
                        printf "${GREEN}\t [+] Completed ${scanRunning} scan\n"
                        printf "${NOCOLOR}\n"
                        echo
                        echo
                fi
        done

        IFS="${initIFS}"

        echo
        echo
        echo
}

# recommend options for reconnaissance based on found ports
reconnaissanceRecommend() {
        printf "${GREEN}\t [+] Initiating reconnaissance recommend\n"
        printf "${NOCOLOR}\n"

        IFS="
"

        # variables $port and $file setting
        if [ -f "recon101/AllPorts_Extra_${HOST}.nmap" ]; then
                targetPorts="${allPort}"
                file="$(cat "recon101/Script_${HOST}.nmap" "recon101/AllPorts_Extra_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
        elif [ -f "recon101/Script_${HOST}.nmap" ]; then
                targetPorts="${topPort}"
                file="$(grep "open" "recon101/Script_${HOST}.nmap" | grep -v "#")"

        fi

        # port 25 SMTP reconnaissance
        if echo "${file}" | grep -q "25/tcp"; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] SMTP reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "smtp-user-enum -t \"${HOST}\" -U /usr/share/wordlists/metasploit/unix_users.txt | tee \"Reconnaissance/smtp_user_enum_${HOST}.txt\""
                echo
        fi

        # port 53 DNS reconnaissance
        if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] DNS reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"Reconnaissance/dig_${HOST}.txt\""
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"Reconnaissance/hostname_${HOST}.txt\""
                echo "dnsrecon -n \"${DNSSERVER}\" -r 127.0.0.0/24 | tee \"Reconnaissance/dnsrecon-local_${HOST}.txt\""
                echo "dnsrecon -n \"${DNSSERVER}\" -r \"${subnetVar}/24\" | tee \"Reconnaissance/dnsrecon_${HOST}.txt\""
                echo
        fi

        # ports 139 and 445 SMB Reconnaissance
        if echo "${file}" | grep -q "139/tcp" && [ "${OS}" = "Linux" ]; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] SMB port 139 reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "enum4linux -a \"${HOST}\" | tee \"Reconnaissance/enum4linux_${HOST}.txt\""
                echo
        # test with port 445
        elif echo "${file}" | grep -q "445/tcp"; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] SMB port 445 reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"Reconnaissance/smbclient_${HOST}.txt\""
                echo "smbmap -H \"${HOST}\" | tee \"Reconnaissance/smbmap_${HOST}.txt\""
                if [ "${OS}" = "Linux" ]; then
                        echo "enum4linux -a \"${HOST}\" | tee \"Reconnaissance/enum4linux_${HOST}.txt\""
                elif [ "${OS}" = "Windows" ]; then
                        echo "nmap --script vuln -oN \"Reconnaissance/SMB_vulns_${HOST}.txt\" -Pn -p445 \"${HOST}\""
                fi
                echo
        fi

        # http based Web reconnaissance
        if echo "${file}" | grep -i -q http; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] Web Servers reconnaissance running\n"
                printf "${NOCOLOR}\n"

                # url HTTP reconnaissance
                for line in ${file}; do
                        if echo "${line}" | grep -i -q http; then
                                port="$(echo "${line}" | cut -d "/" -f 1)"
                                if echo "${line}" | grep -q ssl/http; then
                                        httpType='https://'
                                        echo "nikto -ssl -host \"${httpType}${HOST}:${port}\" | tee \"Reconnaissance/nikto_${HOST}_${port}.txt\""
                                        echo "sslscan \"${HOST}\" | tee \"Reconnaissance/sslscan_${HOST}_${port}.txt\""
                                else
                                        httpType='http://'
                                        echo "nikto -host \"${httpType}${HOST}:${port}\" | tee \"Reconnaissance/nikto_${HOST}_${port}.txt\""
                                fi
                                # the wordlist or the extensions can be changed
                                if type gobuster >/dev/null 2>&1; then
                                        acceptExtension="$(echo 'index' >./index && gobuster dir -u "${httpType}${HOST}:${port}" -w ./index -s '200,302' -qnkx '.html,.asp,.aspx,.jsp,.php' -t 30 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                        echo "gobuster dir -u \"${httpType}${HOST}:${port}\" -w /usr/share/wordlists/dirb/common.txt -t 30 -ekx '${acceptExtension}' -o \"Reconnaissance/gobuster_${HOST}_${port}.txt\"" 
                                else
                                        acceptExtension="$(echo 'index' >./index && ffuf -u "${httpType}${HOST}:${port}/FUZZ" -e '.jsp,.php,.asp,.aspx,.html' -s -w ./index:FUZZ -mc '200,302' 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                        echo "ffuf -ic -u \"${httpType}${HOST}:${port}/FUZZ\" -w /usr/share/wordlists/dirb/common.txt -e '${acceptExtension}' | tee \"Reconnaissance/ffuf_${HOST}_${port}.txt\""
                                fi
                                echo
                        fi
                done
                # content management system reconnaissance
                if [ -f "recon101/Script_${HOST}.nmap" ]; then
                        contmngsys="$(grep http-generator "recon101/Script_${HOST}.nmap" | cut -d " " -f 2)"
                        if [ -n "${contmngsys}" ]; then
                                for line in ${contmngsys}; do
                                        port="$(sed -n 'H;x;s/\/.*'"${line}"'.*//p' "recon101/Script_${HOST}.nmap")"

                                        # ! case returns 1 when a match is found
                                        if ! case "${contmngsys}" in Drupal | WordPress | Joomla) false ;; esac then
                                                printf "${NOCOLOR}\n"
                                                printf "${CYAN}\t [+] CMS reconnaissance running\n"
                                                printf "${NOCOLOR}\n"
                                        fi
                                        case "${contmngsys}" in
                                        Drupal) echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"Reconnaissance/droopescan_${HOST}_${port}.txt\"" ;;
                                        WordPress) echo "wpscan --url \"${HOST}:${port}\" --enumerate p | tee \"Reconnaissance/wpscan_${HOST}_${port}.txt\"" ;;
                                        Joomla!) echo "joomscan --url \"${HOST}:${port}\" | tee \"Reconnaissance/joomscan_${HOST}_${port}.txt\"" ;;
                                        esac
                                done
                        fi
                fi
        fi

        # port 161 SNMP Reconnaissance
        if [ -f "recon101/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "recon101/UDP_Extra_${HOST}.nmap"; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] SNMP reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "snmpwalk -Os -v1 \"${HOST}\" -c public | tee \"Reconnaissance/snmpwalk_${HOST}.txt\""
                echo "snmp-check \"${HOST}\" -c public | tee \"Reconnaissance/snmpcheck_${HOST}.txt\""
                echo
        fi

        # port 389 LDAP Reconnaissance
        if echo "${file}" | grep -q "389/tcp"; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] LDAP reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "nmap --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"Reconnaissance/ldapsearch_${HOST}.txt\" -Pn -p 389 | cut -d \\" \\" -f2)\"' \"${HOST}\" -oN \"Reconnaissance/nmap_ldap_${HOST}.txt\""
                echo "ldapsearch -x -s base -h \"${HOST}\"| tee \"Reconnaissance/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -b \"\$(grep rootDomainNamingContext \"Reconnaissance/ldapsearch_${HOST}.txt\" -h \"${HOST}\" | cut -d ' ' -f2)\" | tee \"Reconnaissance/ldapsearch_DC_${HOST}.txt\""
                echo
        fi

        # port 1521 oracle database reconnaissance
        if echo "${file}" | grep -q "1521/tcp"; then
                printf "${NOCOLOR}\n"
                printf "${CYAN}\t [+] Oracle reconnaissance running\n"
                printf "${NOCOLOR}\n"
                echo "odat passwordguesser -d XE -p 1521 -s \"${HOST}\" --accounts-file accounts/accounts-multiple.txt"
                echo "odat sidguesser -p 1521 -s \"${HOST}\""
                echo
        fi

        IFS="${initIFS}"

        echo
        echo
        echo
}

# performing nmap UDP scan
UDPScan() {
        printf "${GREEN}\t [+] Initiating UDP Scan\n\n"
        printf "${RED}\t [-] Kindly note that this scan takes time, please leave running in the background!\n"
        printf "${NOCOLOR}\n"

        if $LOCAL; then
                # checking if root priviliges have been enabled
                if [ "${USER}" != 'root' ]; then
                        echo "UDP scan requires to be run with sudo"
                        sudo -v
                        echo
                fi

                scanBar "sudo ${pingType} -sU --max-retries 1 --open -oN recon101/UDP_${HOST}.nmap ${HOST} ${ALTDNS}" 3
                allocatePorts "${HOST}"

                # performing nmap version and default script scan on discovered UDP ports
                if [ -n "${UDPPort}" ]; then
                        echo
                        echo
                        printf "${CYAN}\t [+] Performing a script scan on UDP ports: $(echo "${UDPPort}" | sed 's/,/, /g')\n"
                        printf "${NOCOLOR}\n"
                        if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                                sudo -v
                                scanBar "sudo ${pingType} -p${UDPPort} --open -sCVU --script vulners --script-args mincvss=7.0 -oN recon101/UDP_Extra_${HOST}.nmap ${HOST} ${ALTDNS}" 2
                        else
                                sudo -v
                                scanBar "sudo ${pingType} -sCVU -p${UDPPort} --open -oN recon101/UDP_Extra_${HOST}.nmap ${HOST} ${ALTDNS}" 2
                        fi
                else
                        echo
                        echo
                        printf "${CYAN}\t [+] No open UDP ports!\n"
                        printf "${NOCOLOR}\n"
                fi
        else
                printf "${RED}\t [-] UDP Scan unable to initiate!\n${NOCOLOR}"
        fi

        echo
        echo
}

# display time taken by scan on footer
footer() {

        printf "${GREEN}\t [+] ALL SCANS COMPLETED!\n"
        printf "${NOCOLOR}\n\n"

        endTimer="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        totalSeconds=$((endTimer - initTimer))

        if [ ${totalSeconds} -gt 3600 ]; then
                hours=$((totalSeconds / 3600))
                minutes=$(((totalSeconds % 3600) / 60))
                seconds=$(((totalSeconds % 3600) % 60))
                printf "${CYAN}\t [+] Scan took ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
        elif [ ${totalSeconds} -gt 60 ]; then
                minutes=$(((totalSeconds % 3600) / 60))
                seconds=$(((totalSeconds % 3600) % 60))
                printf "${CYAN}\t [+] Scan took ${minutes} minute(s) and ${seconds} second(s)\n"
        else
                printf "${CYAN}\t [+] Scan took ${totalSeconds} seconds\n"
        fi
        printf "${NOCOLOR}\n"
}

# run script based on specified flags
main() {
        allocatePorts "${HOST}"

        header

        case "${TYPE}" in
        [Hh]ost) hostScan "${HOST}" ;;
        [Pp]ort) portScan "${HOST}" ;;
        [Ss]cript)
                [ ! -f "recon101/TopPorts_${HOST}.nmap" ] && portScan "${HOST}"
                nmapScriptScan "${HOST}"
                ;;
        [Aa]llports) allPortsScan "${HOST}" ;;
        [Cc]ve)
                [ ! -f "recon101/TopPorts_${HOST}.nmap" ] && portScan "${HOST}"
                CVEScan "${HOST}"
                ;;
        [Rr]econnaissance)
                [ ! -f "recon101/TopPorts_${HOST}.nmap" ] && portScan "${HOST}"
                [ ! -f "recon101/Script_${HOST}.nmap" ] && nmapScriptScan "${HOST}"
                reconnaissance "${HOST}"
                ;;
        [Uu]dp) UDPScan "${HOST}" ;;
        [Aa]ll)
                hostScan "${HOST}"
                portScan "${HOST}"
                nmapScriptScan "${HOST}"
                allPortsScan "${HOST}"
                CVEScan "${HOST}"
                reconnaissance "${HOST}"
                UDPScan "${HOST}"
                ;;
        esac

        footer
}

# check for host and type parameters
if [ -z "${HOST}" ] || [ -z "${TYPE}" ]; then

        usage
fi

# check if host parameter is a valid URL or IP
if ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null &&  ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
        printf "${RED}\n"
        printf "${RED}\t [-] Enter a valid URL or IP!\n"

        usage
fi

# check validity of selected scan type and run it
if ! case "${TYPE}" in [Hh]ost | [Pp]ort | [Ss]cript | [Aa]llports | CVE | cve | [Rr]econnaissance | UDP | udp | [Aa]ll) false ;; esac then
        mkdir -p "${OUTDIR}" && cd "${OUTDIR}" && mkdir -p recon101/ || usage
        main | tee "recon101_${HOST}_${TYPE}.txt"
else
        printf "${RED}\t [-] Select a valid scan type!\n"

        usage
fi

exit 0