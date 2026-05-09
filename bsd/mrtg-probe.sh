#!/bin/sh
# mrtg-probe.sh — read byte counters for one interface from netstat -ibn
# Usage: mrtg-probe.sh <interface>
# Output (4 lines, as required by MRTG external target):
#   line 1: inbound bytes (ifInOctets)
#   line 2: outbound bytes (ifOutOctets)
#   line 3: uptime in hundredths of a second (0 = let MRTG use sysuptime)
#   line 4: interface description label

IFACE="${1:-em0}"

# Prefer the link-layer row (<Link#N>) for most accurate byte counters
LINE=$(netstat -ibn | awk -v iface="$IFACE" '$1 == iface && $3 ~ /^<[Ll]ink/ { print; exit }')
# Fallback: accept the first matching row for this interface
[ -z "$LINE" ] && LINE=$(netstat -ibn | awk -v iface="$IFACE" '$1 == iface { print; exit }')

if [ -z "$LINE" ]; then
    echo "0"
    echo "0"
    echo "0"
    echo "$IFACE"
    exit 0
fi

# netstat -ibn columns on FreeBSD:
#  Name  Mtu   Network  Address  Ipkts  Ierrs  Ibytes  Opkts  Oerrs  Obytes  Coll
#  [0]   [1]   [2]      [3]      [4]    [5]    [6]     [7]    [8]    [9]     [10]
IN=$(echo  "$LINE" | awk '{print $7}')
OUT=$(echo "$LINE" | awk '{print $10}')

echo "${IN:-0}"
echo "${OUT:-0}"
echo "0"
echo "$IFACE"
