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
LINE=$(/usr/bin/netstat -ibn | awk -v iface="$IFACE" '$1 == iface && $3 ~ /^<[Ll]ink/ { print; exit }')
# Fallback: accept the first matching row for this interface
[ -z "$LINE" ] && LINE=$(/usr/bin/netstat -ibn | awk -v iface="$IFACE" '$1 == iface { print; exit }')

if [ -z "$LINE" ]; then
    echo "0"
    echo "0"
    echo "0"
    echo "$IFACE"
    exit 0
fi

# FreeBSD 12+ added Idrop column, shifting Ibytes and Obytes by 1:
#  Old (≤11): Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll  (11 fields)
#  New (12+): Name Mtu Network Address Ipkts Ierrs Idrop  Ibytes Opkts Oerrs Obytes Coll (12 fields)
FIELD_COUNT=$(echo "$LINE" | awk '{print NF}')
if [ "$FIELD_COUNT" -ge 12 ]; then
    IN=$(echo  "$LINE" | awk '{print $8}')
    OUT=$(echo "$LINE" | awk '{print $11}')
else
    IN=$(echo  "$LINE" | awk '{print $7}')
    OUT=$(echo "$LINE" | awk '{print $10}')
fi

echo "${IN:-0}"
echo "${OUT:-0}"
echo "0"
echo "$IFACE"
