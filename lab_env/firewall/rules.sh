#!/bin/sh
# Lab firewall: routes between the zones and only forwards what lab/zone_edges.csv allows.
#   internet -> dmz, dmz -> app, app -> data, office -> data,
#   office -> mgmt, mgmt -> dmz, mgmt -> app, mgmt -> data   (MGMT: bastion and monitoring, never from the internet)
# plus every zone -> sec on the Wazuh agent ports (1514 events, 1515 enrollment).
# Everything else is dropped and logged with the prefix "FW-DROP" (see: docker compose logs firewall
# does not show kernel logs; use `docker compose exec firewall iptables -vnL FORWARD` for counters).
set -eu

iface() {   # interface that holds an address in the given subnet prefix, e.g. "10.10.10."
    ip -o -4 addr show | awk -v p="$1" 'index($4, p) == 1 {print $2; exit}'
}

INET=$(iface 172.30.0.)
DMZ=$(iface 10.10.10.)
APP=$(iface 10.10.20.)
DATA=$(iface 10.10.30.)
OFFICE=$(iface 10.10.40.)
MGMT=$(iface 10.10.50.)
SEC=$(iface 10.10.90.)
for v in INET DMZ APP DATA OFFICE MGMT SEC; do
    eval "[ -n \"\$$v\" ]" || { echo "firewall: no interface for $v"; exit 1; }
done
echo "firewall: internet=$INET dmz=$DMZ app=$APP data=$DATA office=$OFFICE mgmt=$MGMT sec=$SEC"

ip route replace default via 172.30.0.1 dev "$INET"

iptables -F FORWARD
iptables -t nat -F POSTROUTING
iptables -t mangle -F FORWARD
if [ "${IDS_NFQUEUE:-1}" = "1" ]; then
    # Copy every forwarded packet to the IDS (Suricata, queue 0) before the filter table decides.
    # The verdict in mangle only ends the mangle chain, so the rules below still apply;
    # --queue-bypass lets traffic through while Suricata is not running.
    if iptables -t mangle -A FORWARD -j NFQUEUE --queue-num 0 --queue-bypass; then
        echo "firewall: forwarded traffic queued to the IDS (NFQUEUE 0)"
    else
        echo "firewall: NFQUEUE not available in this kernel; run the IDS with IDS_MODE=pcap"
    fi
fi
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

allow() { iptables -A FORWARD -i "$1" -o "$2" -m comment --comment "$3" -j ACCEPT; }
allow "$INET" "$DMZ"  "Internet -> DMZ"
allow "$DMZ"  "$APP"  "DMZ -> APP"
allow "$APP"  "$DATA" "APP -> DATA"
allow "$OFFICE" "$DATA" "Office -> DATA"
allow "$OFFICE" "$MGMT" "Office -> MGMT"
allow "$MGMT" "$DMZ"  "MGMT -> DMZ"
allow "$MGMT" "$APP"  "MGMT -> APP"
allow "$MGMT" "$DATA" "MGMT -> DATA"

for z in "$DMZ" "$APP" "$DATA" "$OFFICE" "$MGMT"; do
    iptables -A FORWARD -i "$z" -o "$SEC" -p tcp -m multiport --dports 1514,1515 \
        -m comment --comment "agent -> wazuh" -j ACCEPT
done
# The Wazuh containers route via Docker's gateway, so replies must come back to the firewall.
iptables -t nat -A POSTROUTING -o "$SEC" -j MASQUERADE

if [ "${FW_ALLOW_EGRESS:-0}" = "1" ]; then   # lab hosts reach the real internet (package updates)
    for z in "$DMZ" "$APP" "$DATA" "$OFFICE" "$MGMT"; do
        allow "$z" "$INET" "egress"
    done
    iptables -t nat -A POSTROUTING -o "$INET" ! -d 172.30.0.0/24 -j MASQUERADE
fi

iptables -A FORWARD -j LOG --log-prefix "FW-DROP " --log-level 4
iptables -A FORWARD -j DROP

iptables -vnL FORWARD
echo "firewall: ready"
exec sleep infinity
