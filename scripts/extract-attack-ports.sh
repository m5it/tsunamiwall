#!/bin/sh

# Extract unique attacker source ports from iptables/dmesg drop logs.
#
# Usage:
#   sudo dmesg | ./extract-attack-ports.sh
#   sudo dmesg | ./extract-attack-ports.sh --src-ip    # unique attacker IPs
#   sudo dmesg | ./extract-attack-ports.sh --dst-port  # unique destination ports probed
#
# Works with these common log prefixes (case-insensitive):
#   IPTABLES-DROP:  TSUNAMIWALL-DROP:  iptables-dropped:  ip6tables-dropped:

set -eu

FIELD="SPT"
while [ $# -gt 0 ]; do
    case "$1" in
        --src-ip|--ip|--src)
            FIELD="SRC"
            shift
            ;;
        --dst-port|--dpt|--target-port)
            FIELD="DPT"
            shift
            ;;
        --src-port|--spt|--port)
            FIELD="SPT"
            shift
            ;;
        -h|--help)
            echo "Usage: sudo dmesg | $0 [--src-port|--src-ip|--dst-port]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Case-insensitive match for iptables/ip6tables/TsunamiWall drop prefixes.
# Extract the requested FIELD=value token, drop the field name, dedupe and sort.
grep -iE '(iptables|ip6tables).*(drop|dropped):|tsunamiwall.*drop:' | \
grep -oE "${FIELD}=[^[:space:]]+" | \
cut -d'=' -f2 | \
if [ "${FIELD}" = "SRC" ] || [ "${FIELD}" = "DST" ]; then
    # IPv4 addresses sort numerically by octet; IPv6 addresses fall back to lexicographic.
    sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | uniq
else
    sort -n | uniq
fi
