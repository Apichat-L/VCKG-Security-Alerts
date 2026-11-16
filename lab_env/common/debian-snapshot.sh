#!/bin/sh
# Point apt at a frozen Debian 12 archive (snapshot.debian.org), so the distro packages a host installs are
# the exact builds listed in lab/services.csv (package_version) instead of whatever bookworm ships today.
#   debian-snapshot.sh [timestamp]     default 20240311T000000Z = the date of the debian:bookworm-20240311 base image
# No security suite is added on purpose: the packages stay at their vulnerable builds.
# Run it before install-wazuh-agent.sh (that script runs apt-get update).
set -eu
STAMP="${1:-20240311T000000Z}"
rm -f /etc/apt/sources.list.d/debian.sources
echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${STAMP} bookworm main" \
    > /etc/apt/sources.list
# snapshot.debian.org is slow and rate-limited: retry and allow long downloads
printf 'Acquire::Retries "5";\nAcquire::http::Timeout "120";\n' > /etc/apt/apt.conf.d/80lab-snapshot
