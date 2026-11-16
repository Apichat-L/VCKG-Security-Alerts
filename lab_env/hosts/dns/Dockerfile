# DMZ DNS server (authoritative for lab.local, recursion for the lab). BIND 9.18.19 from Debian 12, pinned to the
# 2024-03-11 build 1:9.18.19-1~deb12u1 (common/debian-snapshot.sh) -> CPE isc:bind (CVE-2023-50387 KeyTrap,
# CVE-2023-50868, CVE-2024-0760, ...). distro package bind9: CVEs come from OSV Debian:12 (asset_kg/osv.py).
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh \
 && /lab/debian-snapshot.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bind9=1:9.18.19-1~deb12u1 bind9-utils=1:9.18.19-1~deb12u1 bind9-dnsutils=1:9.18.19-1~deb12u1 \
 && apt-mark hold bind9 bind9-utils bind9-dnsutils \
 && rm -rf /var/lib/apt/lists/*
COPY hosts/dns/named.conf.options hosts/dns/named.conf.local hosts/dns/db.lab.local /etc/bind/
RUN sed -i 's/\r$//' /etc/bind/named.conf.* /etc/bind/db.lab.local && named-checkconf && named-checkzone lab.local /etc/bind/db.lab.local
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/lab/entrypoint.sh"]
# -f: foreground, logs go to syslog (rsyslog -> /var/log/syslog, read by the Wazuh agent; stock "named" decoder)
CMD ["/usr/sbin/named", "-f", "-u", "bind"]
