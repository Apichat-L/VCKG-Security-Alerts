# MGMT bastion (jump host) the administrators use to manage the other zones. OpenSSH 9.2p1 from Debian 12, pinned
# to the 2024-03-11 build 1:9.2p1-2+deb12u2 (common/debian-snapshot.sh), before the fixes for CVE-2024-6387
# (regreSSHion, fixed in deb12u3) and CVE-2025-26465 -> CPE openbsd:openssh; distro package openssh: CVEs come from
# OSV Debian:12 (asset_kg/osv.py). The admin tools reach DMZ / APP / DATA (MGMT -> * in firewall/rules.sh).
# Same start script as the workstations: the user comes from the environment, LAB_URLS are the saved admin URLs.
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh \
 && /lab/debian-snapshot.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server=1:9.2p1-2+deb12u2 openssh-client=1:9.2p1-2+deb12u2 openssh-sftp-server=1:9.2p1-2+deb12u2 \
        sudo postgresql-client mariadb-client smbclient sshpass bind9-dnsutils redis-tools \
 && apt-mark hold openssh-server openssh-client openssh-sftp-server \
 && rm -rf /var/lib/apt/lists/*
COPY hosts/workstation/start.sh /lab/start.sh
RUN sed -i 's/\r$//' /lab/start.sh && chmod +x /lab/start.sh
EXPOSE 22
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/start.sh"]
