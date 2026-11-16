# DMZ mail server. Postfix 3.7.10 (SMTP 25) + Dovecot 2.3.19.1 (IMAP 143) from Debian 12, pinned to the 2024-03-11
# builds (common/debian-snapshot.sh) -> CPE postfix:postfix, dovecot:dovecot (CVE-2024-23184, CVE-2024-23185, ...).
# Both are distro packages: CVEs come from OSV Debian:12 (asset_kg/osv.py).
# Mail -> DNS dependency: the host resolves through the lab DNS (10.10.10.13), set by start.sh.
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh \
 && /lab/debian-snapshot.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections \
 && echo "postfix postfix/mailname string mail.lab.local" | debconf-set-selections \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        postfix=3.7.10-0+deb12u1 dovecot-core=1:2.3.19.1+dfsg1-2.1 dovecot-imapd=1:2.3.19.1+dfsg1-2.1 \
        bind9-dnsutils netcat-openbsd \
 && apt-mark hold postfix dovecot-core dovecot-imapd \
 && rm -rf /var/lib/apt/lists/*
# Postfix: accept mail for lab.local, relay for the lab subnets (an open-ish relay inside the lab), Maildir delivery.
RUN postconf -e "myhostname = mail.lab.local" "mydomain = lab.local" "myorigin = lab.local" \
        "mydestination = \$myhostname, lab.local, localhost" "inet_interfaces = all" "inet_protocols = ipv4" \
        "mynetworks = 127.0.0.0/8 10.10.0.0/16" "home_mailbox = Maildir/" "smtpd_banner = \$myhostname ESMTP"
COPY hosts/mail/dovecot-lab.conf /etc/dovecot/conf.d/99-lab.conf
COPY hosts/mail/start.sh hosts/mail/check.sh /lab/
RUN sed -i 's/\r$//' /lab/start.sh /lab/check.sh /etc/dovecot/conf.d/99-lab.conf && chmod +x /lab/start.sh /lab/check.sh
EXPOSE 25 143
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/start.sh"]
