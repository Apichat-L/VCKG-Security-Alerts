#!/bin/sh
# Mail host: resolve through the lab DNS, create the mailbox account with a dummy message, start Dovecot,
# then run Postfix in the foreground.
#   MAIL_USER / MAIL_PASSWORD   IMAP login and mailbox (<user>@lab.local)
set -eu
USER_NAME="${MAIL_USER:-dave}"
USER_PASS="${MAIL_PASSWORD:-Passw0rd!}"

# Mail -> DNS dependency: every name lookup on this host (MX, lab.local names) goes to the DMZ DNS server.
echo "nameserver ${LAB_DNS:-10.10.10.13}" > /etc/resolv.conf
echo "search lab.local" >> /etc/resolv.conf

if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd -m -s /usr/sbin/nologin "$USER_NAME"
    echo "$USER_NAME:$USER_PASS" | chpasswd
    md="/home/$USER_NAME/Maildir"
    mkdir -p "$md/cur" "$md/new" "$md/tmp"
    cat > "$md/new/1700000000.lab.mail" <<MSG
From: it@lab.local
To: $USER_NAME@lab.local
Subject: VPN and HR portal access (dummy)

Your HR portal account is ready: http://hr.lab.local:8080/hr/  (user $USER_NAME)
MSG
    chown -R "$USER_NAME:$USER_NAME" "/home/$USER_NAME"
fi

# Postfix logs to syslog (rsyslog runs, see common/entrypoint.sh); its chroot copies resolv.conf on start.
dovecot
exec postfix start-fg
