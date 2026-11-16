#!/bin/sh
# Prepare the Gitea database and the admin account (idempotent), then run Gitea as the git user.
#   GITEA_ADMIN_USER / GITEA_ADMIN_PASSWORD   site administrator
set -eu
G="runuser -u git -- /usr/local/bin/gitea --config /etc/gitea/app.ini --work-path /var/lib/gitea"
$G migrate >/dev/null
$G admin user create --admin --username "${GITEA_ADMIN_USER:-gitadmin}" --password "${GITEA_ADMIN_PASSWORD:-Passw0rd!}" \
    --email "${GITEA_ADMIN_USER:-gitadmin}@lab.local" --must-change-password=false >/dev/null 2>&1 || true
exec $G web
