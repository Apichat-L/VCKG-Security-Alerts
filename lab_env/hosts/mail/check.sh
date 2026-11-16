#!/bin/sh
# lab_env/eval health check: SMTP and IMAP answer, and the host can resolve its own mail domain through the lab DNS
# (Mail -> DNS). Exits non-zero if any part fails.
set -eu
postfix status >/dev/null 2>&1
nc -z -w 3 127.0.0.1 25
nc -z -w 3 127.0.0.1 143
dig +short +time=3 +tries=1 MX lab.local | grep -q "mail.lab.local"
