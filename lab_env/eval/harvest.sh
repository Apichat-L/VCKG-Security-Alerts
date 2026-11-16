#!/bin/bash
# Usable-reach probe (ground truth for blast-radius compromise mode, `python -m eval_kg measure-usable`).
#
# Answers: if this host were compromised, which other lab hosts could an intruder actually use, with what is
# already stored on it? It is NOT told where anything is: it searches generically, the way post-compromise
# enumeration does, then tries a harmless authenticated access with what it found:
#   - targets: http(s) URLs and ip:port pairs of lab hosts in the environment and in config-like files
#   - credentials: the libpq environment (PGHOST/PGUSER/PGPASSWORD), Samba credential files (username=/password=),
#     JDBC data sources (jdbc:mariadb|mysql://ip:port/db with username="..." password="..." in the same file)
#   - access: HTTP GET (2xx/3xx), `psql -c 'select 1'`, `smbclient ... -c ls`, `mariadb -e 'select 1'`,
#     Redis PING on redis://ip:port URLs (no password needed when Redis has none)
# Usage (stdin script): bash -s -- "<space-separated lab asset IPs>"
# Output, one line per attempt:  <ip> <protocol> ok|fail <evidence>
set -u
ASSET_IPS=" $* "
SELF_IPS=" $(ip -o -4 addr show 2>/dev/null | awk '{split($4, a, "/"); printf "%s ", a[1]}') "
is_target() { case "$ASSET_IPS" in *" $1 "*) case "$SELF_IPS" in *" $1 "*) return 1 ;; esac; return 0 ;; esac; return 1; }

T=$(mktemp -d)
env > "$T/env"
find /etc /app /home /root /lab /usr/local/apache2/conf /usr/local/apache2/htdocs /var/jenkins_home/jobs \
     /usr/local/tomcat/conf /usr/local/tomcat/webapps \
     -xdev -type f -size -200k 2>/dev/null \
  | grep -vE '^/etc/(ssl|ca-certificates|alternatives)|/ossec/' > "$T/files"
{ cat "$T/env"; xargs -r -d '\n' cat -- < "$T/files" 2>/dev/null; } > "$T/text"

# --- HTTP: full URLs and bare ip:port pairs of lab hosts
grep -aohE 'https?://10\.10\.[0-9]+\.[0-9]+(:[0-9]+)?(/[^ "'"'"'<>;]*)?' "$T/text" | sort -u > "$T/urls"
grep -aohE '\b10\.10\.[0-9]+\.[0-9]+:[0-9]+\b' "$T/text" | sort -u | while read -r hp; do
    case "${hp##*:}" in 5432|445|139|22|25|53|143|3306|6379) ;; *) echo "http://$hp/" ;; esac
done >> "$T/urls"
sort -u "$T/urls" | while read -r url; do
    ip=$(echo "$url" | sed -E 's|https?://([0-9.]+).*|\1|')
    is_target "$ip" || continue
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$url" 2>/dev/null)
    case "$code" in 2*|3*) echo "$ip http ok $url" ;; *) echo "$ip http fail $url ($code)" ;; esac
done

# --- PostgreSQL with the libpq environment of this host
if command -v psql >/dev/null 2>&1 && [ -n "${PGHOST:-}" ] && is_target "$PGHOST"; then
    if psql -X -tA -c 'select 1' >/dev/null 2>&1; then echo "$PGHOST postgres ok PGHOST/PGPASSWORD"
    else echo "$PGHOST postgres fail PGHOST/PGPASSWORD"; fi
fi

# --- SMB shares named anywhere, with each credentials file found (and as guest)
grep -aohE '//10\.10\.[0-9]+\.[0-9]+/[A-Za-z0-9_$.-]+' "$T/text" | sort -u > "$T/shares"
xargs -r -d '\n' grep -alE '^username=' < "$T/files" 2>/dev/null \
  | xargs -r -d '\n' grep -alE '^password=' > "$T/creds" 2>/dev/null
if command -v smbclient >/dev/null 2>&1; then
    while read -r share; do
        ip=$(echo "$share" | cut -d/ -f3)
        is_target "$ip" || continue
        ok=""
        while read -r c; do
            smbclient "$share" -A "$c" -c ls >/dev/null 2>&1 && { ok="$c"; break; }
        done < "$T/creds"
        [ -z "$ok" ] && smbclient "$share" -N -c ls >/dev/null 2>&1 && ok="guest"
        if [ -n "$ok" ]; then echo "$ip smb ok $share ($ok)"; else echo "$ip smb fail $share"; fi
    done < "$T/shares"
fi
# --- MariaDB / MySQL: JDBC data sources with their stored account
MY=$(command -v mariadb || command -v mysql || true)
if [ -n "$MY" ]; then
    xargs -r -d '\n' grep -alE 'jdbc:(mariadb|mysql)://10\.10\.' < "$T/files" 2>/dev/null | while read -r f; do
        url=$(grep -aoE 'jdbc:(mariadb|mysql)://10\.10\.[0-9]+\.[0-9]+(:[0-9]+)?/[A-Za-z0-9_]+' "$f" | head -1)
        [ -n "$url" ] || continue
        hp=${url#*://}; hp=${hp%%/*}; db=${url##*/}
        ip=${hp%%:*}; port=3306; case "$hp" in *:*) port=${hp##*:} ;; esac
        is_target "$ip" || continue
        user=$(grep -aoE 'username="[^"]*"' "$f" | head -1 | cut -d'"' -f2)
        pass=$(grep -aoE 'password="[^"]*"' "$f" | head -1 | cut -d'"' -f2)
        if "$MY" -h "$ip" -P "$port" -u "$user" -p"$pass" --connect-timeout=5 -e 'select 1' "$db" >/dev/null 2>&1
        then echo "$ip mysql ok $url ($f)"; else echo "$ip mysql fail $url ($f)"; fi
    done
fi

# --- Redis: redis://ip:port URLs, PING over a plain TCP connection (bash /dev/tcp, no client needed)
grep -aohE 'redis://10\.10\.[0-9]+\.[0-9]+(:[0-9]+)?' "$T/text" | sort -u | while read -r url; do
    hp=${url#redis://}; ip=${hp%%:*}; port=6379; case "$hp" in *:*) port=${hp##*:} ;; esac
    is_target "$ip" || continue
    reply=$(timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"; printf "PING\r\n" >&3; head -c 5 <&3' "$ip" "$port" 2>/dev/null)
    case "$reply" in +PONG*) echo "$ip redis ok $url" ;; *) echo "$ip redis fail $url" ;; esac
done

rm -rf "$T"
