# DATA cache. Redis 7.2.4 (official image, Debian 12) -> CPE redis:redis (CVE-2024-31449, CVE-2025-21605,
# CVE-2025-49844, ...). Upstream build, not a Debian package. No password and protected mode off: anyone who can
# reach 6379 can read and write the cache (lab only).
FROM redis:7.2.4-bookworm
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN mkdir -p /var/log/redis && chown redis:redis /var/log/redis
EXPOSE 6379
ENTRYPOINT ["/lab/entrypoint.sh", "docker-entrypoint.sh"]
# Log to a file for the Wazuh agent (no stock decoder: collected as plain syslog lines)
CMD ["redis-server", "--protected-mode", "no", "--logfile", "/var/log/redis/redis.log", "--maxmemory", "64mb"]
