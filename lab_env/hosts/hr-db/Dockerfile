# DATA HR database. MariaDB 10.11.6 (official image, Ubuntu 22.04) -> CPE mariadb:mariadb (22 CVEs in the graph).
# Upstream build (MariaDB's own repository), not an Ubuntu package.
FROM mariadb:10.11.6-jammy
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
COPY hosts/hr-db/init.sql /docker-entrypoint-initdb.d/10-hr.sql
RUN mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql
EXPOSE 3306
ENTRYPOINT ["/lab/entrypoint.sh", "docker-entrypoint.sh"]
# Error log to a file the Wazuh agent reads (log_format mysql_log): "Access denied for user" lines on failed
# logins (log_warnings=2, the default). Small buffer pool: the lab has many hosts.
CMD ["mariadbd", "--log-error=/var/log/mysql/error.log", "--log-warnings=2", "--innodb-buffer-pool-size=64M"]
