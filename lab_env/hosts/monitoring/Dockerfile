# MGMT monitoring. Grafana 10.2.3 (official image, Ubuntu 22.04) -> CPE grafana:grafana (CVE-2024-1442,
# CVE-2025-4123, ...). Upstream build, not an Ubuntu package.
# Monitoring -> PostgreSQL dependency: a provisioned PostgreSQL datasource (shop dashboards); the health check asks
# Grafana to test it. Runs as root so the entrypoint can set the route and start the Wazuh agent (lab only).
FROM grafana/grafana:10.2.3-ubuntu
USER root
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
# psql: the operator's console for the same database (libpq environment in docker-compose.yml)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-client \
 && rm -rf /var/lib/apt/lists/*
COPY hosts/monitoring/provisioning/ /etc/grafana/provisioning/
RUN sed -i 's/\r$//' /etc/grafana/provisioning/datasources/*.yaml
EXPOSE 3000
ENTRYPOINT ["/lab/entrypoint.sh", "/run.sh"]
