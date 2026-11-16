# APP source code hosting. Gitea 1.21.7 (official binary on Debian 12) -> CPE gitea:gitea (45 CVEs in the graph,
# e.g. CVE-2024-6886). Upstream binary, not a Debian package.
# Gitea -> Redis dependency: cache on Redis (app.ini); /api/healthz fails when the cache is down.
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
ARG GITEA_VERSION=1.21.7
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh \
 && /lab/debian-snapshot.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
ADD https://dl.gitea.com/gitea/${GITEA_VERSION}/gitea-${GITEA_VERSION}-linux-amd64 /usr/local/bin/gitea
RUN chmod 755 /usr/local/bin/gitea \
 && useradd -r -m -d /home/git -s /bin/bash git \
 && mkdir -p /etc/gitea /var/lib/gitea /var/log/gitea \
 && chown -R git:git /var/lib/gitea /var/log/gitea
COPY hosts/gitea/app.ini /etc/gitea/app.ini
COPY hosts/gitea/start.sh /lab/start.sh
RUN sed -i 's/\r$//' /lab/start.sh /etc/gitea/app.ini && chmod +x /lab/start.sh && chown -R git:git /etc/gitea
EXPOSE 3000
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/start.sh"]
