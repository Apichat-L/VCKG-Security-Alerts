# Office workstation (Admin-PC, Dep-PC and Dev-PC share this image; the user comes from the environment).
# OpenSSH is pinned to Ubuntu 22.04's release build 1:8.9p1-3, which has none of the later security
# updates -> CPE openbsd:openssh 8.9p1 (CVE-2025-26465, ...).
FROM ubuntu:22.04
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server=1:8.9p1-3 openssh-client=1:8.9p1-3 openssh-sftp-server=1:8.9p1-3 \
        sudo smbclient postgresql-client curl sshpass \
 && apt-mark hold openssh-server openssh-client openssh-sftp-server \
 && rm -rf /var/lib/apt/lists/*
COPY hosts/workstation/start.sh /lab/start.sh
RUN sed -i 's/\r$//' /lab/start.sh && chmod +x /lab/start.sh
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/start.sh"]
