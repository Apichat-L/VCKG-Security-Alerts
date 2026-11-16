FROM kalilinux/kali-rolling
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nmap iproute2 iputils-ping curl netcat-traditional smbclient postgresql-client openssh-client \
        bind9-dnsutils mariadb-client redis-tools swaks \
 && rm -rf /var/lib/apt/lists/*
# The lab subnets (10.10.0.0/16) are behind the firewall; everything else uses Docker's gateway.
CMD ["sh", "-c", "ip route replace 10.10.0.0/16 via 172.30.0.254 && echo 'kali: ready' && exec sleep infinity"]
