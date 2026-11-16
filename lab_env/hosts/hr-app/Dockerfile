# APP HR portal. Apache Tomcat 9.0.85 -> CPE apache:tomcat (CVE-2025-24813 in CISA KEV, CVE-2024-50379,
# CVE-2024-52316, ...). Upstream build (Tomcat's own tarball in the official image), not a distro package.
# The default servlet is writable (readonly=false), the precondition of CVE-2025-24813 / CVE-2024-50379: lab only.
# HR-App -> HR-DB dependency: the /hr webapp reads the employees table on HR-DB (JNDI DataSource in context.xml).
FROM tomcat:9.0.85-jdk17-temurin-jammy
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
# mariadb-client: the admin console a real HR server would have (and what lab_env/eval/harvest.sh uses)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends mariadb-client \
 && rm -rf /var/lib/apt/lists/*
ADD https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/3.3.3/mariadb-java-client-3.3.3.jar \
    /usr/local/tomcat/lib/mariadb-java-client-3.3.3.jar
# Access log at a fixed path in combined format (Wazuh's apache decoder), the default servlet writable.
RUN sed -i -e 's|prefix="localhost_access_log" suffix=".txt"|prefix="access_log" suffix="" rotatable="false"|' \
           -e 's|pattern="%h %l %u %t &quot;%r&quot; %s %b"|pattern="combined"|' conf/server.xml \
 && grep -n 'access_log' conf/server.xml \
 && sed -i '/<servlet-name>default<\/servlet-name>/,/<load-on-startup>/ s|<load-on-startup>|<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>\n        <load-on-startup>|' conf/web.xml \
 && grep -n -A1 '<param-name>readonly' conf/web.xml
COPY hosts/hr-app/webapp/ /usr/local/tomcat/webapps/
RUN sed -i 's/\r$//' /usr/local/tomcat/webapps/hr/*.jsp /usr/local/tomcat/webapps/hr/META-INF/context.xml
ENV CATALINA_OPTS="-Xmx256m"
EXPOSE 8080
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["catalina.sh", "run"]
