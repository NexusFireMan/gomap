FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends snmpd \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/gomap-snmp-agent
ENTRYPOINT ["/bin/sh", "/usr/local/bin/gomap-snmp-agent"]
