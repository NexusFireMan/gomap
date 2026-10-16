#!/bin/sh
set -eu

cp /fixtures/usm.conf /var/lib/snmp/snmpd.conf
exec /usr/sbin/snmpd -f -Lo -p /run/snmpd.pid
