#!/bin/sh
set -eu
mkdir -p /var/cache/bind/keys
python3 /opt/zone/generate.py
sed "s/@WAN_DOMAIN@/$WAN_DOMAIN/g" /opt/zone/named.conf.template > /var/cache/bind/named.conf
named-checkzone "$WAN_DOMAIN" /var/cache/bind/zone.db
named-checkconf -z /var/cache/bind/named.conf
exec named -g -c /var/cache/bind/named.conf
