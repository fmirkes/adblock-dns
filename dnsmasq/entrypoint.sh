#!/bin/sh
set -eu

/usr/local/bin/create-dnsmasq-adblock-conf
dnsmasq -d
