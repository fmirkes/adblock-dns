#!/bin/sh
set -eu

/usr/local/bin/create-adblock-hosts-file
exec dnsmasq -d
