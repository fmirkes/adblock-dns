#!/bin/sh
set -eu

echo "Creating adblock hosts file..."
/usr/local/bin/create-adblock-hosts-file

echo "Starting dnsmasq..."
exec dnsmasq -d
