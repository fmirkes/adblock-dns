#!/bin/sh
set -eu

if ! [ -f "/var/cache/pixelserv/ca.key" ]; then
  echo "Generating ssl ca private key..."
  openssl genrsa -out "/var/cache/pixelserv/ca.key" 2048

  echo "Generating ssl ca crt..."
  openssl req -key "/var/cache/pixelserv/ca.key" -new -x509 -days 3650 -sha256 -extensions v3_ca -out "/var/cache/pixelserv/ca.crt" -subj "/CN=${PIXELSERV_CA_CN}"
fi

echo "Starting pixelserv..."
exec pixelserv-tls -f
