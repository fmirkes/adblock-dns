FROM alpine:latest

ENV PIXELSERV_IP=127.0.0.1

ENV DOMAIN_WHITELIST=

ENV BLOCKLISTS_SIMPLE=
ENV BLOCKLISTS_ABP=
ENV BLOCKLISTS_HOSTS=

EXPOSE 53

RUN apk --no-cache add ca-certificates dnsmasq python3

RUN echo "addn-hosts=/etc/dnsmasq.d/adblock.hosts" > /etc/dnsmasq.d/adblock.conf

COPY create-adblock-hosts-file.py /usr/local/bin/create-adblock-hosts-file

VOLUME ["/etc/dnsmasq.d"]

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
