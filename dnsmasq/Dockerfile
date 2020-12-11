FROM alpine:latest

ENV PIXELSERV_IP4=127.0.0.1
ENV PIXELSERV_IP6=::1

ENV DOMAIN_BLACKLIST=
ENV DOMAIN_WHITELIST=

ENV BLOCKLISTS_SIMPLE=
ENV BLOCKLISTS_ABP=
ENV BLOCKLISTS_HOSTS=

EXPOSE 53 53/udp

RUN apk --no-cache add ca-certificates dnsmasq python3

RUN echo "cache-size=10000" > /etc/dnsmasq.d/adblock.conf \
  && echo "local-ttl=2147483647" >> /etc/dnsmasq.d/adblock.conf \
  && echo "addn-hosts=/etc/dnsmasq.d/adblock.hosts" >> /etc/dnsmasq.d/adblock.conf

COPY create-adblock-hosts-file.py /usr/local/bin/create-adblock-hosts-file

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
