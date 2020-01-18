FROM alpine:latest

ENV PIXELSERV_IP=0.0.0.0

EXPOSE 53

VOLUME ["/etc/dnsmasq.d"]

RUN apk --no-cache add ca-certificates dnsmasq python3

COPY create-dnsmasq-adblock-conf.py /usr/local/bin/create-dnsmasq-adblock-conf

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
