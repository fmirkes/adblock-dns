FROM alpine:latest

ENV PIXELSERV_IP=0.0.0.0

EXPOSE 53

VOLUME ["/etc/dnsmasq.d"]

RUN apk --no-cache add ca-certificates dnsmasq python3

RUN echo "addn-hosts=/etc/dnsmasq.d/adblock.hosts" > /etc/dnsmasq.d/adblock.conf

COPY create-adblock-hosts-file.py /usr/local/bin/create-adblock-hosts-file

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
