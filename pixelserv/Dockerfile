FROM alpine

ENV PIXELSERV_VERSION=2.4

EXPOSE 80
EXPOSE 443

ADD https://github.com/kvic-z/pixelserv-tls/archive/refs/tags/${PIXELSERV_VERSION}.tar.gz /tmp/

RUN apk add --no-cache --virtual .build-deps autoconf automake build-base linux-headers openssl-dev \
  && tar xzf "/tmp/${PIXELSERV_VERSION}.tar.gz" -C "/tmp/" \
  && cd "/tmp/pixelserv-tls-${PIXELSERV_VERSION}" \
  && autoreconf -i && ./configure && make install \
  && apk del .build-deps \
  && rm "/tmp/${PIXELSERV_VERSION}.tar.gz" && rm -r "/tmp/pixelserv-tls-${PIXELSERV_VERSION}"

RUN apk add --no-cache openssl \
  && mkdir -p "/var/cache/pixelserv" \
  && openssl genrsa -out "/var/cache/pixelserv/ca.key" 1024 \
  && openssl req -key "/var/cache/pixelserv/ca.key" -new -x509 -days 3650 -sha256 -extensions v3_ca -out "/var/cache/pixelserv/ca.crt" -subj "/CN=Pixelserv CA" \
  && chown -R nobody "/var/cache/pixelserv" \
  && apk del openssl

VOLUME /var/cache/pixelserv

ENTRYPOINT ["pixelserv-tls","-f"]
