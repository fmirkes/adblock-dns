FROM alpine

ENV PIXELSERV_VERSION="2.4"
ENV PIXELSERV_CA_CN="adblock-dns CA"

EXPOSE 80
EXPOSE 443

ADD https://github.com/kvic-z/pixelserv-tls/archive/refs/tags/${PIXELSERV_VERSION}.tar.gz /tmp/

RUN apk add --no-cache --virtual .build-deps autoconf automake build-base linux-headers openssl-dev \
  && tar xzf "/tmp/${PIXELSERV_VERSION}.tar.gz" -C "/tmp/" \
  && cd "/tmp/pixelserv-tls-${PIXELSERV_VERSION}" \
  && autoreconf -i && ./configure && make install \
  && apk del .build-deps \
  && rm "/tmp/${PIXELSERV_VERSION}.tar.gz" && rm -r "/tmp/pixelserv-tls-${PIXELSERV_VERSION}"

RUN apk add --no-cache openssl

RUN mkdir -p "/var/cache/pixelserv" \
  && chown -R nobody "/var/cache/pixelserv"

VOLUME /var/cache/pixelserv

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
