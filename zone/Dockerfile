FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends bind9 bind9-utils dnsutils python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY zone /opt/zone
RUN chmod 0555 /opt/zone/entrypoint.sh && mkdir -p /var/cache/bind/keys && chown -R bind:bind /var/cache/bind
USER bind
ENTRYPOINT ["/opt/zone/entrypoint.sh"]
