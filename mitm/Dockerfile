# TLS interception node.
#
# Based on the official mitmproxy image (Debian trixie) rather than Alpine:
# Alpine ships neither mitmproxy nor wireguard-go.
#
# The tunnel endpoint, the local redirect and the proxy all live in this one
# netns deliberately. Transparent mode recovers the original destination via
# SO_ORIGINAL_DST, which only works when the iptables REDIRECT happened on the
# same host as the proxy. That is why the router cannot simply DNAT to here - a
# DNAT rewrites the destination and the proxy would have no idea where the
# client was actually trying to go.
FROM mitmproxy/mitmproxy:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      wireguard-tools \
      wireguard-go \
      iptables iproute2 \
      procps iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# wireguard-go is installed in the SAME layer deliberately. Splitting it into a
# second RUN with "|| true" silently produced an image with no userspace backend
# at all - wg-quick was present, wireguard-go was not, and transparent mode
# would have failed at runtime rather than at build time.

COPY addons/ /addons/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 8080 proxy, 8081 mitmweb, 51820/udp tunnel
EXPOSE 8080 8081 51820/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
