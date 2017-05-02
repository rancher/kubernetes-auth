FROM ubuntu:16.04

RUN apt-get update -y \
    && apt-get install -y wget curl jq unzip

COPY kubernetes-auth /usr/bin/
COPY entry.sh /usr/bin/

ENV SSL_SCRIPT_COMMIT 98660ada3d800f653fc1f105771b5173f9d1a019
RUN wget -O /usr/bin/update-rancher-ssl https://raw.githubusercontent.com/rancher/rancher/${SSL_SCRIPT_COMMIT}/server/bin/update-rancher-ssl && \
    chmod +x /usr/bin/update-rancher-ssl

ENTRYPOINT ["/usr/bin/entry.sh"]
CMD ["kubernetes-auth"]
