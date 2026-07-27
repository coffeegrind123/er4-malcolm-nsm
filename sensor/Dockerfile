FROM alpine:3.20
RUN apk add --no-cache openssh-client tcpdump tzdata
COPY capture.sh rotate.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/capture.sh /usr/local/bin/rotate.sh
ENTRYPOINT ["/usr/local/bin/capture.sh"]
