# Base image for the demo service
FROM alpine:latest
RUN apk add --no-cache curl
# intentionally runs as root (DS002) for the self-control
CMD ["sh"]
