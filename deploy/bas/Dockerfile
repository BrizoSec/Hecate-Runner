# Build with a context containing only this file and the Sandcat binary.
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --chmod=0555 sandcat /usr/local/bin/sandcat
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/sandcat"]
