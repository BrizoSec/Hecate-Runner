# Build with a context containing only this file and the Sandcat binary.
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache strace
COPY --chmod=0555 sandcat /usr/local/bin/sandcat
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/usr/bin/strace", "-f", "-qq", "-ttt", "-s", "8192", "-e", "trace=execve,execveat", "-e", "signal=none", "-o", "/tmp/hecate-exec.trace", "/usr/local/bin/sandcat"]
