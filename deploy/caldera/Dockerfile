# Derive from the locally installed controller image; runtime state is never
# copied into an image. Pin BASE_IMAGE to an inspected local image when building.
ARG BASE_IMAGE=caldera-local:latest
FROM ${BASE_IMAGE}
USER 0
RUN groupadd --gid 10001 caldera-runtime \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --home-dir /tmp/caldera-home --shell /usr/sbin/nologin caldera-runtime
ENV HOME=/tmp/caldera-home USER=caldera-runtime LOGNAME=caldera-runtime \
    PYTHONDONTWRITEBYTECODE=1 GOCACHE=/tmp/caldera-home/go-cache
USER 10001:10001
WORKDIR /usr/src/app
ENTRYPOINT ["python3", "-u", "server.py"]
