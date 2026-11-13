# Owner prepares this builder separately, then pins its resulting RepoDigest in the lock.
# BASE_IMAGE must be a reviewed Debian bookworm reference with an immutable sha256 digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN test -f /etc/debian_version && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      bash bc binutils bison build-essential ca-certificates flex libelf-dev \
      libssl-dev python3 xz-utils && \
    rm -rf /var/lib/apt/lists/*
ENV LC_ALL=C TZ=UTC
WORKDIR /build
# Runtime overrides this with the non-root caller's numeric transport uid/gid.
USER 1000:1000
