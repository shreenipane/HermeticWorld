# Online preparation only. BASE_IMAGE must include Rust 1.97.0 and musl tools.
# Pass an immutable repository@sha256:digest; retain the resulting image ID.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY source.tar.gz /tmp/source.tar.gz
RUN echo '89f02fe6867edcf0a0154305d5533a611e48eaa99ba11d24aa2f076492bef615  /tmp/source.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/source.tar.gz -C /tmp \
    && cd /tmp/firecracker-1.18.0 \
    && cargo +1.97.0 vendor --locked --versioned-dirs /vendor > /tmp/vendor-config.toml \
    && mv /tmp/vendor-config.toml /vendor/config.toml \
    && chmod -R a+rX /vendor \
    && rm -rf /tmp/firecracker-1.18.0 /tmp/source.tar.gz
