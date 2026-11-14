# Online preparation for the verified Firecracker 1.18.0 builder.
FROM rust@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        musl-tools cmake patch clang libclang-dev linux-libc-dev libseccomp-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
    && ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic
RUN rustup toolchain install 1.97.0 --profile minimal --component rustfmt \
        --target x86_64-unknown-linux-musl \
    && rustup default 1.97.0
