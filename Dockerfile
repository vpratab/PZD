# Parent-partition proxy image for the PZDR Nitro Gateway.
#
# The enclave binary is built separately into an EIF with eif/build-eif.sh.

FROM rust:1-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services

RUN cargo build --release --bin vsock-parent-proxy

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -m -s /usr/sbin/nologin pzdr

COPY --from=builder /build/target/release/vsock-parent-proxy /usr/local/bin/vsock-parent-proxy

ENV PROXY_ADDR=0.0.0.0:8090 \
    ENCLAVE_CID=16 \
    ENCLAVE_PORT=5000 \
    ENCLAVE_TIMEOUT_MS=30000 \
    RUST_LOG=info

EXPOSE 8090
USER pzdr

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fs http://127.0.0.1:8090/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/vsock-parent-proxy"]
