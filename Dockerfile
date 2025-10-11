# ---- Stage 1: Build -------------------------------------------------------
# Use the latest stable Rust toolchain to compile the project.
# ---- Stage 1: Build -------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /usr/src/app

RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev clang \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests AND .cargo config first
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src

# Build the project in release mode.
RUN cargo build --release

# ---- Stage 2: Runtime -----------------------------------------------------
FROM debian:bookworm-slim

# Install runtime dependencies and helper tools for templating configs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage.
COPY --from=builder /usr/src/app/target/release/bpst /usr/local/bin/bpst

# Copy the deployment tooling.
COPY deployment/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Create directory for configuration files.
RUN mkdir -p /etc/bpst

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bpst"]
