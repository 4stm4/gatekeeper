FROM rust:1.83-slim

# Install system dependencies required by bindgen/clang users.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang pkg-config libclang-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain install nightly --profile minimal

WORKDIR /work

# Cache crates.io index/dependencies once during the image build so that
# subsequent `docker run` executions don't pull them again.
COPY Cargo.toml Cargo.lock build.rs memory.x ./
COPY benches ./benches
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && cargo +nightly fetch --locked \
    && rm -rf src

# Default command executes host tests; override in `docker run ... -- <cmd>`
# if another target/feature set is needed.
CMD ["cargo", "test", "--tests", "--target", "x86_64-unknown-linux-gnu"]
