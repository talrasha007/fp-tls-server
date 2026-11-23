FROM rust:1.93-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libpcap-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs README.md ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/fp-tls-server /usr/local/bin/fp-tls-server
ENTRYPOINT ["/usr/local/bin/fp-tls-server"]
