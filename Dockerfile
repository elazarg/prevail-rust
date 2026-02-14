FROM rust:1.93-slim

WORKDIR /prevail
COPY . /prevail/
RUN cargo build --release
ENTRYPOINT ["target/release/prevail"]
