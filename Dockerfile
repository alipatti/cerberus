FROM rust:1.65 AS builder

WORKDIR /usr/src/hecate

# build dependencies first to leverage Docker's caching 
# (the step will only run when dependencies change)
RUN cargo init
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# build app
COPY src ./src
COPY .env ./
RUN cargo build --release


# ---- slimmer containers to actually deploy ----

FROM debian:buster-slim AS moderator

COPY  --from=builder usr/src/hecate/target/release/moderator .
CMD ["./moderator"]

FROM debian:buster-slim AS coordinator

# instal openssl libraries (required for https communication)
RUN apt-get update && apt-get install -y libssl-dev

COPY  --from=builder usr/src/hecate/target/release/coordinator .
CMD ["./coordinator"]
