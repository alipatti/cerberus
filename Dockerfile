FROM rust:1.65 AS builder

WORKDIR /usr/src/hecate
COPY . .
RUN cargo build --release


FROM debian:buster-slim AS moderator

COPY  --from=builder usr/src/hecate/target/release/moderator .
CMD ["./moderator"]


FROM debian:buster-slim AS coordinator

COPY  --from=builder usr/src/hecate/target/release/coordinator .
CMD ["./coordinator"]
