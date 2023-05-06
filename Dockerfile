########################
## BUILDING CONTAINER ##
########################

FROM rust:1.69 AS builder

WORKDIR /usr/src/cerberus

# -- build dependencies --
# this leverages Docker's caching and will only run when dependencies change
RUN cargo init
COPY Cargo.toml Cargo.lock ./
RUN cargo build
# RUN cargo build --release

# -- build app --
COPY src ./src
COPY .env ./
RUN cargo build
# RUN cargo build --release

###########################################
## SLIMMER CONTAINERS TO ACTUALLY DEPLOY ##
###########################################

FROM debian:buster-slim AS moderator

# instal openssl libraries
RUN apt-get update && apt-get install -y libssl-dev

COPY --from=builder usr/src/cerberus/target/debug/moderator .
# COPY  --from=builder usr/src/cerberus/target/release/moderator .
CMD ["./moderator"]

FROM debian:buster-slim AS coordinator

# instal openssl libraries (required for https communication)
RUN apt-get update && apt-get install -y libssl-dev

COPY --from=builder usr/src/cerberus/target/debug/coordinator .
# COPY  --from=builder usr/src/cerberus/target/release/coordinator .
CMD ["./coordinator"]
