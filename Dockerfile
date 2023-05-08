########################
## BUILDING CONTAINER ##
########################

FROM rust:1.69 AS builder

WORKDIR /usr/src/cerberus

# -- build dependencies --
# this leverages Docker's caching and will only run when dependencies change
RUN cargo init
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# -- build app --
COPY src ./src
COPY examples ./examples
RUN cargo build --release --examples

###########################################
## SLIMMER CONTAINERS TO ACTUALLY DEPLOY ##
###########################################

FROM debian:buster-slim AS moderator

RUN apt-get update && apt-get install -y libssl-dev

COPY --from=builder usr/src/cerberus/target/release/examples/moderator_server .
CMD ["./moderator_server"]

FROM debian:buster-slim AS tester

RUN apt-get update && apt-get install -y libssl-dev

COPY --from=builder usr/src/cerberus/target/release/examples/dry_run .
CMD ["./dry_run"]

########################
## BENCHING CONTAINER ##
########################

FROM builder AS bencher

# HACK: add benchmark to cargo manifest
RUN echo "\
[[bench]]\n\
name = 'token_creation'\n\
harness = false \n\
" >>Cargo.toml

# copy in benchmarks themselves
COPY benches/ ./benches

CMD ["cargo", "bench", "--bench", "token_creation"]
