# Cerberus

A decentralized abuse-reporting protocol for end-to-end encrypted messaging services as presented at IEEE S&P, 2023 ([extended abstract](TODO), [poster](TODO)).

## Benchmarks

Execute `docker compose up --build` to run the benchmarks. This will cause Docker to compile the program, launch moderators in separate containers, and benchmark token-creation and message-reporting. Results will be placed in the creatively-named `benchmark-results` folder.

In principle, Docker is the only requirement to run the benchmarks, but I haven't tested that. With that said, expect to wait quite a while the first time you run the program while the dependencies are built and the code is compiled. Subsequent runs should be much, much faster due to Docker's caching.
