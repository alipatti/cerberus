# Cerberus

A decentralized abuse-reporting protocol for end-to-end encrypted messaging services [as presented at IEEE S&P, 2023](https://sp2023.ieee-security.org/downloads/SP23-posters/sp23-posters-paper30-final_version_2_page_abstract.pdf).

## Benchmarks

Benchmarks were run on a 2020 MacBook Pro with each container alloted a single 2.6 GHz processor and 1GB ram. Results are available at the link above.

Execute `docker compose up --build` to run the benchmarks. This will cause Docker to compile the program, launch all parties in separate containers, and benchmark token-creation and message-reporting. Results will be placed in the creatively-named `benches/results` folder.

In principle, Docker is the only requirement to run the benchmarks, but I haven't tested that. With that said, expect to wait quite a while the first time you run the program while the dependencies are built and the code is compiled. Subsequent runs should be much, much faster due to Docker's caching.
