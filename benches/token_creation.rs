use cerberus::UserId;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{thread, time::Duration, vec};

fn bench_token_creation(c: &mut Criterion) {
    ///////////
    // SETUP //
    ///////////

    let batch_sizes = vec![10, 50];
    let n_moderators = 5;
    let signing_threshold = 4;
    let decryption_threshold = 3;

    // create rng and async runtime
    let mut rng = rand::thread_rng();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    // wait for mod servers to start
    thread::sleep(Duration::from_millis(1000));

    //////////////////
    // BENCHMARKING //
    //////////////////

    let mut token_creation = c.benchmark_group("token_creation");

    for batch_size in batch_sizes {
        // create benchmark coordinator
        let mut coordinator = tokio_runtime
            .block_on(cerberus::Coordinator::init(
                n_moderators,
                signing_threshold,
                decryption_threshold,
                batch_size,
            ))
            .unwrap();

        //create random batch of user ids
        let user_ids: Vec<_> =
            (0..batch_size).map(|_| UserId::random(&mut rng)).collect();

        token_creation.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, _batch_size| {
                b.iter(|| {
                    let _tokens = tokio_runtime
                        .block_on(coordinator.create_tokens(&user_ids))
                        .expect("Failed to create tokens.");
                })
            },
        );

        // shut down the moderator servers so we can start fresh
        //  with the next set of parameters
        tokio_runtime
            .block_on(coordinator.shutdown_moderators())
            .expect("Unable to shut down moderators.");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(60));
    targets = bench_token_creation
}

criterion_main!(benches);
