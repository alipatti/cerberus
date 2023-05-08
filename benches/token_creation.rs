use cerberus::UserId;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{thread, time::Duration, vec};

fn bench_token_creation(c: &mut Criterion) {
    ///////////
    // SETUP //
    ///////////

    let batch_sizes = vec![1, 10, 50, 100, 200, 500, 750, 1000];
    let n_moderators = vec![3, 5, 7];
    let thresholds = vec![2, 3, 4];

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

    for (n, t) in n_moderators.into_iter().zip(thresholds) {
        for batch_size in &batch_sizes {
            // create benchmark coordinator
            let mut coordinator = tokio_runtime
                .block_on(cerberus::Coordinator::init(n, t, t, *batch_size))
                .unwrap();

            //create random batch of user ids
            let user_ids: Vec<_> =
                (0..*batch_size).map(|_| UserId::random(&mut rng)).collect();

            let id =
                BenchmarkId::from_parameter(format!("{n}-{t}-{batch_size}"));
            token_creation.bench_with_input(
                id,
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
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(60));
    targets = bench_token_creation
}

criterion_main!(benches);
