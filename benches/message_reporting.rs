use cerberus::UserId;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{thread, time::Duration, vec};

fn bench_message_reporting(c: &mut Criterion) {
    ///////////
    // SETUP //
    ///////////

    let batch_size = 1;
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

    let mut message_reporting = c.benchmark_group("message_reporting");

    for (n, t) in n_moderators.into_iter().zip(thresholds) {
        // create benchmark coordinator
        let mut coordinator = tokio_runtime
            .block_on(cerberus::Coordinator::init(n, t, t, batch_size))
            .unwrap();

        // get a token to report
        let user_ids: Vec<_> =
            (0..batch_size).map(|_| UserId::random(&mut rng)).collect();

        let token = tokio_runtime
            .block_on(coordinator.create_tokens(&user_ids))
            .unwrap()
            .pop()
            .unwrap();

        let id = BenchmarkId::from_parameter(format!("{n}-{t}"));
        message_reporting.bench_with_input(
            id,
            &batch_size,
            |b, _batch_size| {
                b.iter(|| {
                    tokio_runtime
                        .block_on(coordinator.request_token_decryption(&token))
                        .unwrap();
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
    targets = bench_message_reporting
}

criterion_main!(benches);
