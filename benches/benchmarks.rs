use cerberus::UserId;
use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    thread,
    time::{Duration, Instant},
};

fn bench(c: &mut Criterion) {
    // TODO parameterize benchmarks over this
    let batch_size = 100;

    // create rng and async runtime
    let mut rng = rand::thread_rng();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    // wait for mod servers to start
    thread::sleep(Duration::from_millis(500));

    // create coordinator object
    let mut coordinator = tokio_runtime
        .block_on(cerberus::Coordinator::init(batch_size))
        .unwrap();

    //create random batch of user ids
    let user_ids: Vec<_> =
        (0..batch_size).map(|_| UserId::random(&mut rng)).collect();

    c.bench_function("token_creation", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();

            for _ in 0..iters {
                let _tokens = tokio_runtime
                    .block_on(coordinator.create_tokens(&user_ids))
                    .expect("Failed to create tokens.");
            }

            start.elapsed()
        });

        // toy example:
        // b.iter(|| {
        //     (0..batch_size)
        //         .map(|_| UserId::random(&mut rng))
        //         .collect::<Vec<_>>()
        // });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(60));
    targets = bench
}
criterion_main!(benches);
