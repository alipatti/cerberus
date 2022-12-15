use array_init::array_init;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use std::{thread, time::Duration};

fn bench(c: &mut Criterion) {
    // create rng and async runtime
    let mut rng = thread_rng();
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    // wait for mod servers to start and create coordinator object
    thread::sleep(Duration::from_millis(500));
    let coordinator = tokio_runtime
        .block_on(cerberus::Coordinator::init())
        .unwrap();

    c.bench_function("iter", move |b| {
        let user_ids = array_init(|_| cerberus::UserId(rng.gen()));
        b.to_async(&tokio_runtime).iter(|| async {
            coordinator.create_tokens(&user_ids).await.unwrap()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
