use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rumi::oram::{Operation, PathORAM};
use rand::{thread_rng, Rng};
use std::time::Instant;

fn bench_oram_operation(
    operation: Operation,
    data_size: usize,
    access_pattern: &str,
    c: &mut Criterion,
) {
    let mut rng = thread_rng();
    let mut oram = PathORAM::new();
    let test_data = vec![1u8; data_size];
    
    let mut group = c.benchmark_group(format!("oram_{:?}_{}", operation, access_pattern));
    group.sample_size(50);
    group.measurement_time(std::time::Duration::from_secs(10));
    
    // Pre-populate ORAM with some data
    for i in 0..1000 {
        oram.access(
            Operation::Write,
            i as u64,
            Some(vec![1u8; data_size]),
            &mut rng,
        );
    }
    
    group.bench_function(format!("size_{}", data_size), |b| {
        b.iter(|| {
            let block_id = if access_pattern == "sequential" {
                1000
            } else {
                rng.gen_range(0..10000)
            };
            
            match operation {
                Operation::Read => {
                    oram.access(Operation::Read, block_id as u64, None, &mut rng)
                }
                Operation::Write => {
                    oram.access(
                        Operation::Write,
                        block_id as u64,
                        Some(test_data.clone()),
                        &mut rng,
                    )
                }
            }
        });
    });
    
    group.finish();
}

fn bench_oram_scaling(c: &mut Criterion) {
    // Test different data sizes
    for &size in &[32, 64, 128, 256, 512, 1024, 2048, 4096] {
        // Test sequential access pattern
        bench_oram_operation(Operation::Read, size, "sequential", c);
        bench_oram_operation(Operation::Write, size, "sequential", c);
        
        // Test random access pattern
        bench_oram_operation(Operation::Read, size, "random", c);
        bench_oram_operation(Operation::Write, size, "random", c);
    }
}

fn bench_oram_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("oram_throughput");
    let mut rng = thread_rng();
    let mut oram = PathORAM::new();
    let test_data = vec![1u8; 64]; // Use 64-byte blocks for throughput test
    
    // Pre-populate ORAM
    for i in 0..1000 {
        oram.access(Operation::Write, i as u64, Some(vec![1u8; 64]), &mut rng);
    }
    
    group.bench_function("mixed_workload", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            
            for _ in 0..iters {
                let op = if rng.gen_bool(0.5) {
                    Operation::Read
                } else {
                    Operation::Write
                };
                
                let block_id = rng.gen_range(0..10000) as u64;
                let data = if op == Operation::Write {
                    Some(test_data.clone())
                } else {
                    None
                };
                
                let _ = oram.access(op, block_id, data, &mut rng);
            }
            
            start.elapsed()
        });
    });
    
    group.finish();
}

criterion_group!(
    name = oram_benches;
    config = Criterion::default()
        .sample_size(50)
        .measurement_time(std::time::Duration::from_secs(30));
    targets = bench_oram_scaling, bench_oram_throughput
);
criterion_main!(oram_benches); 