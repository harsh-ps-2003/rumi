use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rumi::oram::{Operation, PathORAM};
use rand::{thread_rng, Rng};
use std::time::Instant;

#[derive(Default)]
struct ORAMMetrics {
    time_ns: u64,
    operations_count: usize,
    data_transferred_bytes: usize,
    tree_height: usize,
    position_map_size: usize,
    stash_size: usize,
    total_blocks: usize,
}

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
    
    group.bench_with_input(
        BenchmarkId::new("comprehensive", data_size),
        &data_size,
        |b, _| {
            b.iter_custom(|iters| {
                let mut total_metrics = ORAMMetrics::default();
                
                for _ in 0..iters {
                    let start = Instant::now();
                    
                    // Perform ORAM operation
                    let block_id = if access_pattern == "sequential" {
                        1000 // Fixed for sequential access
                    } else {
                        rng.gen_range(0..10000)
                    };
                    
                    match operation {
                        Operation::Read => {
                            let result = oram.access(Operation::Read, block_id as u64, None, &mut rng);
                            if let Some(data) = result {
                                total_metrics.data_transferred_bytes += data.len();
                            }
                        }
                        Operation::Write => {
                            oram.access(
                                Operation::Write,
                                block_id as u64,
                                Some(test_data.clone()),
                                &mut rng,
                            );
                            total_metrics.data_transferred_bytes += data_size;
                        }
                    }
                    
                    total_metrics.time_ns += start.elapsed().as_nanos() as u64;
                    total_metrics.operations_count += 1;
                }
                
                // Collect final metrics
                total_metrics.tree_height = oram.get_tree_height();
                total_metrics.position_map_size = oram.get_position_map_size();
                total_metrics.stash_size = oram.get_stash_size();
                total_metrics.total_blocks = oram.get_total_blocks();
                
                // Log detailed metrics
                println!("\nDetailed metrics for {:?} operation ({} pattern, {} bytes):", 
                    operation, access_pattern, data_size);
                println!("Avg time per op: {} ns", total_metrics.time_ns / iters);
                println!("Total operations: {}", total_metrics.operations_count);
                println!("Data transferred: {} bytes", total_metrics.data_transferred_bytes);
                println!("Tree height: {}", total_metrics.tree_height);
                println!("Position map size: {} entries", total_metrics.position_map_size);
                println!("Stash size: {} blocks", total_metrics.stash_size);
                println!("Total blocks in ORAM: {}", total_metrics.total_blocks);
                println!("Throughput: {:.2} ops/sec", 
                    (total_metrics.operations_count as f64) / 
                    (total_metrics.time_ns as f64 / 1_000_000_000.0));
                println!("Data throughput: {:.2} MB/sec",
                    (total_metrics.data_transferred_bytes as f64 / 1_000_000.0) /
                    (total_metrics.time_ns as f64 / 1_000_000_000.0));
                
                std::time::Duration::from_nanos(total_metrics.time_ns / iters)
            });
        },
    );
    
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
            let mut total_data = 0;
            let mut reads = 0;
            let mut writes = 0;
            
            for _ in 0..iters {
                let op = if rng.gen_bool(0.5) {
                    reads += 1;
                    Operation::Read
                } else {
                    writes += 1;
                    Operation::Write
                };
                
                let block_id = rng.gen_range(0..10000) as u64;
                let data = if op == Operation::Write {
                    Some(test_data.clone())
                } else {
                    None
                };
                
                if let Some(result) = oram.access(op, block_id, data, &mut rng) {
                    total_data += result.len();
                }
            }
            
            let elapsed = start.elapsed();
            println!("\nThroughput test results:");
            println!("Total operations: {} ({} reads, {} writes)", iters, reads, writes);
            println!("Total data transferred: {} bytes", total_data);
            println!("Time elapsed: {:.2} seconds", elapsed.as_secs_f64());
            println!("Throughput: {:.2} ops/sec", 
                iters as f64 / elapsed.as_secs_f64());
            println!("Data throughput: {:.2} MB/sec",
                (total_data as f64 / 1_000_000.0) / elapsed.as_secs_f64());
            println!("Final stash size: {} blocks", oram.get_stash_size());
            println!("Final total blocks: {}", oram.get_total_blocks());
            
            elapsed
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