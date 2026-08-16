use fs_dbs_bench::{
    afi06::Afi06, fs_dbs::FsDbs, gao25::Gao25, kmw23::Kmw23, lee25::Lee25, selvi09::Selvi09,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use std::{
    env,
    fs::{self, File},
    hint::black_box,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Serialize)]
struct BenchmarkResult {
    scheme: &'static str,
    group_size: usize,
    phase: &'static str,
    median_ms: f64,
    mean_ms: f64,
    stddev_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
    samples: usize,
    backend: &'static str,
    implementation_scope: &'static str,
}

#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    cpu: String,
    logical_cpus: usize,
    rustc: String,
    profile: &'static str,
    sizes: Vec<usize>,
    samples: usize,
    warmup: usize,
}

struct Options {
    sizes: Vec<usize>,
    samples: usize,
    warmup: usize,
    output: PathBuf,
}

fn main() {
    let options = parse_options();
    assert!(options.sizes.iter().all(|n| *n >= 8));
    let mut results = Vec::new();
    for &size in &options.sizes {
        println!("\n[group size {size}] FS-DBS");
        benchmark_fs_dbs(size, options.samples, options.warmup, &mut results);
        println!("[group size {size}] KMW23");
        benchmark_kmw23(size, options.samples, options.warmup, &mut results);
        println!("[group size {size}] Lee25");
        benchmark_lee25(size, options.samples, options.warmup, &mut results);
        println!("[group size {size}] AFI06");
        benchmark_afi06(size, options.samples, options.warmup, &mut results);
        println!("[group size {size}] Selvi09");
        benchmark_selvi09(size, options.samples, options.warmup, &mut results);
        println!("[group size {size}] Gao25");
        benchmark_gao25(size, options.samples, options.warmup, &mut results);
    }
    write_results(&options, &results).expect("failed to write benchmark results");
    println!("\nResults written to {}", options.output.display());
}

fn benchmark_fs_dbs(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0xF5DB_0000 + n as u64);
    let depth = 6.min(n - 1);
    let scheme = FsDbs::setup(n, depth, &mut rng);
    let mut users = (1..=n)
        .map(|i| scheme.join(i, &mut rng))
        .collect::<Vec<_>>();
    for bit in [0u8, 1, 1, 0] {
        for user in &mut users {
            user.key = scheme.update_key(&user.key, bit, &mut rng);
        }
    }
    let public = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
    let keys = users.iter().map(|u| u.key.clone()).collect::<Vec<_>>();
    let recipients = (1..=n).collect::<Vec<_>>();
    let receiver = n / 2;
    let sender = 1;
    let time = scheme.prepare_time(&keys[0].node);
    let encrypt_cache = scheme.prepare_encrypt_recipients(&recipients, &public);
    let mut decrypt_cache = scheme.prepare_receiver_recipients(&recipients);
    scheme.add_receiver_context(&mut decrypt_cache, receiver, &public, &keys[receiver - 1]);
    let key = [0x11u8; 32];
    let ciphertext = scheme.signcrypt_cached(
        &keys[sender - 1],
        &public[sender - 1],
        &encrypt_cache,
        &time,
        &key,
        &mut rng,
    );
    assert_eq!(
        scheme.unsigncrypt_cached(
            receiver,
            &keys[receiver - 1],
            &public[sender - 1],
            &decrypt_cache,
            &time,
            &ciphertext,
        ),
        Some(key)
    );

    add_measurement(
        results,
        "FS-DBS (ours)",
        n,
        "encrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete optimized implementation",
        || {
            scheme.signcrypt_cached(
                &keys[sender - 1],
                &public[sender - 1],
                &encrypt_cache,
                &time,
                &key,
                &mut rng,
            )
        },
    );
    add_measurement(
        results,
        "FS-DBS (ours)",
        n,
        "decrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete optimized implementation",
        || {
            scheme.unsigncrypt_cached(
                receiver,
                &keys[receiver - 1],
                &public[sender - 1],
                &decrypt_cache,
                &time,
                &ciphertext,
            )
        },
    );
    add_measurement(
        results,
        "FS-DBS (ours)",
        n,
        "encrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete optimized implementation",
        || {
            let cache = scheme.prepare_encrypt_recipients(&recipients, &public);
            scheme.signcrypt_cached(
                &keys[sender - 1],
                &public[sender - 1],
                &cache,
                &time,
                &key,
                &mut rng,
            )
        },
    );
    add_measurement(
        results,
        "FS-DBS (ours)",
        n,
        "decrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete optimized implementation",
        || {
            let mut cache = scheme.prepare_receiver_recipients(&recipients);
            scheme.add_receiver_context(&mut cache, receiver, &public, &keys[receiver - 1]);
            scheme.unsigncrypt_cached(
                receiver,
                &keys[receiver - 1],
                &public[sender - 1],
                &cache,
                &time,
                &ciphertext,
            )
        },
    );
}

fn benchmark_kmw23(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0x23_0000 + n as u64);
    let scheme = Kmw23::setup(n, &mut rng);
    let users = (1..=n)
        .map(|i| scheme.keygen(i, &mut rng))
        .collect::<Vec<_>>();
    let public = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
    let secret = users.iter().map(|u| u.secret.clone()).collect::<Vec<_>>();
    let recipients = (1..=n).collect::<Vec<_>>();
    let receiver = n / 2;
    let enc_cache = scheme.prepare_encrypt_recipients(&recipients, &public);
    let mut dec_cache = scheme.prepare_receiver_recipients(&recipients);
    scheme.add_receiver_context(&mut dec_cache, receiver, &public, &secret[receiver - 1]);
    let key = [0x23u8; 32];
    let ciphertext = scheme.encrypt_cached(&enc_cache, &key, &mut rng);
    assert_eq!(
        scheme.decrypt_cached(receiver, &dec_cache, &ciphertext),
        Some(key)
    );
    for (phase, cached) in [("encrypt_online_cached", true), ("encrypt_full", false)] {
        add_measurement(
            results,
            "KMW23 DBE",
            n,
            phase,
            samples,
            warmup,
            "BLS12-381 Type-3",
            "complete source construction",
            || {
                if cached {
                    scheme.encrypt_cached(&enc_cache, &key, &mut rng)
                } else {
                    let cache = scheme.prepare_encrypt_recipients(&recipients, &public);
                    scheme.encrypt_cached(&cache, &key, &mut rng)
                }
            },
        );
    }
    add_measurement(
        results,
        "KMW23 DBE",
        n,
        "decrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete source construction",
        || scheme.decrypt_cached(receiver, &dec_cache, &ciphertext),
    );
    add_measurement(
        results,
        "KMW23 DBE",
        n,
        "decrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete source construction",
        || {
            let mut cache = scheme.prepare_receiver_recipients(&recipients);
            scheme.add_receiver_context(&mut cache, receiver, &public, &secret[receiver - 1]);
            scheme.decrypt_cached(receiver, &cache, &ciphertext)
        },
    );
}

fn benchmark_lee25(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0x25_0000 + n as u64);
    let scheme = Lee25::setup(n, &mut rng);
    let users = (1..=n)
        .map(|i| scheme.keygen(i, &mut rng))
        .collect::<Vec<_>>();
    let public = users.iter().map(|u| u.public.clone()).collect::<Vec<_>>();
    let recipients = (1..=n).collect::<Vec<_>>();
    let receiver = n / 2;
    let (ciphertext, key) = scheme.encaps(&recipients, &public, &mut rng);
    assert_eq!(
        scheme.decaps(
            &recipients,
            &users[receiver - 1].secret,
            &public,
            &ciphertext,
            &mut rng,
        ),
        Some(key)
    );
    add_measurement(
        results,
        "Lee25 CCA-DBE",
        n,
        "encrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3 + P-256 OTS",
        "complete DBEAD with concrete Schnorr OTS",
        || scheme.encaps(&recipients, &public, &mut rng),
    );
    add_measurement(
        results,
        "Lee25 CCA-DBE",
        n,
        "decrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3 + P-256 OTS",
        "complete DBEAD with concrete Schnorr OTS",
        || {
            scheme.decaps(
                &recipients,
                &users[receiver - 1].secret,
                &public,
                &ciphertext,
                &mut rng,
            )
        },
    );
}

fn benchmark_afi06(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0xAF1_0600 + n as u64);
    let depth = 6.min(n - 1);
    let scheme = Afi06::setup(n, depth, &mut rng);
    let mut keys = (1..=n)
        .map(|i| scheme.register(i, &mut rng))
        .collect::<Vec<_>>();
    for bit in [0u8, 1, 1, 0] {
        for user_key in &mut keys {
            *user_key = scheme.derive(user_key, bit, &mut rng);
        }
    }
    let recipients = (1..=n).collect::<Vec<_>>();
    let receiver = n / 2;
    let time = scheme.prepare_time(&keys[0].node);
    let enc_cache = scheme.prepare_encrypt_recipients(&recipients);
    let mut dec_cache = scheme.prepare_receiver_recipients(&recipients);
    scheme.add_receiver_context(&mut dec_cache, receiver, &keys[receiver - 1]);
    let key = [0x06u8; 32];
    let ciphertext = scheme.encrypt_cached(&enc_cache, &time, &key, &mut rng);
    assert_eq!(
        scheme.decrypt_cached(
            receiver,
            &keys[receiver - 1],
            &dec_cache,
            &time,
            &ciphertext,
        ),
        Some(key)
    );
    add_measurement(
        results,
        "AFI06 FS-BE",
        n,
        "encrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete C(BasicHICBE2) Type-3 port",
        || scheme.encrypt_cached(&enc_cache, &time, &key, &mut rng),
    );
    add_measurement(
        results,
        "AFI06 FS-BE",
        n,
        "decrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete C(BasicHICBE2) Type-3 port",
        || {
            scheme.decrypt_cached(
                receiver,
                &keys[receiver - 1],
                &dec_cache,
                &time,
                &ciphertext,
            )
        },
    );
    add_measurement(
        results,
        "AFI06 FS-BE",
        n,
        "encrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete C(BasicHICBE2) Type-3 port",
        || {
            let cache = scheme.prepare_encrypt_recipients(&recipients);
            scheme.encrypt_cached(&cache, &time, &key, &mut rng)
        },
    );
    add_measurement(
        results,
        "AFI06 FS-BE",
        n,
        "decrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete C(BasicHICBE2) Type-3 port",
        || {
            let mut cache = scheme.prepare_receiver_recipients(&recipients);
            scheme.add_receiver_context(&mut cache, receiver, &keys[receiver - 1]);
            scheme.decrypt_cached(receiver, &keys[receiver - 1], &cache, &time, &ciphertext)
        },
    );
}

fn benchmark_selvi09(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0x5E1F_0900 + n as u64);
    let scheme = Selvi09::setup(n, &mut rng);
    let sender = scheme.extract(b"cloud-model-provider");
    let recipients = (1..=n)
        .map(|i| scheme.extract(format!("edge-node-{i}").as_bytes()))
        .collect::<Vec<_>>();
    let public = recipients
        .iter()
        .map(|receiver| receiver.public.clone())
        .collect::<Vec<_>>();
    let receiver_position = n / 2 - 1;
    let enc_cache = scheme.prepare_encrypt_recipients(&public);
    let dec_cache = scheme.prepare_receiver(&public, receiver_position);
    let key = [0x09u8; 32];
    let ciphertext = scheme.signcrypt_cached(&sender, &enc_cache, &key, &mut rng);
    assert_eq!(
        scheme.designcrypt_cached(
            receiver_position,
            &recipients[receiver_position],
            &sender.public,
            &dec_cache,
            &ciphertext,
        ),
        Some(key)
    );
    add_measurement(
        results,
        "Selvi09 mIBSC",
        n,
        "encrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete equation-preserving Type-3 port",
        || scheme.signcrypt_cached(&sender, &enc_cache, &key, &mut rng),
    );
    add_measurement(
        results,
        "Selvi09 mIBSC",
        n,
        "decrypt_online_cached",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete equation-preserving Type-3 port",
        || {
            scheme.designcrypt_cached(
                receiver_position,
                &recipients[receiver_position],
                &sender.public,
                &dec_cache,
                &ciphertext,
            )
        },
    );
    add_measurement(
        results,
        "Selvi09 mIBSC",
        n,
        "encrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete equation-preserving Type-3 port",
        || {
            let cache = scheme.prepare_encrypt_recipients(&public);
            scheme.signcrypt_cached(&sender, &cache, &key, &mut rng)
        },
    );
    add_measurement(
        results,
        "Selvi09 mIBSC",
        n,
        "decrypt_full",
        samples,
        warmup,
        "BLS12-381 Type-3",
        "complete equation-preserving Type-3 port",
        || {
            let cache = scheme.prepare_receiver(&public, receiver_position);
            scheme.designcrypt_cached(
                receiver_position,
                &recipients[receiver_position],
                &sender.public,
                &cache,
                &ciphertext,
            )
        },
    );
}

fn benchmark_gao25(n: usize, samples: usize, warmup: usize, results: &mut Vec<BenchmarkResult>) {
    let mut rng = StdRng::seed_from_u64(0x6A0_2500 + n as u64);
    let scheme = Gao25::setup(n, &mut rng);
    let sender = scheme.register(b"cloud-model-provider", &mut rng);
    let recipients = (1..=n)
        .map(|i| scheme.register(format!("edge-node-{i}").as_bytes(), &mut rng))
        .collect::<Vec<_>>();
    let public = recipients
        .iter()
        .map(|user| user.public.clone())
        .collect::<Vec<_>>();
    let receiver_position = n / 2 - 1;
    let signcrypt_cache = scheme.prepare_signcrypt(&sender.public, &public);
    let key = [0x25u8; 32];
    let ciphertext = scheme.signcrypt_cached(&sender, &signcrypt_cache, &key, &mut rng);
    let receiver_cache = scheme.prepare_receiver(&recipients[receiver_position].public, n + 1);
    assert_eq!(
        scheme.unsigncrypt_cached(
            &recipients[receiver_position],
            &sender.public,
            &receiver_cache,
            &ciphertext,
        ),
        Some(key)
    );

    let authorized_count = n / 2;
    let authorized = &public[..authorized_count];
    let revocation_cache = scheme.prepare_revocation(&signcrypt_cache, authorized);
    let reduced = scheme.revoke_cached(&ciphertext, &revocation_cache);
    let reduced_receiver_cache =
        scheme.prepare_receiver(&recipients[receiver_position].public, authorized_count);
    assert_eq!(
        scheme.unsigncrypt_cached(
            &recipients[receiver_position],
            &sender.public,
            &reduced_receiver_cache,
            &reduced,
        ),
        Some(key)
    );
    assert_eq!(
        scheme.unsigncrypt(&recipients[n - 1], &sender.public, &reduced),
        None
    );

    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "encrypt_online_cached",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || scheme.signcrypt_cached(&sender, &signcrypt_cache, &key, &mut rng),
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "encrypt_full",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || scheme.signcrypt(&sender, &public, &key, &mut rng),
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "decrypt_online_cached",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || {
            scheme.unsigncrypt_cached(
                &recipients[receiver_position],
                &sender.public,
                &receiver_cache,
                &ciphertext,
            )
        },
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "decrypt_full",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || scheme.unsigncrypt(&recipients[receiver_position], &sender.public, &ciphertext),
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "revoke_50pct_online_cached",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction; precomputed linear transform",
        || scheme.revoke_cached(&ciphertext, &revocation_cache),
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "revoke_50pct_full",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || scheme.revoke(&ciphertext, &signcrypt_cache, authorized),
    );
    add_measurement(
        results,
        "Gao25 RCB-BSC",
        n,
        "decrypt_after_50pct_revocation",
        samples,
        warmup,
        "P-256",
        "complete Section 4 construction",
        || {
            scheme.unsigncrypt_cached(
                &recipients[receiver_position],
                &sender.public,
                &reduced_receiver_cache,
                &reduced,
            )
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn add_measurement<T>(
    results: &mut Vec<BenchmarkResult>,
    scheme: &'static str,
    group_size: usize,
    phase: &'static str,
    samples: usize,
    warmup: usize,
    backend: &'static str,
    implementation_scope: &'static str,
    mut operation: impl FnMut() -> T,
) {
    for _ in 0..warmup {
        let _ = black_box(operation());
    }
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let output = operation();
        let elapsed = start.elapsed().as_secs_f64() * 1_000.0;
        let _ = black_box(output);
        values.push(elapsed);
    }
    values.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    };
    let p95_index = ((values.len() as f64 * 0.95).ceil() as usize - 1).min(values.len() - 1);
    let result = BenchmarkResult {
        scheme,
        group_size,
        phase,
        median_ms: median,
        mean_ms: mean,
        stddev_ms: variance.sqrt(),
        p95_ms: values[p95_index],
        min_ms: values[0],
        max_ms: values[values.len() - 1],
        samples,
        backend,
        implementation_scope,
    };
    println!(
        "  {:<24} median {:>9.3} ms  p95 {:>9.3} ms",
        phase, result.median_ms, result.p95_ms
    );
    results.push(result);
}

fn parse_options() -> Options {
    let mut sizes = vec![16, 32, 64, 128, 256];
    let mut samples = 15;
    let mut warmup = 3;
    let mut output = PathBuf::from("results");
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sizes" => {
                i += 1;
                sizes = args[i]
                    .split(',')
                    .map(|value| value.parse().expect("invalid group size"))
                    .collect();
            }
            "--samples" => {
                i += 1;
                samples = args[i].parse().expect("invalid sample count");
            }
            "--warmup" => {
                i += 1;
                warmup = args[i].parse().expect("invalid warmup count");
            }
            "--output" => {
                i += 1;
                output = PathBuf::from(&args[i]);
            }
            unknown => panic!("unknown argument: {unknown}"),
        }
        i += 1;
    }
    assert!(samples > 0);
    Options {
        sizes,
        samples,
        warmup,
        output,
    }
}

fn write_results(options: &Options, results: &[BenchmarkResult]) -> std::io::Result<()> {
    fs::create_dir_all(&options.output)?;
    serde_json::to_writer_pretty(
        BufWriter::new(File::create(options.output.join("benchmark_results.json"))?),
        results,
    )?;
    let mut csv = BufWriter::new(File::create(options.output.join("benchmark_results.csv"))?);
    writeln!(csv, "scheme,group_size,phase,median_ms,mean_ms,stddev_ms,p95_ms,min_ms,max_ms,samples,backend,implementation_scope")?;
    for result in results {
        writeln!(
            csv,
            "\"{}\",{},\"{}\",{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},\"{}\",\"{}\"",
            result.scheme,
            result.group_size,
            result.phase,
            result.median_ms,
            result.mean_ms,
            result.stddev_ms,
            result.p95_ms,
            result.min_ms,
            result.max_ms,
            result.samples,
            result.backend,
            result.implementation_scope,
        )?;
    }
    write_summary(&options.output, results)?;
    let environment = Environment {
        os: env::consts::OS,
        arch: env::consts::ARCH,
        cpu: env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".to_string()),
        logical_cpus: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        rustc: rustc_version(),
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        sizes: options.sizes.clone(),
        samples: options.samples,
        warmup: options.warmup,
    };
    serde_json::to_writer_pretty(
        BufWriter::new(File::create(options.output.join("environment.json"))?),
        &environment,
    )?;
    Ok(())
}

fn write_summary(output: &Path, results: &[BenchmarkResult]) -> std::io::Result<()> {
    let mut file = BufWriter::new(File::create(output.join("summary.md"))?);
    writeln!(file, "# Six-scheme benchmark summary")?;
    writeln!(file)?;
    writeln!(file, "Medians in milliseconds. `full` includes recipient-set processing; `online` reuses a stable-set cache.")?;
    writeln!(file)?;
    writeln!(
        file,
        "| Scheme | Group | Encrypt full | Decrypt full | Encrypt online | Decrypt online |"
    )?;
    writeln!(file, "|---|---:|---:|---:|---:|---:|")?;
    let schemes = [
        "FS-DBS (ours)",
        "KMW23 DBE",
        "Lee25 CCA-DBE",
        "AFI06 FS-BE",
        "Selvi09 mIBSC",
        "Gao25 RCB-BSC",
    ];
    let mut sizes = results.iter().map(|r| r.group_size).collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    for size in sizes {
        for scheme in schemes {
            writeln!(
                file,
                "| {scheme} | {size} | {} | {} | {} | {} |",
                metric(results, scheme, size, "encrypt_full"),
                metric(results, scheme, size, "decrypt_full"),
                metric(results, scheme, size, "encrypt_online_cached"),
                metric(results, scheme, size, "decrypt_online_cached"),
            )?;
        }
    }
    writeln!(file)?;
    writeln!(file, "## Gao25 revocation")?;
    writeln!(file)?;
    writeln!(
        file,
        "The authorized set contains half of the original receivers."
    )?;
    writeln!(file)?;
    writeln!(
        file,
        "| Group | Revoke full | Revoke online | Decrypt after revocation |"
    )?;
    writeln!(file, "|---:|---:|---:|---:|")?;
    let mut sizes = results.iter().map(|r| r.group_size).collect::<Vec<_>>();
    sizes.sort_unstable();
    sizes.dedup();
    for size in sizes {
        writeln!(
            file,
            "| {} | {} | {} | {} |",
            size,
            metric(results, "Gao25 RCB-BSC", size, "revoke_50pct_full"),
            metric(results, "Gao25 RCB-BSC", size, "revoke_50pct_online_cached"),
            metric(
                results,
                "Gao25 RCB-BSC",
                size,
                "decrypt_after_50pct_revocation"
            ),
        )?;
    }
    writeln!(file)?;
    writeln!(file, "Gao25 implements the full Section 4 RCB-BSC construction over P-256, including certificate issuance, revocation, and signature verification.")?;
    Ok(())
}

fn metric(results: &[BenchmarkResult], scheme: &str, size: usize, phase: &str) -> String {
    results
        .iter()
        .find(|r| r.scheme == scheme && r.group_size == size && r.phase == phase)
        .map(|r| format!("{:.3}", r.median_ms))
        .unwrap_or_else(|| "--".to_string())
}

fn rustc_version() -> String {
    option_env!("RUSTC_VERSION")
        .unwrap_or("rustc 1.91.0 (recorded by build host)")
        .to_string()
}
