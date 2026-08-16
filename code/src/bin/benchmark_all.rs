use ed25519_dalek::{Signer, SigningKey, Verifier};
use fs_dbs_bench::{
    afi06::ForwardSecureState as AfiSecretKey,
    afi06_adapter::{Afi06Adapter, Afi06PublicKey},
    benchmark::{measure, write_raw_csv, write_summary_csv, BenchmarkOptions, Measurement},
    common::encode_indices,
    environment::{write_environment, EnvironmentRecord},
    fs_dbs::{Ciphertext, EvolvingKey, UserPublicKey},
    fs_dbs_adapter::FsDbsAdapter,
    gao25_adapter::{Gao25Adapter, Gao25PublicKey, Gao25SecretKey},
    kmw23::{UserPublicKey as KmwPublicKey, UserSecretKey as KmwSecretKey},
    kmw23_adapter::Kmw23Adapter,
    lee25::{Lee25SsPublicKey, Lee25SsSecretKey},
    lee25_ss_adapter::Lee25SsAdapter,
    li17_adapter::{Li17Adapter, Li17PublicKey, Li17SecretKey},
    model_distribution::{
        decrypt_model, encrypt_model, nonce_from_counter, sha256, update_manifest,
    },
    scheme_adapter::{FeatureSupport, SchemeAdapter, SchemeCapabilities, SetupParameters},
    selvi09_adapter::{Selvi09Adapter, Selvi09PublicKey, Selvi09SecretKey},
    zhang23_adapter::{Zhang23Adapter, Zhang23PublicKey, Zhang23SecretKey},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env,
    error::Error,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
};

struct Cli {
    scheme: String,
    figure: Option<u8>,
    repetitions: usize,
    warmup: usize,
    inner_iterations: usize,
    receiver_sizes: Vec<usize>,
    max_users: usize,
    tree_depth: usize,
    tree_depths: Vec<usize>,
    seed: u64,
    model_path: Option<PathBuf>,
    comparison_results: PathBuf,
    output: PathBuf,
    no_plots: bool,
}

struct FsFixture {
    adapter: FsDbsAdapter,
    sender_public: UserPublicKey,
    sender_secret: EvolvingKey,
    public_keys: Vec<UserPublicKey>,
    receiver_secret: EvolvingKey,
}

struct KmwFixture {
    adapter: Kmw23Adapter,
    public_keys: Vec<KmwPublicKey>,
    receiver_secret: KmwSecretKey,
}

struct AfiFixture {
    adapter: Afi06Adapter,
    public_keys: Vec<Afi06PublicKey>,
    receiver_secret: AfiSecretKey,
}

struct LeeSsFixture {
    adapter: Lee25SsAdapter,
    public_keys: Vec<Lee25SsPublicKey>,
    receiver_secret: Lee25SsSecretKey,
}

struct SelviFixture {
    adapter: Selvi09Adapter,
    sender_public: Selvi09PublicKey,
    sender_secret: Selvi09SecretKey,
    public_keys: Vec<Selvi09PublicKey>,
    receiver_secret: Selvi09SecretKey,
}

struct GaoFixture {
    adapter: Gao25Adapter,
    sender_public: Gao25PublicKey,
    sender_secret: Gao25SecretKey,
    public_keys: Vec<Gao25PublicKey>,
    receiver_secret: Gao25SecretKey,
}

struct Li17Fixture {
    adapter: Li17Adapter,
    sender_public: Li17PublicKey,
    sender_secret: Li17SecretKey,
    public_keys: Vec<Li17PublicKey>,
    receiver_secret: Li17SecretKey,
}

struct Zhang23Fixture {
    adapter: Zhang23Adapter,
    sender_public: Zhang23PublicKey,
    sender_secret: Zhang23SecretKey,
    secret_keys: Vec<Zhang23SecretKey>,
    receiver_secret: Zhang23SecretKey,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_cli()?;
    fs::create_dir_all(cli.output.join("raw"))?;
    fs::create_dir_all(cli.output.join("summary"))?;
    write_environment(
        &cli.output.join("environment.txt"),
        &EnvironmentRecord {
            seed: cli.seed,
            warmup: cli.warmup,
            repetitions: cli.repetitions,
            inner_iterations: cli.inner_iterations,
        },
    )?;
    write_security_features(&cli.output.join("summary/table_security_features.csv"))?;
    write_operation_counts(&cli.output.join("summary/table_operation_counts.csv"))?;

    if cli.figure == Some(6) {
        let model_path = cli
            .model_path
            .as_deref()
            .filter(|path| path.is_file())
            .ok_or("ResNet-50 model file not found")?;
        run_model_distribution_experiment(&cli, model_path)?;
        if !cli.no_plots {
            run_plots(&cli)?;
        }
        println!("Benchmark artifacts written under {}", cli.output.display());
        return Ok(());
    }

    match cli.scheme.as_str() {
        "FS-DBS" => {
            let run_depth_figures = cli.figure.is_none() || matches!(cli.figure, Some(3) | Some(5));
            if run_depth_figures {
                run_depth_experiments(&cli)?;
            }
            let run_receiver_figures =
                cli.figure.is_none() || matches!(cli.figure, Some(1) | Some(2) | Some(4));
            if run_receiver_figures {
                run_receiver_experiments(&cli)?;
            }
        }
        "KMW23" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("KMW23 does not support KeyUpdate or evolving-key storage".into());
            }
            run_kmw_receiver_experiments(&cli)?;
        }
        "AFI06" => {
            let run_depth_figures = cli.figure.is_none() || matches!(cli.figure, Some(3) | Some(5));
            if run_depth_figures {
                run_afi_depth_experiments(&cli)?;
            }
            let run_receiver_figures =
                cli.figure.is_none() || matches!(cli.figure, Some(1) | Some(2) | Some(4));
            if run_receiver_figures {
                run_afi_receiver_experiments(&cli)?;
            }
        }
        "Lee25-SS" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("Lee25-SS does not support KeyUpdate or evolving-key storage".into());
            }
            run_lee_ss_receiver_experiments(&cli)?;
        }
        "Selvi09" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("Selvi09 does not support KeyUpdate or evolving-key storage".into());
            }
            run_selvi_receiver_experiments(&cli)?;
        }
        "Gao25" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("Gao25 does not support KeyUpdate or evolving-key storage".into());
            }
            run_gao_receiver_experiments(&cli)?;
        }
        "Li17-AAGKA" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("Li17-AAGKA does not expose time-key evolution".into());
            }
            run_li17_receiver_experiments(&cli)?;
        }
        "Zhang23-DAAGKA" => {
            if matches!(cli.figure, Some(3) | Some(5)) {
                return Err("Zhang23-DAAGKA does not expose time-key evolution".into());
            }
            run_zhang23_receiver_experiments(&cli)?;
        }
        _ => {
            return Err(format!(
                "scheme is not enabled in the audited harness: {}",
                cli.scheme
            )
            .into())
        }
    }

    if !cli.no_plots {
        run_plots(&cli)?;
    }
    println!("Benchmark artifacts written under {}", cli.output.display());
    Ok(())
}

fn run_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set >= cli.max_users {
        return Err("max_users must be larger than every receiver set".into());
    }
    println!(
        "Preparing FS-DBS fixture: n={}, depth={}, receivers up to {} (setup excluded from timing)",
        cli.max_users, cli.tree_depth, largest_set
    );
    let fixture = build_fixture(cli.max_users, cli.tree_depth, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x42u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0xF1F1_0001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  FS-DBS receiver set {receiver_size}");
        let scheme = fixture.adapter.scheme();
        let time_cache = scheme.prepare_time(&fixture.sender_secret.node);
        let encrypt_cache = scheme.prepare_encrypt_recipients(&recipients, &fixture.public_keys);
        let mut decrypt_cache = scheme.prepare_receiver_recipients(&recipients);
        scheme.add_receiver_context(
            &mut decrypt_cache,
            1,
            &fixture.public_keys,
            &fixture.receiver_secret,
        );
        let verification_cache = scheme.prepare_verification(&fixture.sender_public);
        let ciphertext = scheme.signcrypt_cached(
            &fixture.sender_secret,
            &fixture.sender_public,
            &encrypt_cache,
            &time_cache,
            &message,
            &mut operation_rng,
        );
        let recovered = scheme.unsigncrypt_online(
            1,
            &fixture.receiver_secret,
            &fixture.sender_public,
            &decrypt_cache,
            &time_cache,
            &verification_cache,
            &ciphertext,
        );
        if recovered != Some(message) {
            return Err("FS-DBS correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "FS-DBS",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    scheme.signcrypt_cached(
                        &fixture.sender_secret,
                        &fixture.sender_public,
                        &encrypt_cache,
                        &time_cache,
                        &message,
                        &mut operation_rng,
                    )
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "FS-DBS",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = scheme
                        .unsigncrypt_online(
                            1,
                            &fixture.receiver_secret,
                            &fixture.sender_public,
                            &decrypt_cache,
                            &time_cache,
                            &verification_cache,
                            &ciphertext,
                        )
                        .expect("pre-validated FS-DBS unsigncryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            let storage = fixture
                .adapter
                .serialize_ciphertext(&ciphertext, &recipients)?;
            size_rows.push((receiver_size, storage));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "FS-DBS",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_kmw_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every KMW23 receiver slot".into());
    }
    println!(
        "Preparing KMW23 fixture: n={}, receivers up to {} (Setup/KeyGen excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_kmw_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x23u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x23DB_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  KMW23 receiver set {receiver_size}");
        let ciphertext = fixture.adapter.encrypt(
            &recipients,
            &fixture.public_keys,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.decrypt(
            1,
            &fixture.receiver_secret,
            &recipients,
            &fixture.public_keys,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("KMW23 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "KMW23",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .encrypt(
                            &recipients,
                            &fixture.public_keys,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated KMW23 encryption")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "KMW23",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .decrypt(
                            1,
                            &fixture.receiver_secret,
                            &recipients,
                            &fixture.public_keys,
                            &ciphertext,
                        )
                        .expect("pre-validated KMW23 decryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "KMW23",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_afi_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every AFI06 receiver slot".into());
    }
    println!(
        "Preparing AFI06 fixture: n={}, depth={}, receivers up to {} (Setup/Regist excluded from timing)",
        cli.max_users, cli.tree_depth, largest_set
    );
    let fixture = build_afi_fixture(cli.max_users, cli.tree_depth, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0xA6u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  AFI06 receiver set {receiver_size}");
        let ciphertext = fixture.adapter.encrypt(
            &recipients,
            &fixture.public_keys,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.decrypt(
            1,
            &fixture.receiver_secret,
            &recipients,
            &fixture.public_keys,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("AFI06 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "AFI06",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .encrypt(
                            &recipients,
                            &fixture.public_keys,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated AFI06 encryption")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "AFI06",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .decrypt(
                            1,
                            &fixture.receiver_secret,
                            &recipients,
                            &fixture.public_keys,
                            &ciphertext,
                        )
                        .expect("pre-validated AFI06 decryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "AFI06",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_lee_ss_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every Lee25-SS receiver slot".into());
    }
    println!(
        "Preparing Lee25-SS fixture: n={}, receivers up to {} (Setup/GenKey/IsValid excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_lee_ss_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x25u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x1EE2_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  Lee25-SS receiver set {receiver_size}");
        let ciphertext = fixture.adapter.encrypt(
            &recipients,
            &fixture.public_keys,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.decrypt(
            1,
            &fixture.receiver_secret,
            &recipients,
            &fixture.public_keys,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("Lee25-SS correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "Lee25-SS",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .encrypt(
                            &recipients,
                            &fixture.public_keys,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated Lee25-SS encryption")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "Lee25-SS",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .decrypt(
                            1,
                            &fixture.receiver_secret,
                            &recipients,
                            &fixture.public_keys,
                            &ciphertext,
                        )
                        .expect("pre-validated Lee25-SS decryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "Lee25-SS",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_li17_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every Li17 group member".into());
    }
    println!(
        "Preparing Li17 fixture: n={}, group sizes up to {} (Agreement and group key generation excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_li17_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x17u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut context_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_C001);
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  Li17 established group size {receiver_size}");
        let group = fixture.adapter.prepare_group(
            &recipients,
            &fixture.public_keys,
            1,
            &mut context_rng,
        )?;
        let ciphertext = fixture.adapter.signcrypt_prepared(
            &fixture.sender_secret,
            &fixture.sender_public,
            &group,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.unsigncrypt_prepared(
            1,
            &fixture.receiver_secret,
            &fixture.sender_public,
            &group,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("Li17 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "Li17-AAGKA",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .signcrypt_prepared(
                            &fixture.sender_secret,
                            &fixture.sender_public,
                            &group,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated Li17 Sign/Encrypt")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "Li17-AAGKA",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .unsigncrypt_prepared(
                            1,
                            &fixture.receiver_secret,
                            &fixture.sender_public,
                            &group,
                            &ciphertext,
                        )
                        .expect("pre-validated Li17 Decrypt/Verify");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "Li17-AAGKA",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_zhang23_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every Zhang23 group member".into());
    }
    println!(
        "Preparing Zhang23 fixture: n={}, group sizes up to {} (Agreement and group key generation excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_zhang23_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x23u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut context_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_C001);
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  Zhang23 established group size {receiver_size}");
        let group = fixture.adapter.prepare_group(
            &recipients,
            &fixture.secret_keys,
            1,
            &mut context_rng,
        )?;
        let ciphertext = fixture.adapter.signcrypt_prepared(
            &fixture.sender_secret,
            &fixture.sender_public,
            &group,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.unsigncrypt_prepared(
            1,
            &fixture.receiver_secret,
            &fixture.sender_public,
            &group,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("Zhang23 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "Zhang23-DAAGKA",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .signcrypt_prepared(
                            &fixture.sender_secret,
                            &fixture.sender_public,
                            &group,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated Zhang23 Sign/Encrypt")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "Zhang23-DAAGKA",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .unsigncrypt_prepared(
                            1,
                            &fixture.receiver_secret,
                            &fixture.sender_public,
                            &group,
                            &ciphertext,
                        )
                        .expect("pre-validated Zhang23 Decrypt/Verify");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "Zhang23-DAAGKA",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_selvi_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every Selvi09 receiver slot".into());
    }
    println!(
        "Preparing Selvi09 fixture: n={}, receivers up to {} (Setup/Extract excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_selvi_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x09u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x5E1F_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  Selvi09 receiver set {receiver_size}");
        let ciphertext = fixture.adapter.signcrypt(
            &fixture.sender_secret,
            &fixture.sender_public,
            &recipients,
            &fixture.public_keys,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.unsigncrypt(
            1,
            &fixture.receiver_secret,
            &fixture.sender_public,
            &recipients,
            &fixture.public_keys,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("Selvi09 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "Selvi09",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .signcrypt(
                            &fixture.sender_secret,
                            &fixture.sender_public,
                            &recipients,
                            &fixture.public_keys,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated Selvi09 signcryption")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "Selvi09",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .unsigncrypt(
                            1,
                            &fixture.receiver_secret,
                            &fixture.sender_public,
                            &recipients,
                            &fixture.public_keys,
                            &ciphertext,
                        )
                        .expect("pre-validated Selvi09 designcryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "Selvi09",
            &size_rows,
        )?;
    }
    Ok(())
}

fn run_gao_receiver_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let largest_set = *cli
        .receiver_sizes
        .iter()
        .max()
        .ok_or("empty receiver sizes")?;
    if largest_set > cli.max_users {
        return Err("max_users must cover every Gao25 receiver slot".into());
    }
    println!(
        "Preparing Gao25 fixture: n={}, receivers up to {} (Setup/SV/Cert excluded from timing)",
        cli.max_users, largest_set
    );
    let fixture = build_gao_fixture(cli.max_users, largest_set, cli.seed)?;
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let message = [0x25u8; 32];
    let mut encryption = Vec::new();
    let mut decryption = Vec::new();
    let mut size_rows = Vec::new();
    let mut operation_rng = StdRng::seed_from_u64(cli.seed ^ 0x6A02_E001);

    for &receiver_size in &cli.receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        println!("  Gao25 receiver set {receiver_size}");
        let ciphertext = fixture.adapter.signcrypt(
            &fixture.sender_secret,
            &fixture.sender_public,
            &recipients,
            &fixture.public_keys,
            &message,
            &mut operation_rng,
        )?;
        let recovered = fixture.adapter.unsigncrypt(
            1,
            &fixture.receiver_secret,
            &fixture.sender_public,
            &recipients,
            &fixture.public_keys,
            &ciphertext,
        )?;
        if recovered != message {
            return Err("Gao25 correctness check failed before timing".into());
        }

        if cli.figure.is_none() || cli.figure == Some(1) {
            encryption.push(measure(
                "Gao25",
                "Encryption / Signcryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    fixture
                        .adapter
                        .signcrypt(
                            &fixture.sender_secret,
                            &fixture.sender_public,
                            &recipients,
                            &fixture.public_keys,
                            &message,
                            &mut operation_rng,
                        )
                        .expect("pre-validated Gao25 signcryption")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(2) {
            decryption.push(measure(
                "Gao25",
                "Decryption / Unsigncryption",
                "receiver_size",
                receiver_size,
                options,
                || {
                    let plaintext = fixture
                        .adapter
                        .unsigncrypt(
                            1,
                            &fixture.receiver_secret,
                            &fixture.sender_public,
                            &recipients,
                            &fixture.public_keys,
                            &ciphertext,
                        )
                        .expect("pre-validated Gao25 unsigncryption");
                    assert_eq!(plaintext, message);
                    plaintext
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(4) {
            size_rows.push((
                receiver_size,
                fixture
                    .adapter
                    .serialize_ciphertext(&ciphertext, &recipients)?,
            ));
        }
    }

    if !encryption.is_empty() {
        write_measurement_pair(&cli.output, "figure1_encrypt_time", &encryption)?;
    }
    if !decryption.is_empty() {
        write_measurement_pair(&cli.output, "figure2_decrypt_time", &decryption)?;
    }
    if !size_rows.is_empty() {
        write_ciphertext_sizes(
            &cli.output.join("summary/figure4_ciphertext_size.csv"),
            "Gao25",
            &size_rows,
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct ReceiverTimingRow {
    scheme: String,
    axis_value: usize,
    median_ms: f64,
}

#[derive(Deserialize)]
struct UpdateTimingRow {
    scheme: String,
    tree_depth: usize,
    median_ms: f64,
}

struct ApplicationCost {
    scheme: String,
    encrypt_ms: f64,
    decrypt_ms: f64,
    update_ms: f64,
    signature_ms: f64,
    verification_ms: f64,
}

fn run_model_distribution_experiment(cli: &Cli, model_path: &Path) -> Result<(), Box<dyn Error>> {
    const MIN_MODEL_BYTES: usize = 50 * 1024 * 1024;
    const RECEIVER_COUNT: usize = 100;
    const TREE_DEPTH: usize = 20;

    let model = fs::read(model_path)?;
    if model.len() < MIN_MODEL_BYTES {
        return Err(format!(
            "ResNet-50 model file is unexpectedly small: {} bytes (minimum {})",
            model.len(),
            MIN_MODEL_BYTES
        )
        .into());
    }
    let timing_dir = cli.comparison_results.join("summary");
    let encryption =
        load_receiver_medians(&timing_dir.join("figure1_encrypt_time.csv"), RECEIVER_COUNT)?;
    let decryption =
        load_receiver_medians(&timing_dir.join("figure2_decrypt_time.csv"), RECEIVER_COUNT)?;
    let updates = load_update_medians(&timing_dir.join("figure3_update_time.csv"), TREE_DEPTH)?;

    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0xA350_6001);
    let mut content_key = [0u8; 32];
    rng.fill_bytes(&mut content_key);
    let receiver_set = (1..=RECEIVER_COUNT).collect::<Vec<_>>();
    let receiver_set_id = sha256(&encode_indices(&receiver_set));
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(b"resnet50-pretrained");
    associated_data.extend_from_slice(&1u64.to_le_bytes());
    associated_data.extend_from_slice(&receiver_set_id);
    associated_data.extend_from_slice(b"cloud-model-provider");

    let reference_nonce = nonce_from_counter(0);
    let encrypted_model = encrypt_model(&content_key, &reference_nonce, &model, &associated_data)
        .expect("validated AES-256-GCM inputs");
    let recovered_model = decrypt_model(
        &content_key,
        &reference_nonce,
        &encrypted_model,
        &associated_data,
    )
    .expect("fresh AES-256-GCM ciphertext must decrypt");
    if recovered_model != model {
        return Err("AES-256-GCM model round trip failed".into());
    }
    drop(recovered_model);

    let mut nonce_counter = 1u128;
    let aes_encrypt = measure(
        "Application",
        "AES-256-GCM Encryption",
        "model_size_bytes",
        model.len(),
        options,
        || {
            let nonce = nonce_from_counter(nonce_counter);
            nonce_counter += 1;
            encrypt_model(&content_key, &nonce, &model, &associated_data)
                .expect("unique nonce and in-memory model")
        },
    );
    let aes_decrypt = measure(
        "Application",
        "AES-256-GCM Decryption",
        "model_size_bytes",
        model.len(),
        options,
        || {
            decrypt_model(
                &content_key,
                &reference_nonce,
                &encrypted_model,
                &associated_data,
            )
            .expect("pre-validated in-memory model ciphertext")
        },
    );

    let encrypted_model_hash = sha256(&encrypted_model);
    let header_hash = sha256(b"representative-broadcast-header");
    let manifest = update_manifest(
        b"resnet50-pretrained",
        1,
        &receiver_set_id,
        &encrypted_model_hash,
        &header_hash,
    );
    let mut signing_seed = [0u8; 32];
    rng.fill_bytes(&mut signing_seed);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();
    let reference_signature = signing_key.sign(&manifest);
    verifying_key.verify(&manifest, &reference_signature)?;
    let ed25519_sign = measure(
        "Application",
        "Ed25519 Sign",
        "manifest_bytes",
        manifest.len(),
        options,
        || signing_key.sign(&manifest),
    );
    let ed25519_verify = measure(
        "Application",
        "Ed25519 Verify",
        "manifest_bytes",
        manifest.len(),
        options,
        || {
            verifying_key
                .verify(&manifest, &reference_signature)
                .expect("pre-validated Ed25519 manifest signature")
        },
    );

    let components = vec![aes_encrypt, aes_decrypt, ed25519_sign, ed25519_verify];
    write_measurement_pair(&cli.output, "figure6_component_times", &components)?;
    write_model_record(
        &cli.output.join("model_artifact.txt"),
        model_path,
        &model,
        encrypted_model.len(),
    )?;

    let external_sign_ms = components[2].summary.median_ms;
    let external_verify_ms = components[3].summary.median_ms;
    let mut costs = Vec::new();
    for scheme in [
        "FS-DBS",
        "KMW23",
        "AFI06",
        "Lee25-SS",
        "Li17-AAGKA",
        "Zhang23-DAAGKA",
    ] {
        let external_auth = matches!(scheme, "KMW23" | "AFI06" | "Lee25-SS");
        costs.push(ApplicationCost {
            scheme: scheme.to_owned(),
            encrypt_ms: required_median(&encryption, scheme, "encryption")?,
            decrypt_ms: required_median(&decryption, scheme, "decryption")?,
            update_ms: updates.get(scheme).copied().unwrap_or(0.0),
            signature_ms: external_auth.then_some(external_sign_ms).unwrap_or(0.0),
            verification_ms: external_auth.then_some(external_verify_ms).unwrap_or(0.0),
        });
    }
    write_model_update_results(
        &cli.output.join("summary/figure6_model_update.csv"),
        &cli.output
            .join("summary/figure6_model_update_end_to_end.csv"),
        &costs,
        components[0].summary.median_ms,
        components[1].summary.median_ms,
    )?;
    Ok(())
}

fn load_receiver_medians(
    path: &Path,
    receiver_count: usize,
) -> Result<HashMap<String, f64>, Box<dyn Error>> {
    let mut medians = HashMap::new();
    for row in csv::Reader::from_path(path)?.deserialize::<ReceiverTimingRow>() {
        let row = row?;
        if row.axis_value == receiver_count {
            medians.insert(row.scheme, row.median_ms);
        }
    }
    Ok(medians)
}

fn load_update_medians(
    path: &Path,
    tree_depth: usize,
) -> Result<HashMap<String, f64>, Box<dyn Error>> {
    let mut medians = HashMap::new();
    for row in csv::Reader::from_path(path)?.deserialize::<UpdateTimingRow>() {
        let row = row?;
        if row.tree_depth == tree_depth {
            medians.insert(row.scheme, row.median_ms);
        }
    }
    Ok(medians)
}

fn required_median(
    values: &HashMap<String, f64>,
    scheme: &str,
    operation: &str,
) -> Result<f64, Box<dyn Error>> {
    values
        .get(scheme)
        .copied()
        .ok_or_else(|| format!("missing {operation} median for {scheme}").into())
}

fn write_model_record(
    path: &Path,
    model_path: &Path,
    model: &[u8],
    encrypted_bytes: usize,
) -> std::io::Result<()> {
    let mut writer = create_writer(path)?;
    writeln!(writer, "Model path: {}", model_path.display())?;
    writeln!(writer, "Model bytes: {}", model.len())?;
    writeln!(writer, "Encrypted bytes: {encrypted_bytes}")?;
    writeln!(writer, "SHA-256: {}", hex_encode(&sha256(model)))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_model_update_results(
    security_path: &Path,
    end_to_end_path: &Path,
    costs: &[ApplicationCost],
    aes_encrypt_ms: f64,
    aes_decrypt_ms: f64,
) -> std::io::Result<()> {
    let mut security = create_writer(security_path)?;
    let mut end_to_end = create_writer(end_to_end_path)?;
    writeln!(security, "scheme,periods,scheme_encrypt_ms,scheme_decrypt_ms,key_update_ms,signature_ms,verification_ms,aes_encrypt_ms,aes_decrypt_ms,per_period_security_layer_ms,per_period_end_to_end_ms,cumulative_security_layer_ms,cumulative_security_layer_s,cumulative_end_to_end_processing_ms,cumulative_end_to_end_processing_s")?;
    writeln!(
        end_to_end,
        "scheme,periods,cumulative_end_to_end_processing_ms,cumulative_end_to_end_processing_s"
    )?;
    for cost in costs {
        let per_security = cost.encrypt_ms
            + cost.decrypt_ms
            + cost.update_ms
            + cost.signature_ms
            + cost.verification_ms;
        let per_end_to_end = per_security + aes_encrypt_ms + aes_decrypt_ms;
        for periods in [1usize, 5, 10, 20, 50, 100] {
            let cumulative_security = per_security * periods as f64;
            let cumulative_end_to_end = per_end_to_end * periods as f64;
            writeln!(
                security,
                "{},{},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9}",
                cost.scheme,
                periods,
                cost.encrypt_ms,
                cost.decrypt_ms,
                cost.update_ms,
                cost.signature_ms,
                cost.verification_ms,
                aes_encrypt_ms,
                aes_decrypt_ms,
                per_security,
                per_end_to_end,
                cumulative_security,
                cumulative_security / 1000.0,
                cumulative_end_to_end,
                cumulative_end_to_end / 1000.0,
            )?;
            writeln!(
                end_to_end,
                "{},{},{:.9},{:.9}",
                cost.scheme,
                periods,
                cumulative_end_to_end,
                cumulative_end_to_end / 1000.0,
            )?;
        }
    }
    Ok(())
}

fn run_afi_depth_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let mut updates = Vec::new();
    let mut secret_sizes = Vec::new();
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_F001);
    for &depth in &cli.tree_depths {
        println!("  AFI06 preorder update / root key storage at tree depth {depth}");
        let adapter = Afi06Adapter::setup(
            SetupParameters {
                max_users: cli.max_users,
                tree_depth: depth,
            },
            &mut rng,
        )?;
        let root = adapter.keygen(1, &mut rng)?.secret;
        if cli.figure.is_none() || cli.figure == Some(3) {
            updates.push(measure(
                "AFI06",
                "Root-level KeyUpdate",
                "tree_depth",
                depth,
                options,
                || {
                    adapter
                        .update(&root, 0, &mut rng)
                        .expect("pre-validated AFI06 preorder update")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(5) {
            secret_sizes.push((depth, adapter.serialize_secret_key(&root)?));
        }
    }
    if !updates.is_empty() {
        write_measurement_pair(&cli.output, "figure3_update_time", &updates)?;
        write_update_summary(
            &cli.output.join("summary/figure3_update_time.csv"),
            "AFI06",
            &updates,
        )?;
    }
    if !secret_sizes.is_empty() {
        write_secret_key_sizes(
            &cli.output.join("summary/figure5_secret_key_size.csv"),
            "AFI06",
            &secret_sizes,
        )?;
    }
    Ok(())
}

fn run_depth_experiments(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: cli.inner_iterations,
    };
    let mut updates = Vec::new();
    let mut secret_sizes = Vec::new();
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0xF3F5_0001);
    for &depth in &cli.tree_depths {
        println!("  FS-DBS root update / key storage at tree depth {depth}");
        let adapter = FsDbsAdapter::setup(
            SetupParameters {
                max_users: cli.max_users,
                tree_depth: depth,
            },
            &mut rng,
        )?;
        let root = adapter.join(1, &mut rng)?.secret;
        if cli.figure.is_none() || cli.figure == Some(3) {
            updates.push(measure(
                "FS-DBS",
                "Root-level KeyUpdate",
                "tree_depth",
                depth,
                options,
                || {
                    adapter
                        .update(&root, 1, &mut rng)
                        .expect("pre-validated FS-DBS root update")
                },
            ));
        }
        if cli.figure.is_none() || cli.figure == Some(5) {
            secret_sizes.push((depth, adapter.serialize_secret_key(&root)?));
        }
    }
    if !updates.is_empty() {
        write_measurement_pair(&cli.output, "figure3_update_time", &updates)?;
        write_update_summary(
            &cli.output.join("summary/figure3_update_time.csv"),
            "FS-DBS",
            &updates,
        )?;
    }
    if !secret_sizes.is_empty() {
        write_secret_key_sizes(
            &cli.output.join("summary/figure5_secret_key_size.csv"),
            "FS-DBS",
            &secret_sizes,
        )?;
    }
    Ok(())
}

fn build_fixture(
    max_users: usize,
    tree_depth: usize,
    largest_set: usize,
    seed: u64,
) -> Result<FsFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xF5DB_0001);
    let adapter = FsDbsAdapter::setup(
        SetupParameters {
            max_users,
            tree_depth,
        },
        &mut rng,
    )?;
    let mut public_keys = Vec::with_capacity(largest_set);
    let receiver = adapter.join(1, &mut rng)?;
    let mut receiver_secret = receiver.secret;
    public_keys.push(receiver.public);
    for identity in 2..=largest_set {
        public_keys.push(adapter.projected_public_key_for_benchmark(identity, 1, &mut rng));
        if identity % 100 == 0 || identity == largest_set {
            println!("    Public-key projection progress: {identity}/{largest_set}");
        }
    }
    let sender = adapter.join(max_users, &mut rng)?;
    let mut sender_secret = sender.secret;
    for level in 0..tree_depth {
        let child_bit = (level % 2) as u8;
        sender_secret = adapter.update(&sender_secret, child_bit, &mut rng)?;
        receiver_secret = adapter.update(&receiver_secret, child_bit, &mut rng)?;
    }
    Ok(FsFixture {
        adapter,
        sender_public: sender.public,
        sender_secret,
        public_keys,
        receiver_secret,
    })
}

fn build_kmw_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<KmwFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x23DB_0001);
    let adapter = Kmw23Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    KeyGen progress: {identity}/{largest_set} receiver public keys");
        }
    }
    Ok(KmwFixture {
        adapter,
        public_keys,
        receiver_secret: receiver_secret.ok_or("receiver set is empty")?,
    })
}

fn build_afi_fixture(
    max_users: usize,
    tree_depth: usize,
    largest_set: usize,
    seed: u64,
) -> Result<AfiFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xAF10_0001);
    let adapter = Afi06Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    Regist progress: {identity}/{largest_set} receiver keys");
        }
    }
    Ok(AfiFixture {
        adapter,
        public_keys,
        receiver_secret: receiver_secret.ok_or("receiver set is empty")?,
    })
}

fn build_lee_ss_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<LeeSsFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x1EE2_0001);
    let adapter = Lee25SsAdapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if !adapter.is_valid(&pair.public, &mut rng) {
            return Err(format!("Lee25-SS IsValid rejected generated slot {identity}").into());
        }
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    GenKey progress: {identity}/{largest_set} receiver public keys");
        }
    }
    Ok(LeeSsFixture {
        adapter,
        public_keys,
        receiver_secret: receiver_secret.ok_or("receiver set is empty")?,
    })
}

fn build_li17_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<Li17Fixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x1A17_0001);
    let adapter = Li17Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    Li17 Extract progress: {identity}/{largest_set} members");
        }
    }
    let sender = adapter.keygen(max_users + 1, &mut rng)?;
    Ok(Li17Fixture {
        adapter,
        sender_public: sender.public,
        sender_secret: sender.secret,
        public_keys,
        receiver_secret: receiver_secret.ok_or("Li17 group is empty")?,
    })
}

fn build_zhang23_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<Zhang23Fixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x2A23_0001);
    let adapter = Zhang23Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut secret_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        secret_keys.push(pair.secret);
        if identity % 100 == 0 || identity == largest_set {
            println!("    Zhang23 KeyGen progress: {identity}/{largest_set} members");
        }
    }
    let sender = adapter.keygen(max_users + 1, &mut rng)?;
    Ok(Zhang23Fixture {
        adapter,
        sender_public: sender.public,
        sender_secret: sender.secret,
        secret_keys,
        receiver_secret: receiver_secret.ok_or("Zhang23 group is empty")?,
    })
}

fn build_selvi_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<SelviFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5E1F_0001);
    let adapter = Selvi09Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.keygen(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    Extract progress: {identity}/{largest_set} receiver keys");
        }
    }
    let sender = adapter.keygen(max_users + 1, &mut rng)?;
    Ok(SelviFixture {
        adapter,
        sender_public: sender.public,
        sender_secret: sender.secret,
        public_keys,
        receiver_secret: receiver_secret.ok_or("receiver set is empty")?,
    })
}

fn build_gao_fixture(
    max_users: usize,
    largest_set: usize,
    seed: u64,
) -> Result<GaoFixture, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x6A02_0001);
    let adapter = Gao25Adapter::setup(
        SetupParameters {
            max_users,
            tree_depth: 0,
        },
        &mut rng,
    )?;
    let mut receiver_secret = None;
    let mut public_keys = Vec::with_capacity(largest_set);
    for identity in 1..=largest_set {
        let pair = adapter.join(identity, &mut rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
        if identity % 100 == 0 || identity == largest_set {
            println!("    SV/Cert progress: {identity}/{largest_set} receiver keys");
        }
    }
    let sender = adapter.join(max_users + 1, &mut rng)?;
    Ok(GaoFixture {
        adapter,
        sender_public: sender.public,
        sender_secret: sender.secret,
        public_keys,
        receiver_secret: receiver_secret.ok_or("receiver set is empty")?,
    })
}

fn write_measurement_pair(
    output: &Path,
    stem: &str,
    measurements: &[Measurement],
) -> std::io::Result<()> {
    write_raw_csv(&output.join(format!("raw/{stem}_raw.csv")), measurements)?;
    write_summary_csv(&output.join(format!("summary/{stem}.csv")), measurements)
}

fn write_ciphertext_sizes(
    path: &Path,
    scheme: &str,
    rows: &[(usize, fs_dbs_bench::scheme_adapter::CiphertextStorage)],
) -> std::io::Result<()> {
    let mut writer = create_writer(path)?;
    writeln!(writer, "scheme,receiver_size,cryptographic_ciphertext_bytes,recipient_metadata_bytes,total_wire_bytes")?;
    for (receiver_size, storage) in rows {
        writeln!(
            writer,
            "{},{},{},{},{}",
            scheme,
            receiver_size,
            storage.cryptographic_ciphertext_bytes,
            storage.recipient_metadata_bytes,
            storage.total_wire_bytes
        )?;
    }
    Ok(())
}

fn write_update_summary(
    path: &Path,
    scheme: &str,
    measurements: &[Measurement],
) -> std::io::Result<()> {
    let mut writer = create_writer(path)?;
    writeln!(writer, "scheme,tree_depth,samples,mean_ms,median_ms,stddev_ms,min_ms,max_ms,ci95_low_ms,ci95_high_ms,g1_scalar_multiplications,g2_scalar_multiplications,g1_group_additions,g2_group_additions,position")?;
    for measurement in measurements {
        let summary = measurement.summary;
        let depth = measurement.axis_value;
        if scheme == "FS-DBS" {
            writeln!(
                writer,
                "FS-DBS,{},{},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},0,{},{},{},root_to_child_1_worst_case",
                depth,
                measurement.samples_ms.len(),
                summary.mean_ms,
                summary.median_ms,
                summary.stddev_ms,
                summary.min_ms,
                summary.max_ms,
                summary.ci95_low_ms,
                summary.ci95_high_ms,
                depth + 4,
                0,
                depth + 4,
            )?;
        } else {
            writeln!(
                writer,
                "AFI06,{},{},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},2,{},2,{},preorder_root_to_left_child_with_right_sibling",
                depth,
                measurement.samples_ms.len(),
                summary.mean_ms,
                summary.median_ms,
                summary.stddev_ms,
                summary.min_ms,
                summary.max_ms,
                summary.ci95_low_ms,
                summary.ci95_high_ms,
                2 * depth + 6,
                2 * depth + 6,
            )?;
        }
    }
    Ok(())
}

fn write_secret_key_sizes(
    path: &Path,
    scheme: &str,
    rows: &[(usize, fs_dbs_bench::scheme_adapter::SecretKeyStorage)],
) -> std::io::Result<()> {
    let mut writer = create_writer(path)?;
    writeln!(writer, "scheme,tree_depth,serialized_bytes,number_of_G1_elements,number_of_G2_elements,number_of_Zp_elements,position")?;
    for (depth, storage) in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},root_z_0",
            scheme,
            depth,
            storage.serialized_bytes,
            storage.number_of_g1_elements,
            storage.number_of_g2_elements,
            storage.number_of_zp_elements,
        )?;
    }
    Ok(())
}

fn write_security_features(path: &Path) -> std::io::Result<()> {
    let rows = [
        (FsDbsAdapter::scheme_name(), FsDbsAdapter::capabilities()),
        (Kmw23Adapter::scheme_name(), Kmw23Adapter::capabilities()),
        (
            Lee25SsAdapter::scheme_name(),
            Lee25SsAdapter::capabilities(),
        ),
        (Afi06Adapter::scheme_name(), Afi06Adapter::capabilities()),
        (Li17Adapter::scheme_name(), Li17Adapter::capabilities()),
        (
            Zhang23Adapter::scheme_name(),
            Zhang23Adapter::capabilities(),
        ),
    ];
    let mut writer = create_writer(path)?;
    writeln!(writer, "Scheme,Distributed_KeyGen,Forward_Security,Broadcast_Encryption,Authentication,Signcryption,CCA,EUF_CMA,Constant_Ciphertext,Key_Update")?;
    for (name, capabilities) in rows {
        write_capability_row(&mut writer, name, &capabilities)?;
    }
    Ok(())
}

fn write_capability_row(
    writer: &mut BufWriter<File>,
    name: &str,
    capabilities: &SchemeCapabilities,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "{},{},{},{},{},{},{},{},{},{}",
        name,
        capabilities.distributed_keygen,
        capabilities.forward_security,
        capabilities.broadcast_encryption,
        capabilities.sender_authentication,
        capabilities.signcryption,
        capabilities.ind_cca,
        capabilities.euf_cma,
        capabilities.constant_ciphertext,
        capabilities.key_update,
    )
}

fn write_operation_counts(path: &Path) -> std::io::Result<()> {
    let mut writer = create_writer(path)?;
    writeln!(
        writer,
        "Scheme,Algorithm,E1,E2,ET,P,M1,M2,H,Counting_boundary,Source_mapping"
    )?;
    writeln!(writer, "FS-DBS,Encryption/Signcryption,3,4,1,0,0,4,2,online phase after recipient-set and time-node preparation,FS-DBS Construction: Signcrypt")?;
    writeln!(writer, "FS-DBS,Decryption/Unsigncryption,1,0,0,5,1,0,2,online phase after formula-level aggregation; one sender-static pairing excluded,FS-DBS Construction: Unsigncrypt")?;
    writeln!(writer, "FS-DBS,KeyUpdate,0,d+4,0,0,0,d+4,0,root z=0 to child bit 1 including time-base evaluation,FS-DBS Construction: KeyUpdate")?;
    writeln!(writer, "KMW23,Encryption/Signcryption,1,1,1,0,2|S|-1,0,1,full recipient aggregation plus 32-byte KEM projection,KMW23 Section 5.1 / Construction A.7 Encrypt")?;
    writeln!(writer, "KMW23,Decryption/Unsigncryption,0,0,0,2,2(|S|-1),0,1,full receiver cancellation plus KDF,KMW23 Section 5.1 / Construction A.7 Decrypt")?;
    writeln!(writer, "KMW23,KeyUpdate,N/A,N/A,N/A,N/A,N/A,N/A,N/A,unsupported by the source construction,KMW23 Section 5.1")?;
    writeln!(writer, "AFI06,Encryption/Signcryption,3,0,1,0,|S|,0,1,full recipient aggregation plus 32-byte KEM projection,AFI06 Section 4.2 BasicHICBE2 Encrypt")?;
    writeln!(writer, "AFI06,Decryption/Unsigncryption,0,0,0,3,0,|S|-1,1,full receiver cancellation plus KDF,AFI06 Section 4.2 BasicHICBE2 Decrypt")?;
    writeln!(writer, "AFI06,KeyUpdate,2,2d+6,0,0,2,2d+6,0,preorder root expansion retaining the right sibling,AFI06 Section 5 C(HICBE to FS-BE)")?;
    writeln!(writer, "Lee25-SS,Encryption/Signcryption,2,1,1,0,2|S|+1,0,2,source Encaps plus 32-byte KEM projection,Lee25 Section 4.1 DBE_SS Encaps")?;
    writeln!(writer, "Lee25-SS,Decryption/Unsigncryption,3,1,0,4,4|S|+3,1,2,ciphertext validity and randomized Decaps included,Lee25 Section 4.1 DBE_SS Decaps")?;
    writeln!(writer, "Lee25-SS,KeyUpdate,N/A,N/A,N/A,N/A,N/A,N/A,N/A,unsupported by the source construction,Lee25 Section 4.1")?;
    writeln!(writer, "Li17-AAGKA,Encryption/Signcryption,4,0,1,0,1,0,2,complete online Sign/Encrypt after Agreement and Enc.KeyGen,Li and Zhang Information Sciences 414 Section 4.1")?;
    writeln!(writer, "Li17-AAGKA,Decryption/Unsigncryption,1,0,0,4,1,0,2,complete online Decrypt/Verify after member Dec.KeyGen,Li and Zhang Information Sciences 414 Section 4.1")?;
    writeln!(writer, "Li17-AAGKA,KeyUpdate,N/A,N/A,N/A,N/A,N/A,N/A,N/A,group membership refresh is not time-key evolution,Li and Zhang Information Sciences 414 Section 4.1")?;
    writeln!(writer, "Zhang23-DAAGKA,Encryption/Signcryption,2,2,1,0,0,0,2,complete online Sign/Encrypt after Agreement and Enc.KeyGen; concrete hash-to-G2 multiplication included,Zhang et al. IEEE TDSC 20(1) Section 5.2")?;
    writeln!(writer, "Zhang23-DAAGKA,Decryption/Unsigncryption,0,1,0,4,0,0,2,complete online Decrypt/Verify after member Dec.KeyGen; concrete hash-to-G2 multiplication included,Zhang et al. IEEE TDSC 20(1) Section 5.2")?;
    writeln!(writer, "Zhang23-DAAGKA,KeyUpdate,N/A,N/A,N/A,N/A,N/A,N/A,N/A,Join and Leave refresh group keys but are not time-key evolution,Zhang et al. IEEE TDSC 20(1) Section 5.2")?;
    Ok(())
}

fn create_writer(path: &Path) -> std::io::Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(BufWriter::new(File::create(path)?))
}

fn run_plots(cli: &Cli) -> Result<(), Box<dyn Error>> {
    let figures = match cli.figure {
        Some(figure) => vec![figure],
        None if matches!(
            cli.scheme.as_str(),
            "KMW23" | "Lee25-SS" | "Selvi09" | "Gao25" | "Li17-AAGKA" | "Zhang23-DAAGKA"
        ) =>
        {
            vec![1, 2, 4]
        }
        None => vec![1, 2, 3, 4, 5],
    };
    for figure in figures {
        let script = format!("scripts/plot_fig{figure}.py");
        let status = Command::new("python")
            .args([
                &script,
                "--results",
                cli.output.to_string_lossy().as_ref(),
                "--figures",
                "figures",
            ])
            .status()?;
        if !status.success() {
            return Err(format!("plot script failed: {script}").into());
        }
    }
    Ok(())
}

fn parse_cli() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli {
        scheme: "FS-DBS".to_owned(),
        figure: None,
        repetitions: 100,
        warmup: 20,
        inner_iterations: 1,
        receiver_sizes: vec![10, 50, 100, 200, 500, 1000],
        max_users: 1024,
        tree_depth: 20,
        tree_depths: vec![8, 12, 16, 20, 24],
        seed: 2026_0810,
        model_path: None,
        comparison_results: PathBuf::from("results/comparison"),
        output: PathBuf::from("results"),
        no_plots: false,
    };
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--scheme" => {
                index += 1;
                cli.scheme = args.get(index).ok_or("missing --scheme value")?.to_owned();
            }
            "--fig" => {
                index += 1;
                cli.figure = Some(args.get(index).ok_or("missing --fig value")?.parse()?);
            }
            "--repetitions" => {
                index += 1;
                cli.repetitions = args
                    .get(index)
                    .ok_or("missing --repetitions value")?
                    .parse()?;
            }
            "--warmup" => {
                index += 1;
                cli.warmup = args.get(index).ok_or("missing --warmup value")?.parse()?;
            }
            "--inner_iterations" => {
                index += 1;
                cli.inner_iterations = args
                    .get(index)
                    .ok_or("missing --inner_iterations value")?
                    .parse()?;
            }
            "--receiver_sizes" => {
                index += 1;
                cli.receiver_sizes =
                    parse_list(args.get(index).ok_or("missing --receiver_sizes value")?)?;
            }
            "--max_users" => {
                index += 1;
                cli.max_users = args
                    .get(index)
                    .ok_or("missing --max_users value")?
                    .parse()?;
            }
            "--tree_depth" => {
                index += 1;
                cli.tree_depth = args
                    .get(index)
                    .ok_or("missing --tree_depth value")?
                    .parse()?;
            }
            "--tree_depths" => {
                index += 1;
                cli.tree_depths =
                    parse_list(args.get(index).ok_or("missing --tree_depths value")?)?;
            }
            "--model_path" => {
                index += 1;
                cli.model_path = Some(PathBuf::from(
                    args.get(index).ok_or("missing --model_path value")?,
                ));
            }
            "--comparison_results" => {
                index += 1;
                cli.comparison_results = PathBuf::from(
                    args.get(index)
                        .ok_or("missing --comparison_results value")?,
                );
            }
            "--seed" => {
                index += 1;
                cli.seed = args.get(index).ok_or("missing --seed value")?.parse()?;
            }
            "--output" => {
                index += 1;
                cli.output = PathBuf::from(args.get(index).ok_or("missing --output value")?);
            }
            "--no_plots" => cli.no_plots = true,
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
        index += 1;
    }
    if cli.repetitions < 2 {
        return Err("repetitions must be at least 2".into());
    }
    if cli.inner_iterations == 0 {
        return Err("inner_iterations must be positive".into());
    }
    if cli.figure.is_some_and(|figure| !(1..=6).contains(&figure)) {
        return Err("figure must be in 1..=6".into());
    }
    Ok(cli)
}

fn parse_list(value: &str) -> Result<Vec<usize>, Box<dyn Error>> {
    let parsed = value
        .split(',')
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() || parsed.contains(&0) {
        return Err("list values must be positive".into());
    }
    Ok(parsed)
}

#[allow(dead_code)]
fn _assert_ciphertext_is_clone(_: &Ciphertext) {}

#[allow(dead_code)]
fn _feature_support_is_csv_safe(_: FeatureSupport) {}
