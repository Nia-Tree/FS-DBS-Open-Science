use fs_dbs_bench::{
    afi06_adapter::Afi06Adapter,
    benchmark::{measure, write_raw_csv, write_summary_csv, BenchmarkOptions, Measurement},
    environment::{write_environment, EnvironmentRecord},
    fs_dbs_adapter::FsDbsAdapter,
    kmw23_adapter::Kmw23Adapter,
    lee25_ss_adapter::Lee25SsAdapter,
    li17_adapter::Li17Adapter,
    scheme_adapter::{SchemeAdapter, SetupParameters},
    zhang23_adapter::Zhang23Adapter,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    env,
    error::Error,
    fs::{self, File},
    hint::black_box,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const LOCAL_PATH: &str = "Epoch Local / Participant Path";
const LOCAL_CONTRIBUTION: &str = "Epoch Local / Agreement Contribution";
const LOCAL_FINALIZE: &str = "Epoch Local / Receiver Finalize";

struct Cli {
    epochs: usize,
    group_size: usize,
    max_users: usize,
    tree_depth: usize,
    repetitions: usize,
    warmup: usize,
    seed: u64,
    output: PathBuf,
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
            inner_iterations: 1,
        },
    )?;

    let options = BenchmarkOptions {
        warmup: cli.warmup,
        repetitions: cli.repetitions,
        inner_iterations: 1,
    };
    let mut measurements = Vec::new();
    benchmark_fs_dbs(&cli, options, &mut measurements)?;
    benchmark_afi06(&cli, options, &mut measurements)?;
    benchmark_kmw23(&cli, options, &mut measurements)?;
    benchmark_lee25(&cli, options, &mut measurements)?;
    benchmark_li17(&cli, options, &mut measurements)?;
    benchmark_zhang23(&cli, options, &mut measurements)?;

    write_raw_csv(
        &cli.output.join("raw/epoch_local_test_raw.csv"),
        &measurements,
    )?;
    write_summary_csv(
        &cli.output.join("summary/epoch_local_test.csv"),
        &measurements,
    )?;
    write_definitions(&cli.output.join("summary/epoch_local_test_definitions.csv"))?;
    write_scope(&cli.output.join("summary/epoch_local_test_scope.txt"), &cli)?;
    println!(
        "Local-participant test artifacts written under {}",
        cli.output.display()
    );
    Ok(())
}

fn benchmark_fs_dbs(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("FS-DBS: one sender state per epoch boundary");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_1001);
    let adapter = FsDbsAdapter::setup(parameters(cli), &mut setup_rng)?;
    let mut state = adapter.join(cli.max_users, &mut setup_rng)?.secret;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_1002);
    let mut advance_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_1003);
    for event in 1..=cli.epochs {
        measurements.push(measure(
            "FS-DBS",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || {
                adapter
                    .update(black_box(&state), 1, &mut timing_rng)
                    .unwrap()
            },
        ));
        state = adapter.update(&state, 1, &mut advance_rng)?;
    }
    Ok(())
}

fn benchmark_afi06(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("AFI06: one member state per epoch boundary");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_1001);
    let adapter = Afi06Adapter::setup(parameters(cli), &mut setup_rng)?;
    let mut state = adapter.keygen(1, &mut setup_rng)?.secret;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_1002);
    let mut advance_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_1003);
    for event in 1..=cli.epochs {
        measurements.push(measure(
            "AFI06",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || {
                adapter
                    .update(black_box(&state), 0, &mut timing_rng)
                    .unwrap()
            },
        ));
        state = adapter.update(&state, 0, &mut advance_rng)?;
    }
    Ok(())
}

fn benchmark_kmw23(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("KMW23: one user's fresh public/private key pair per epoch boundary");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0x23DB_1001);
    let adapter = Kmw23Adapter::setup(parameters(cli), &mut setup_rng)?;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0x23DB_1002);
    for event in 1..=cli.epochs {
        measurements.push(measure(
            "KMW23",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || adapter.keygen(1, &mut timing_rng).unwrap(),
        ));
    }
    Ok(())
}

fn benchmark_lee25(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Lee25-SS: one user's fresh public/private key pair per epoch boundary");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0x1EE2_1001);
    let adapter = Lee25SsAdapter::setup(parameters(cli), &mut setup_rng)?;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0x1EE2_1002);
    for event in 1..=cli.epochs {
        measurements.push(measure(
            "Lee25-SS",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || adapter.keygen(1, &mut timing_rng).unwrap(),
        ));
    }
    Ok(())
}

fn benchmark_li17(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Li17-AAGKA: one member contribution plus its receiver finalization");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_1001);
    let adapter = Li17Adapter::setup(parameters(cli), &mut setup_rng)?;
    let public_keys = (1..=cli.group_size)
        .map(|identity| {
            adapter
                .keygen(identity, &mut setup_rng)
                .map(|pair| pair.public)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let recipients = (1..=cli.group_size).collect::<Vec<_>>();
    let member = &public_keys[0];
    let mut epoch_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_1002);
    let mut contribution_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_1003);
    let mut combined_rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_1004);

    for event in 1..=cli.epochs {
        let epoch = adapter.prepare_epoch(&recipients, &public_keys, &mut epoch_rng)?;
        black_box(adapter.derive_local_receiver_context(&epoch, 1)?);
        measurements.push(measure(
            "Li17-AAGKA",
            LOCAL_CONTRIBUTION,
            "epoch_event",
            event,
            options,
            || adapter.create_local_agreement_contribution(member, &mut contribution_rng),
        ));
        measurements.push(measure(
            "Li17-AAGKA",
            LOCAL_FINALIZE,
            "epoch_event",
            event,
            options,
            || {
                adapter
                    .derive_local_receiver_context(black_box(&epoch), black_box(1))
                    .unwrap()
            },
        ));
        measurements.push(measure(
            "Li17-AAGKA",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || {
                let contribution =
                    adapter.create_local_agreement_contribution(member, &mut combined_rng);
                let receiver_context = adapter
                    .derive_local_receiver_context(black_box(&epoch), black_box(1))
                    .unwrap();
                (contribution, receiver_context)
            },
        ));
    }
    Ok(())
}

fn benchmark_zhang23(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Zhang23-DAAGKA: one member contribution plus its receiver finalization");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_1001);
    let adapter = Zhang23Adapter::setup(parameters(cli), &mut setup_rng)?;
    let secret_keys = (1..=cli.group_size)
        .map(|identity| {
            adapter
                .keygen(identity, &mut setup_rng)
                .map(|pair| pair.secret)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let recipients = (1..=cli.group_size).collect::<Vec<_>>();
    let member = &secret_keys[0];
    let mut epoch_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_1002);
    let mut contribution_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_1003);
    let mut combined_rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_1004);

    for event in 1..=cli.epochs {
        let epoch = adapter.prepare_epoch(&recipients, &secret_keys, &mut epoch_rng)?;
        black_box(adapter.derive_local_receiver_context(&epoch, 1)?);
        measurements.push(measure(
            "Zhang23-DAAGKA",
            LOCAL_CONTRIBUTION,
            "epoch_event",
            event,
            options,
            || adapter.create_local_agreement_contribution(member, &mut contribution_rng),
        ));
        measurements.push(measure(
            "Zhang23-DAAGKA",
            LOCAL_FINALIZE,
            "epoch_event",
            event,
            options,
            || {
                adapter
                    .derive_local_receiver_context(black_box(&epoch), black_box(1))
                    .unwrap()
            },
        ));
        measurements.push(measure(
            "Zhang23-DAAGKA",
            LOCAL_PATH,
            "epoch_event",
            event,
            options,
            || {
                let contribution =
                    adapter.create_local_agreement_contribution(member, &mut combined_rng);
                let receiver_context = adapter
                    .derive_local_receiver_context(black_box(&epoch), black_box(1))
                    .unwrap();
                (contribution, receiver_context)
            },
        ));
    }
    Ok(())
}

fn parameters(cli: &Cli) -> SetupParameters {
    SetupParameters {
        max_users: cli.max_users,
        tree_depth: cli.tree_depth,
    }
}

fn write_definitions(path: &Path) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(writer, "scheme,event,included_local_work,excluded_work")?;
    writeln!(
        writer,
        "FS-DBS,KeyUpdate,one sender evolving-state update,all receiver updates"
    )?;
    writeln!(
        writer,
        "AFI06,KeyUpdate,one member evolving-state update,all other member updates"
    )?;
    writeln!(writer, "KMW23,EpochKeyGen,one user's fresh public/private key pair,all other key pairs and public-key redistribution")?;
    writeln!(writer, "Lee25-SS,EpochKeyGen,one user's fresh public/private key pair,all other key pairs and public-key redistribution")?;
    writeln!(writer, "Li17-AAGKA,Agreement,one member contribution plus that member's Dec.KeyGen,coordinator aggregation plus other members plus communication and waiting")?;
    writeln!(writer, "Zhang23-DAAGKA,Agreement,one member contribution plus that member's Dec.KeyGen,coordinator aggregation plus other members plus communication and waiting")?;
    Ok(())
}

fn write_scope(path: &Path, cli: &Cli) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(writer, "TEST-ONLY LOCAL-PARTICIPANT EPOCH BENCHMARK")?;
    writeln!(writer, "group_size={}", cli.group_size)?;
    writeln!(writer, "max_users={}", cli.max_users)?;
    writeln!(writer, "tree_depth={}", cli.tree_depth)?;
    writeln!(writer, "epoch_events={}", cli.epochs)?;
    writeln!(writer, "statistic=median wall-clock time")?;
    writeln!(writer, "pairing_preprocessing=disabled")?;
    writeln!(
        writer,
        "scope=local cryptographic CPU work performed by one participant"
    )?;
    writeln!(writer, "not_measured=network delay; synchronization; slowest-member wait; coordinator aggregation; other participants")?;
    writeln!(writer, "warning=KMW23 and Lee25-SS re-keying is a hypothetical epoch reset and does not prove forward security for either source scheme")?;
    Ok(())
}

fn parse_cli() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli {
        epochs: 10,
        group_size: 100,
        max_users: 1024,
        tree_depth: 20,
        repetitions: 20,
        warmup: 5,
        seed: 2026_0813,
        output: PathBuf::from("results/epoch-local-test"),
    };
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        let target = match args[index].as_str() {
            "--epochs" => Some(&mut cli.epochs),
            "--group-size" => Some(&mut cli.group_size),
            "--max-users" => Some(&mut cli.max_users),
            "--tree-depth" => Some(&mut cli.tree_depth),
            "--repetitions" => Some(&mut cli.repetitions),
            "--warmup" => Some(&mut cli.warmup),
            "--seed" => {
                index += 1;
                cli.seed = args.get(index).ok_or("missing --seed value")?.parse()?;
                None
            }
            "--output" => {
                index += 1;
                cli.output = PathBuf::from(args.get(index).ok_or("missing --output value")?);
                None
            }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        };
        if let Some(target) = target {
            index += 1;
            *target = args.get(index).ok_or("missing numeric value")?.parse()?;
        }
        index += 1;
    }
    if cli.epochs == 0 || cli.epochs > cli.tree_depth {
        return Err("epochs must be in 1..=tree-depth".into());
    }
    if cli.group_size == 0 || cli.group_size > cli.max_users {
        return Err("group size must be in 1..=max-users".into());
    }
    if cli.tree_depth == 0 || cli.tree_depth >= cli.max_users {
        return Err("tree depth must be in 1..max-users".into());
    }
    if cli.repetitions < 2 {
        return Err("repetitions must be at least two".into());
    }
    Ok(cli)
}
