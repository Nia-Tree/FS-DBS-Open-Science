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

struct Cli {
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
        &cli.output.join("raw/epoch_rekey_time_raw.csv"),
        &measurements,
    )?;
    write_summary_csv(
        &cli.output.join("summary/epoch_rekey_time.csv"),
        &measurements,
    )?;
    write_definitions(&cli.output.join("summary/epoch_rekey_definitions.csv"))?;
    println!(
        "Epoch-rekey artifacts written under {}",
        cli.output.display()
    );
    Ok(())
}

fn benchmark_fs_dbs(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing FS-DBS roots for {} receivers", cli.group_size);
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_E001);
    let adapter = FsDbsAdapter::setup(parameters(cli), &mut rng)?;
    let receivers = (1..=cli.group_size)
        .map(|identity| adapter.join(identity, &mut rng).map(|pair| pair.secret))
        .collect::<Result<Vec<_>, _>>()?;
    let sender = adapter.join(cli.max_users, &mut rng)?.secret;

    measurements.push(measure(
        "FS-DBS",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            black_box(adapter.update(&sender, 1, &mut rng).unwrap());
            for key in &receivers {
                black_box(adapter.update(key, 1, &mut rng).unwrap());
            }
        },
    ));
    measurements.push(measure(
        "FS-DBS",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || {
            let updated_sender = adapter.update(&sender, 1, &mut rng).unwrap();
            let updated_receiver = adapter.update(&receivers[0], 1, &mut rng).unwrap();
            (updated_sender, updated_receiver)
        },
    ));
    Ok(())
}

fn benchmark_afi06(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing AFI06 roots for {} receivers", cli.group_size);
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_E001);
    let adapter = Afi06Adapter::setup(parameters(cli), &mut rng)?;
    let receivers = (1..=cli.group_size)
        .map(|identity| adapter.keygen(identity, &mut rng).map(|pair| pair.secret))
        .collect::<Result<Vec<_>, _>>()?;

    measurements.push(measure(
        "AFI06",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            for key in &receivers {
                black_box(adapter.update(key, 0, &mut rng).unwrap());
            }
        },
    ));
    measurements.push(measure(
        "AFI06",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || adapter.update(&receivers[0], 0, &mut rng).unwrap(),
    ));
    Ok(())
}

fn benchmark_kmw23(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing KMW23 epoch KeyGen benchmark");
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0x23DB_E001);
    let adapter = Kmw23Adapter::setup(parameters(cli), &mut rng)?;
    measurements.push(measure(
        "KMW23",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            for identity in 1..=cli.group_size {
                black_box(adapter.keygen(identity, &mut rng).unwrap());
            }
        },
    ));
    measurements.push(measure(
        "KMW23",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || adapter.keygen(1, &mut rng).unwrap(),
    ));
    Ok(())
}

fn benchmark_lee25(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing Lee25-SS epoch KeyGen benchmark");
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0x1EE2_E001);
    let adapter = Lee25SsAdapter::setup(parameters(cli), &mut rng)?;
    measurements.push(measure(
        "Lee25-SS",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            for identity in 1..=cli.group_size {
                black_box(adapter.keygen(identity, &mut rng).unwrap());
            }
        },
    ));
    measurements.push(measure(
        "Lee25-SS",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || adapter.keygen(1, &mut rng).unwrap(),
    ));
    Ok(())
}

fn benchmark_li17(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing Li17-AAGKA agreement benchmark");
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0x1A17_E001);
    let adapter = Li17Adapter::setup(parameters(cli), &mut rng)?;
    let public_keys = (1..=cli.group_size)
        .map(|identity| adapter.keygen(identity, &mut rng).map(|pair| pair.public))
        .collect::<Result<Vec<_>, _>>()?;
    let recipients = (1..=cli.group_size).collect::<Vec<_>>();
    measurements.push(measure(
        "Li17-AAGKA",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            adapter
                .prepare_all_receivers(&recipients, &public_keys, &mut rng)
                .unwrap()
        },
    ));
    measurements.push(measure(
        "Li17-AAGKA",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || {
            adapter
                .prepare_group(&recipients, &public_keys, 1, &mut rng)
                .unwrap()
        },
    ));
    Ok(())
}

fn benchmark_zhang23(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing Zhang23-DAAGKA agreement benchmark");
    let mut rng = StdRng::seed_from_u64(cli.seed ^ 0x2A23_E001);
    let adapter = Zhang23Adapter::setup(parameters(cli), &mut rng)?;
    let secret_keys = (1..=cli.group_size)
        .map(|identity| adapter.keygen(identity, &mut rng).map(|pair| pair.secret))
        .collect::<Result<Vec<_>, _>>()?;
    let recipients = (1..=cli.group_size).collect::<Vec<_>>();
    measurements.push(measure(
        "Zhang23-DAAGKA",
        "Epoch Rekey / Aggregate Work",
        "group_size",
        cli.group_size,
        options,
        || {
            adapter
                .prepare_all_receivers(&recipients, &secret_keys, &mut rng)
                .unwrap()
        },
    ));
    measurements.push(measure(
        "Zhang23-DAAGKA",
        "Epoch Rekey / Representative Path",
        "group_size",
        cli.group_size,
        options,
        || {
            adapter
                .prepare_group(&recipients, &secret_keys, 1, &mut rng)
                .unwrap()
        },
    ));
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
    writeln!(
        writer,
        "scheme,event,aggregate_definition,representative_definition"
    )?;
    writeln!(writer, "FS-DBS,KeyUpdate,provider plus all receiver evolving states,provider plus one receiver state")?;
    writeln!(
        writer,
        "AFI06,KeyUpdate,all receiver forward-secure states,one receiver state"
    )?;
    writeln!(writer, "KMW23,EpochKeyGen,all receiver public/private key pairs,one receiver public/private key pair")?;
    writeln!(writer, "Lee25-SS,EpochKeyGen,all receiver public/private key pairs,one receiver public/private key pair")?;
    writeln!(writer, "Li17-AAGKA,Agreement,one Agreement and Enc.KeyGen plus every receiver Dec.KeyGen,one Agreement and Enc.KeyGen plus one receiver Dec.KeyGen")?;
    writeln!(writer, "Zhang23-DAAGKA,Agreement,one Agreement and Enc.KeyGen plus every receiver Dec.KeyGen,one Agreement and Enc.KeyGen plus one receiver Dec.KeyGen")?;
    Ok(())
}

fn parse_cli() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli {
        group_size: 100,
        max_users: 1024,
        tree_depth: 20,
        repetitions: 20,
        warmup: 5,
        seed: 2026_0813,
        output: PathBuf::from("results/epoch-rekey"),
    };
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        let target = match args[index].as_str() {
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
    if cli.group_size == 0 || cli.group_size > cli.max_users {
        return Err("group size must be in 1..=max_users".into());
    }
    if cli.tree_depth == 0 || cli.tree_depth >= cli.max_users {
        return Err("tree depth must be in 1..max_users".into());
    }
    if cli.repetitions < 2 {
        return Err("repetitions must be at least two".into());
    }
    Ok(cli)
}
