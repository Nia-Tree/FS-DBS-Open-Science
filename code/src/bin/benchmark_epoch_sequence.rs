use fs_dbs_bench::{
    afi06_adapter::Afi06Adapter,
    benchmark::{measure, write_raw_csv, write_summary_csv, BenchmarkOptions, Measurement},
    environment::{write_environment, EnvironmentRecord},
    fs_dbs_adapter::FsDbsAdapter,
    scheme_adapter::{SchemeAdapter, SetupParameters},
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, error::Error, fs, path::PathBuf};

struct Cli {
    epochs: usize,
    max_users: usize,
    tree_depth: usize,
    repetitions: usize,
    warmup: usize,
    seed: u64,
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_cli()?;
    if cli.epochs > cli.tree_depth {
        return Err("epochs must not exceed the FS-DBS tree depth".into());
    }
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
    write_raw_csv(
        &cli.output.join("raw/sequential_key_update_raw.csv"),
        &measurements,
    )?;
    write_summary_csv(
        &cli.output.join("summary/sequential_key_update.csv"),
        &measurements,
    )?;
    println!(
        "Sequential epoch-update artifacts written under {}",
        cli.output.display()
    );
    Ok(())
}

fn benchmark_fs_dbs(
    cli: &Cli,
    options: BenchmarkOptions,
    measurements: &mut Vec<Measurement>,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing FS-DBS sequential state");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_5E01);
    let adapter = FsDbsAdapter::setup(parameters(cli), &mut setup_rng)?;
    let mut state = adapter.join(1, &mut setup_rng)?.secret;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_5E02);
    let mut advance_rng = StdRng::seed_from_u64(cli.seed ^ 0xF5DB_5E03);
    for epoch in 1..=cli.epochs {
        measurements.push(measure(
            "FS-DBS",
            "Sequential KeyUpdate / Single State",
            "epoch_boundary",
            epoch,
            options,
            || adapter.update(&state, 1, &mut timing_rng).unwrap(),
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
    println!("Preparing AFI06 sequential state");
    let mut setup_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_5E01);
    let adapter = Afi06Adapter::setup(parameters(cli), &mut setup_rng)?;
    let mut state = adapter.keygen(1, &mut setup_rng)?.secret;
    let mut timing_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_5E02);
    let mut advance_rng = StdRng::seed_from_u64(cli.seed ^ 0xAF10_5E03);
    for epoch in 1..=cli.epochs {
        measurements.push(measure(
            "AFI06",
            "Sequential KeyUpdate / Single State",
            "epoch_boundary",
            epoch,
            options,
            || adapter.update(&state, 0, &mut timing_rng).unwrap(),
        ));
        state = adapter.update(&state, 0, &mut advance_rng)?;
    }
    Ok(())
}

fn parameters(cli: &Cli) -> SetupParameters {
    SetupParameters {
        max_users: cli.max_users,
        tree_depth: cli.tree_depth,
    }
}

fn parse_cli() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli {
        epochs: 10,
        max_users: 1024,
        tree_depth: 20,
        repetitions: 30,
        warmup: 5,
        seed: 2026_0817,
        output: PathBuf::from("results/epoch-sequence"),
    };
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--epochs" => {
                index += 1;
                cli.epochs = args.get(index).ok_or("missing --epochs value")?.parse()?;
            }
            "--max-users" => {
                index += 1;
                cli.max_users = args
                    .get(index)
                    .ok_or("missing --max-users value")?
                    .parse()?;
            }
            "--tree-depth" => {
                index += 1;
                cli.tree_depth = args
                    .get(index)
                    .ok_or("missing --tree-depth value")?
                    .parse()?;
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
            "--seed" => {
                index += 1;
                cli.seed = args.get(index).ok_or("missing --seed value")?.parse()?;
            }
            "--output" => {
                index += 1;
                cli.output = PathBuf::from(args.get(index).ok_or("missing --output value")?);
            }
            unknown => return Err(format!("unknown argument: {unknown}").into()),
        }
        index += 1;
    }
    if cli.epochs == 0 || cli.repetitions < 2 {
        return Err("epochs must be positive and repetitions at least two".into());
    }
    Ok(cli)
}
