use fs_dbs_bench::{
    afi06_adapter::Afi06Adapter,
    benchmark::{measure, write_raw_csv, write_summary_csv, BenchmarkOptions},
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

const PHASE: &str = "Receiver Epoch Transition";

struct Cli {
    group_sizes: Vec<usize>,
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
    let parameters = SetupParameters {
        max_users: cli.max_users,
        tree_depth: cli.tree_depth,
    };
    let mut rng = StdRng::seed_from_u64(cli.seed);

    let fs_dbs = FsDbsAdapter::setup(parameters, &mut rng)?;
    let fs_root = fs_dbs.join(1, &mut rng)?.secret;
    let afi06 = Afi06Adapter::setup(parameters, &mut rng)?;
    let afi_root = afi06.keygen(1, &mut rng)?.secret;
    let kmw23 = Kmw23Adapter::setup(parameters, &mut rng)?;
    let kmw_root = kmw23.keygen(1, &mut rng)?.secret;
    let lee25 = Lee25SsAdapter::setup(parameters, &mut rng)?;
    let lee_root = lee25.keygen(1, &mut rng)?.secret;
    let li17 = Li17Adapter::setup(parameters, &mut rng)?;
    let zhang23 = Zhang23Adapter::setup(parameters, &mut rng)?;

    let largest_group = *cli.group_sizes.iter().max().expect("validated group sizes");
    let li_keys = (1..=largest_group)
        .map(|identity| li17.keygen(identity, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let li_public = li_keys
        .iter()
        .map(|pair| pair.public.clone())
        .collect::<Vec<_>>();
    let zhang_keys = (1..=largest_group)
        .map(|identity| zhang23.keygen(identity, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let zhang_secret = zhang_keys
        .iter()
        .map(|pair| pair.secret.clone())
        .collect::<Vec<_>>();

    write_storage(
        &cli.output.join("summary/private_state_storage.csv"),
        cli.tree_depth,
        &fs_dbs,
        &fs_root,
        &afi06,
        &afi_root,
        &kmw23,
        &kmw_root,
        &lee25,
        &lee_root,
        &li17,
        &li_keys[0].secret,
        &zhang23,
        &zhang_keys[0].secret,
    )?;
    write_definitions(&cli.output.join("summary/epoch_transition_definitions.csv"))?;

    let mut measurements = Vec::new();
    for &group_size in &cli.group_sizes {
        println!("Benchmarking receiver epoch transition at n={group_size}");
        let recipients = (1..=group_size).collect::<Vec<_>>();

        measurements.push(measure(
            "FS-DBS",
            PHASE,
            "group_size",
            group_size,
            options,
            || fs_dbs.update(&fs_root, 1, &mut rng).unwrap(),
        ));
        measurements.push(measure(
            "AFI06",
            PHASE,
            "group_size",
            group_size,
            options,
            || afi06.update(&afi_root, 0, &mut rng).unwrap(),
        ));
        measurements.push(measure(
            "KMW23",
            PHASE,
            "group_size",
            group_size,
            options,
            || kmw23.keygen(1, &mut rng).unwrap(),
        ));
        measurements.push(measure(
            "Lee25-SS",
            PHASE,
            "group_size",
            group_size,
            options,
            || lee25.keygen(1, &mut rng).unwrap(),
        ));
        measurements.push(measure(
            "Li17-AAGKA",
            PHASE,
            "group_size",
            group_size,
            options,
            || {
                black_box(
                    li17.prepare_group(&recipients, &li_public, 1, &mut rng)
                        .unwrap(),
                )
            },
        ));
        measurements.push(measure(
            "Zhang23-DAAGKA",
            PHASE,
            "group_size",
            group_size,
            options,
            || {
                black_box(
                    zhang23
                        .prepare_group(&recipients, &zhang_secret, 1, &mut rng)
                        .unwrap(),
                )
            },
        ));
    }

    write_raw_csv(
        &cli.output.join("raw/epoch_transition_time_raw.csv"),
        &measurements,
    )?;
    write_summary_csv(
        &cli.output.join("summary/epoch_transition_time.csv"),
        &measurements,
    )?;
    println!("Artifacts written under {}", cli.output.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_storage(
    path: &Path,
    tree_depth: usize,
    fs_dbs: &FsDbsAdapter,
    fs_key: &<FsDbsAdapter as SchemeAdapter>::SecretKey,
    afi06: &Afi06Adapter,
    afi_key: &<Afi06Adapter as SchemeAdapter>::SecretKey,
    kmw23: &Kmw23Adapter,
    kmw_key: &<Kmw23Adapter as SchemeAdapter>::SecretKey,
    lee25: &Lee25SsAdapter,
    lee_key: &<Lee25SsAdapter as SchemeAdapter>::SecretKey,
    li17: &Li17Adapter,
    li_key: &<Li17Adapter as SchemeAdapter>::SecretKey,
    zhang23: &Zhang23Adapter,
    zhang_key: &<Zhang23Adapter as SchemeAdapter>::SecretKey,
) -> Result<(), Box<dyn Error>> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "scheme,state_kind,tree_depth,serialized_bytes,g1_elements,g2_elements,zp_elements"
    )?;
    let records = [
        (
            "FS-DBS",
            "root evolving state",
            fs_dbs.serialize_secret_key(fs_key)?,
        ),
        (
            "AFI06",
            "root evolving state",
            afi06.serialize_secret_key(afi_key)?,
        ),
        (
            "KMW23",
            "long-term secret key",
            kmw23.serialize_secret_key(kmw_key)?,
        ),
        (
            "Lee25-SS",
            "long-term secret key",
            lee25.serialize_secret_key(lee_key)?,
        ),
        (
            "Li17-AAGKA",
            "long-term secret key",
            li17.serialize_secret_key(li_key)?,
        ),
        (
            "Zhang23-DAAGKA",
            "long-term secret key",
            zhang23.serialize_secret_key(zhang_key)?,
        ),
    ];
    for (scheme, kind, storage) in records {
        writeln!(
            writer,
            "{scheme},{kind},{tree_depth},{},{},{},{}",
            storage.serialized_bytes,
            storage.number_of_g1_elements,
            storage.number_of_g2_elements,
            storage.number_of_zp_elements,
        )?;
    }
    Ok(())
}

fn write_definitions(path: &Path) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "scheme,timed_epoch_transition,native_forward_security"
    )?;
    writeln!(writer, "FS-DBS,one receiver KeyUpdate,yes")?;
    writeln!(writer, "AFI06,one receiver KeyUpdate,yes")?;
    writeln!(
        writer,
        "KMW23,one fresh receiver public/private key pair,no"
    )?;
    writeln!(
        writer,
        "Lee25-SS,one fresh receiver public/private key pair,no"
    )?;
    writeln!(
        writer,
        "Li17-AAGKA,complete Agreement and Enc.KeyGen plus one receiver Dec.KeyGen,agreement-based"
    )?;
    writeln!(writer, "Zhang23-DAAGKA,complete Agreement and Enc.KeyGen plus one receiver Dec.KeyGen,agreement-based")?;
    Ok(())
}

fn parse_cli() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli {
        group_sizes: (1..=10).map(|value| value * 100).collect(),
        max_users: 1024,
        tree_depth: 20,
        repetitions: 20,
        warmup: 5,
        seed: 2026_0814,
        output: PathBuf::from("results/epoch-transition"),
    };
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--group-sizes" => {
                index += 1;
                cli.group_sizes = args
                    .get(index)
                    .ok_or("missing --group-sizes value")?
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<Vec<_>, _>>()?;
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
    if cli.group_sizes.is_empty()
        || cli
            .group_sizes
            .iter()
            .any(|&size| size == 0 || size > cli.max_users)
    {
        return Err("group sizes must be in 1..=max_users".into());
    }
    if cli.tree_depth == 0 || cli.tree_depth >= cli.max_users {
        return Err("tree depth must be in 1..max_users".into());
    }
    if cli.repetitions < 2 {
        return Err("repetitions must be at least two".into());
    }
    Ok(cli)
}
