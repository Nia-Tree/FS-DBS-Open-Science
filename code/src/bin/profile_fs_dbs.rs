use fs_dbs_bench::{
    benchmark::{measure, write_raw_csv, write_summary_csv, BenchmarkOptions},
    fs_dbs_adapter::FsDbsAdapter,
    scheme_adapter::{SchemeAdapter, SetupParameters},
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, error::Error, fs, path::PathBuf};

const MAX_USERS: usize = 1024;
const TREE_DEPTH: usize = 20;
const WARMUP: usize = 20;
const REPETITIONS: usize = 100;

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let output = PathBuf::from(
        args.first()
            .map(String::as_str)
            .unwrap_or("results/fs-dbs-optimization"),
    );
    let receiver_sizes = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("10,50,100,200,500,1000")
        .split(',')
        .map(str::parse)
        .collect::<Result<Vec<usize>, _>>()?;
    let largest_set = *receiver_sizes.iter().max().ok_or("empty receiver sizes")?;
    if largest_set >= MAX_USERS {
        return Err("receiver size must be smaller than MAX_USERS".into());
    }

    let mut setup_rng = StdRng::seed_from_u64(0xF5DB_CA5E);
    let adapter = FsDbsAdapter::setup(
        SetupParameters {
            max_users: MAX_USERS,
            tree_depth: TREE_DEPTH,
        },
        &mut setup_rng,
    )?;
    let mut public_keys = Vec::with_capacity(largest_set);
    let mut receiver_secret = None;
    for identity in 1..=largest_set {
        let pair = adapter.join(identity, &mut setup_rng)?;
        if identity == 1 {
            receiver_secret = Some(pair.secret.clone());
        }
        public_keys.push(pair.public);
    }
    let sender = adapter.join(MAX_USERS, &mut setup_rng)?;
    let mut sender_secret = sender.secret;
    let mut receiver_secret = receiver_secret.ok_or("receiver set is empty")?;
    for level in 0..TREE_DEPTH {
        let child_bit = (level % 2) as u8;
        sender_secret = adapter.update(&sender_secret, child_bit, &mut setup_rng)?;
        receiver_secret = adapter.update(&receiver_secret, child_bit, &mut setup_rng)?;
    }

    let options = BenchmarkOptions {
        warmup: WARMUP,
        repetitions: REPETITIONS,
        inner_iterations: 1,
    };
    let message = [0x42; 32];
    let mut operation_rng = StdRng::seed_from_u64(0xF5DB_0A11);
    let mut measurements = Vec::new();

    for receiver_size in receiver_sizes {
        let recipients = (1..=receiver_size).collect::<Vec<_>>();
        let scheme = adapter.scheme();
        let time_cache = scheme.prepare_time(&sender_secret.node);
        let verification_cache = scheme.prepare_verification(&sender.public);
        let encrypt_cache = scheme.prepare_encrypt_recipients(&recipients, &public_keys);
        let mut decrypt_cache = scheme.prepare_receiver_recipients(&recipients);
        scheme.add_receiver_context(&mut decrypt_cache, 1, &public_keys, &receiver_secret);
        let ciphertext = scheme.signcrypt_cached(
            &sender_secret,
            &sender.public,
            &encrypt_cache,
            &time_cache,
            &message,
            &mut operation_rng,
        );
        assert_eq!(
            scheme.unsigncrypt_online(
                1,
                &receiver_secret,
                &sender.public,
                &decrypt_cache,
                &time_cache,
                &verification_cache,
                &ciphertext,
            ),
            Some(message)
        );

        measurements.push(measure(
            "FS-DBS",
            "Full Signcrypt",
            "receiver_size",
            receiver_size,
            options,
            || {
                adapter
                    .signcrypt(
                        &sender_secret,
                        &sender.public,
                        &recipients,
                        &public_keys,
                        &message,
                        &mut operation_rng,
                    )
                    .expect("validated full signcryption")
            },
        ));
        measurements.push(measure(
            "FS-DBS",
            "Prepare Encrypt Context",
            "receiver_size",
            receiver_size,
            options,
            || {
                (
                    scheme.prepare_encrypt_recipients(&recipients, &public_keys),
                    scheme.prepare_time(&sender_secret.node),
                )
            },
        ));
        measurements.push(measure(
            "FS-DBS",
            "Online Signcrypt (cached)",
            "receiver_size",
            receiver_size,
            options,
            || {
                scheme.signcrypt_cached(
                    &sender_secret,
                    &sender.public,
                    &encrypt_cache,
                    &time_cache,
                    &message,
                    &mut operation_rng,
                )
            },
        ));
        measurements.push(measure(
            "FS-DBS",
            "Full Unsigncrypt",
            "receiver_size",
            receiver_size,
            options,
            || {
                adapter
                    .unsigncrypt(
                        1,
                        &receiver_secret,
                        &sender.public,
                        &recipients,
                        &public_keys,
                        &ciphertext,
                    )
                    .expect("validated full unsigncryption")
            },
        ));
        measurements.push(measure(
            "FS-DBS",
            "Prepare Decrypt Context",
            "receiver_size",
            receiver_size,
            options,
            || {
                let mut cache = scheme.prepare_receiver_recipients(&recipients);
                scheme.add_receiver_context(&mut cache, 1, &public_keys, &receiver_secret);
                (
                    cache,
                    scheme.prepare_time(&receiver_secret.node),
                    scheme.prepare_verification(&sender.public),
                )
            },
        ));
        measurements.push(measure(
            "FS-DBS",
            "Online Unsigncrypt (cached)",
            "receiver_size",
            receiver_size,
            options,
            || {
                scheme
                    .unsigncrypt_online(
                        1,
                        &receiver_secret,
                        &sender.public,
                        &decrypt_cache,
                        &time_cache,
                        &verification_cache,
                        &ciphertext,
                    )
                    .expect("validated cached unsigncryption")
            },
        ));
    }

    fs::create_dir_all(output.join("raw"))?;
    fs::create_dir_all(output.join("summary"))?;
    write_raw_csv(
        &output.join("raw/fs_dbs_cache_profile_raw.csv"),
        &measurements,
    )?;
    write_summary_csv(
        &output.join("summary/fs_dbs_cache_profile.csv"),
        &measurements,
    )?;
    println!("FS-DBS cache profile written under {}", output.display());
    Ok(())
}
