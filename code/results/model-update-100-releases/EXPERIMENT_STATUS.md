# Epoch-10 Model-Release Experiment Status

Date: 2026-08-13

Status: complete and verified

## Definition

- Authorized receivers: 100
- Registered slots: 1,024
- Time-tree depth: 20
- Pairing: BLS12-381 Type-3 through Arkworks v0.5.0
- Execution: Release build, one benchmark thread
- Pairing preprocessing: disabled
- Epoch policy: an epoch operation is executed after every 10 completed model releases
- Evaluation horizon: 100 releases and 10 epoch events
- Plot metric: public-key security-layer computation; common model AEAD and network transfer are excluded
- End-to-end CSV metric: security layer plus measured ResNet-50 AES-256-GCM processing

The event count after r releases is floor(r / 10). Therefore, cumulative values at releases 10, 20, ..., 100 include one, two, ..., ten completed epoch operations.

## Epoch Operations

| Scheme | Epoch operation |
| --- | --- |
| FS-DBS | Provider and receiver KeyUpdate with secure deletion |
| AFI06 | Receiver KeyUpdate with secure deletion |
| KMW23 | Fresh independent receiver public/private key pairs |
| Lee25-SS | Fresh independent receiver public/private key pairs |
| Li17-AAGKA | Complete Agreement, Enc.KeyGen, and receiver Dec.KeyGen |
| Zhang23-DAAGKA | Complete Agreement, Enc.KeyGen, and receiver Dec.KeyGen |

KMW23 and Lee25-SS are operational epoch-reset baselines. Fresh keys plus secure deletion do not turn either source construction into a formally forward-secure scheme. Public-key publication and network redistribution are not included, so their reported reset costs are conservative computation-only values.

## Sampling

- Online encryption and decryption: 5 warm-ups and 30 timed samples per scheme
- Epoch operation: 3 warm-ups and 10 timed samples per scheme
- Sequential FS KeyUpdate: 5 warm-ups and 20 timed samples at each of 10 consecutive epoch boundaries
- ResNet-50 AES-GCM and Ed25519: 5 warm-ups and 20 timed samples
- Summary statistic used in the figure: median wall-clock time
- Raw samples, mean, standard deviation, extrema, and 95% normal intervals are retained

## Measured Medians

All values below are milliseconds.

| Scheme | Sender online | One receiver online | Representative epoch | Aggregate epoch |
| --- | ---: | ---: | ---: | ---: |
| FS-DBS | 0.6543 | 2.9601 | sequential values | sequential values |
| KMW23 | 3.5492 | 4.5475 | 103.1293 | 10,043.5926 |
| AFI06 | 2.5390 | 5.5731 | sequential values | sequential values |
| Lee25-SS | 4.5221 | 10.7870 | 97.9091 | 10,096.4022 |
| Li17-AAGKA | 1.0055 | 2.7743 | 74.2865 | 489.2163 |
| Zhang23-DAAGKA | 1.7257 | 2.9611 | 18.9175 | 478.1022 |

KMW23, AFI06, and Lee25-SS additionally use the measured external Ed25519 manifest signature and verification costs. Authentication is integrated into FS-DBS, Li17-AAGKA, and Zhang23-DAAGKA.

The ten FS-DBS single-state KeyUpdate medians are 13.3741, 12.4111, 12.1935, 11.3146, 11.0592, 10.5992, 9.9360, 9.6820, 9.9751, and 8.9503 ms. Their sum is 109.4948 ms. The corresponding AFI06 sum is 148.7605 ms.

## Cumulative Cost at 100 Releases

Panel (a) adds one sender operation, one receiver operation, and the representative epoch path. Panel (b) is sequential single-core-equivalent work: one sender, 100 receiver operations, and all epoch work. Panel (b) is not the wall-clock latency of 100 devices executing in parallel.

| Scheme | Panel (a), s | Online share | Epoch share | Panel (b), s | Online share | Epoch share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| FS-DBS | 0.5804 | 62.27% | 37.73% | 40.7249 | 72.84% | 27.16% |
| KMW23 | 1.8446 | 44.09% | 55.91% | 146.5011 | 31.44% | 68.56% |
| AFI06 | 0.9636 | 84.56% | 15.44% | 71.0957 | 79.08% | 20.92% |
| Lee25-SS | 2.5136 | 61.05% | 38.95% | 209.5210 | 51.81% | 48.19% |
| Li17-AAGKA | 1.1208 | 33.72% | 66.28% | 32.7357 | 85.06% | 14.94% |
| Zhang23-DAAGKA | 0.6578 | 71.24% | 28.76% | 34.5641 | 86.17% | 13.83% |

## Application Components

The model artifact is the 102,540,417-byte TorchVision ResNet-50 weight file with SHA-256 `11ad3fa62ca79e40addfd354a8ec4b7c75143b3038b8d2a807fbc68deab379ca`.

- AES-256-GCM encryption: 46.0138 ms
- AES-256-GCM decryption: 45.3954 ms
- Ed25519 manifest signing: 0.0130 ms
- Ed25519 manifest verification: 0.0234 ms

For FS-DBS at 100 releases, the one-sender/one-receiver end-to-end computation is 9.7213 s: 3.72% online public-key processing, 2.25% epoch updates, and 94.03% common AEAD processing.

## Artifacts

- `summary/epoch_rekey_time.csv`: formal epoch-operation statistics
- `raw/epoch_rekey_time_raw.csv`: formal epoch-operation samples
- `online/*/summary/figure1_encrypt_time.csv`: current online sender medians
- `online/*/summary/figure2_decrypt_time.csv`: current online receiver medians
- `sequential-updates/summary/sequential_key_update.csv`: ten consecutive FS epoch boundaries
- `model-components/summary/figure6_component_times.csv`: ResNet-50 AEAD and Ed25519 data
- `figure6-final/summary/figure6_critical_path.csv`: panel (a) data for every release from 0 to 100
- `figure6-final/summary/figure6_aggregate_work.csv`: panel (b) data for every release from 0 to 100
- `figure6-final/summary/figure6_epoch_events.csv`: per-event epoch costs
- `figure6-final/summary/figure6_cost_shares.csv`: security-layer and end-to-end shares
- `figure6-final/figures/figure6_model_update.pdf`: final vector figure

## Verification

- Rust Release test suite: 26 passed, 0 failed
- Every benchmark performs a correctness check before timing
- All 12 formal epoch summaries have coefficient of variation below 4.4%
- Figure PDF was rendered back through Poppler and inspected for clipping and overlap
- `pdflatex` produced a 9-page paper PDF with the new figure
- The repository still contains pre-existing bibliography defects: duplicate BibTeX entries and 11 unresolved citation keys. They are unrelated to this experiment.
