# Artifact Evaluation Notes

## Evaluation Environment

- CPU: Intel Core i7-14700HX
- Memory: 32 GiB
- Operating system: Windows x86-64
- Rust: 1.91.0
- Arkworks: 0.5.0
- Pairing: asymmetric Type-3 BLS12-381
- Maximum user slots: 1,024
- Time-tree depth: 20

## Reported Experiments

The online experiment varies the authorized receiver set from 100 to 1,000.
Each point contains 20 timed samples, and each sample averages ten online calls.
The committed raw CSV files support independent recomputation of the medians,
sample standard deviations, and confidence intervals.

The epoch-transition experiment measures one receiver transition. FS-DBS and
AFI06 run one key update. KMW23 and Lee25-SS generate one fresh receiver key
pair as an operational-reset baseline. Li17-AAGKA and Zhang23-DAAGKA run their
agreement and receiver-key preparation paths.

The model-distribution experiment uses 100 authorized receivers and 100 model
releases. An epoch transition is invoked after every ten releases. The model
body is protected with AES-256-GCM, while each public-key scheme protects the
32-byte content key.

## Data Provenance

Each result directory contains its raw samples, summaries, environment record,
and experiment notes. The model artifact metadata records the expected
ResNet-50 filename, byte length, and SHA-256 digest without redistributing the
weight file.
