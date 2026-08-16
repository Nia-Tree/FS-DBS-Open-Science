# FS-DBS Open Science Artifact

This repository contains the implementation and evaluation artifact for
**FS-DBS: Forward-Secure Distributed Broadcast Signcryption for Secure
Cloud-to-Edge Data Distribution**.

## Contents

- `code/src/`: Rust implementations of FS-DBS and the evaluated baselines.
- `code/scripts/`: benchmark validation and figure-generation scripts.
- `code/results/online-100-1000/`: raw and summarized online latency results.
- `code/results/epoch-transition-100-1000/`: epoch-transition measurements.
- `code/results/model-update-100-releases/`: repeated model-distribution results.
- `code/figures/`: the three performance figures used in the paper.
- `paper/`: the LaTeX source, bibliography, figures, and compiled manuscript.

The ResNet-50 weight file is not included because of its size. Its filename,
size, and SHA-256 digest are recorded in the model-distribution result metadata.

## Build and Test

The implementation targets Rust 1.91 and Arkworks 0.5. From `code/`, run:

```text
cargo test --release
```

For a short FS-DBS run without plotting:

```text
cargo run --release --bin benchmark_all -- --scheme FS-DBS --receiver_sizes 100,200,300,400,500,600,700,800,900,1000 --max_users 1024 --tree_depth 20 --repetitions 20 --warmup 5 --inner_iterations 10 --output results/reproduction-fs-dbs --no_plots
```

## Validate Published Measurements

Install the plotting dependencies with:

```text
python -m pip install -r ../requirements.txt
```

Then validate the online timing summaries against the committed raw samples:

```text
python scripts/validate_statistics.py --results results/online-100-1000
python scripts/audit_curves.py --results results/online-100-1000
```

Recreate the online and epoch-transition plots with:

```text
python scripts/plot_fig34.py --results results/online-100-1000 --figures figures

python scripts/plot_epoch_transition.py --results results/epoch-transition-100-1000 --figures figures
```

Absolute timings depend on the processor, operating system, power policy, and
background load. The committed raw samples are the measurements reported in
the manuscript.

## Artifact Scope

This is a research prototype. It has not undergone an independent production
security audit. The repository omits build caches, historical exploratory runs,
local paths, and the large model weight file.
