# FS-DBS Artifact

This repository contains the implementation, measurements, and paper source.

## Layout

- `code/src/`: FS-DBS and baseline implementations.
- `code/scripts/`: validation and plotting scripts.
- `code/results/`: raw samples and summary files.
- `code/figures/`: performance figures.
- `paper/`: LaTeX source and compiled paper.

## Build

The code uses Rust 1.91 and Arkworks 0.5. From `code/`, run:

```text
cargo test --release
```

For a short FS-DBS benchmark:

```text
cargo run --release --bin benchmark_all -- --scheme FS-DBS --receiver_sizes 100,200,300,400,500,600,700,800,900,1000 --max_users 1024 --tree_depth 20 --repetitions 20 --warmup 5 --inner_iterations 10 --output results/reproduction-fs-dbs --no_plots
```

## Validate Results

Install the plotting dependencies with:

```text
python -m pip install -r ../requirements.txt
```

Validate the online summaries:

```text
python scripts/validate_statistics.py --results results/online-100-1000
python scripts/audit_curves.py --results results/online-100-1000
```

Recreate the plots:

```text
python scripts/plot_fig34.py --results results/online-100-1000 --figures figures

python scripts/plot_epoch_transition.py --results results/epoch-transition-100-1000 --figures figures
```

The ResNet-50 weight file is omitted because of its size. Its filename, size,
and SHA-256 digest are recorded with the model-distribution results. The code is
a research prototype and has not undergone a production security audit.
