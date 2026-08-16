import argparse
import csv
import math
import statistics
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


COLORS = {"FS-DBS": "#1565C0", "AFI06": "#8E24AA"}
MARKERS = {"FS-DBS": "o", "AFI06": "D"}


def aggregate_raw_measurements(
    paths: list[Path], expected_scheme: str, depth: int
) -> tuple[dict[str, object], list[dict[str, object]]]:
    elapsed: list[float] = []
    combined: list[dict[str, object]] = []
    for run_id, path in enumerate(paths, start=1):
        with path.open(newline="", encoding="utf-8") as handle:
            run_rows = [
                row
                for row in csv.DictReader(handle)
                if row["scheme"] == expected_scheme
                and row["axis_name"] == "tree_depth"
                and int(row["axis_value"]) == depth
            ]
        if not run_rows:
            raise ValueError(
                f"no {expected_scheme} samples at depth {depth} in {path}"
            )
        for row in run_rows:
            value = float(row["elapsed_ms"])
            elapsed.append(value)
            combined.append(
                {
                    "scheme": expected_scheme,
                    "tree_depth": depth,
                    "run_id": run_id,
                    "sample_in_run": int(row["sample"]),
                    "elapsed_ms": value,
                    "source": str(path.resolve()),
                }
            )

    samples = len(elapsed)
    stddev = statistics.stdev(elapsed)
    ci_half_width = 1.96 * stddev / math.sqrt(samples)
    mean = statistics.fmean(elapsed)
    measurement: dict[str, object] = {
        "scheme": expected_scheme,
        "tree_depth": depth,
        "runs": len(paths),
        "samples": samples,
        "mean_ms": mean,
        "median_ms": statistics.median(elapsed),
        "stddev_ms": stddev,
        "min_ms": min(elapsed),
        "max_ms": max(elapsed),
        "ci95_low_ms": mean - ci_half_width,
        "ci95_high_ms": mean + ci_half_width,
    }
    return measurement, combined


def build_rows(
    measurements: dict[str, dict[str, str]],
    releases: list[int],
    releases_per_epoch: int,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for scheme, measurement in measurements.items():
        update_ms = float(measurement["median_ms"])
        for release_count in releases:
            # Setup leaves the device at the tree root. Entering each key epoch,
            # including the first one, invokes exactly one measured KeyUpdate.
            key_updates = math.ceil(release_count / releases_per_epoch)
            cumulative_ms = key_updates * update_ms
            rows.append(
                {
                    "scheme": scheme,
                    "model_releases": release_count,
                    "releases_per_key_epoch": releases_per_epoch,
                    "key_updates": key_updates,
                    "tree_depth": int(measurement["tree_depth"]),
                    "independent_runs": int(measurement["runs"]),
                    "samples": int(measurement["samples"]),
                    "key_update_mean_ms": float(measurement["mean_ms"]),
                    "key_update_median_ms": update_ms,
                    "key_update_stddev_ms": float(measurement["stddev_ms"]),
                    "key_update_ci95_low_ms": float(measurement["ci95_low_ms"]),
                    "key_update_ci95_high_ms": float(measurement["ci95_high_ms"]),
                    "cumulative_key_update_ms": cumulative_ms,
                    "cumulative_key_update_s": cumulative_ms / 1000.0,
                }
            )
    return rows


def plot(data: pd.DataFrame, output_dir: Path) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#303030",
            "axes.labelsize": 8.8,
            "axes.titlesize": 9.2,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 7.6,
            "font.family": "serif",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, ax = plt.subplots(figsize=(3.45, 2.65), constrained_layout=True)
    for scheme in ["FS-DBS", "AFI06"]:
        group = data[data["scheme"] == scheme].sort_values("model_releases")
        label = "FS-DBS" if scheme == "FS-DBS" else "AFI06 FS-BE"
        ax.plot(
            group["model_releases"],
            group["cumulative_key_update_s"],
            label=label,
            color=COLORS[scheme],
            marker=MARKERS[scheme],
            linestyle="-" if scheme == "FS-DBS" else "--",
            linewidth=2.25,
            markersize=5.2,
            markeredgecolor="white",
            markeredgewidth=0.7,
        )

    releases_per_epoch = int(data["releases_per_key_epoch"].iloc[0])
    depth = int(data["tree_depth"].iloc[0])
    samples = int(data["samples"].iloc[0])
    ax.set_title("Forward-Secure Key-Evolution Cost", pad=6)
    ax.set_xlabel("Model Releases")
    ax.set_ylabel("Cumulative KeyUpdate Time (s)")
    ax.text(
        0.98,
        0.035,
        f"{releases_per_epoch} releases/epoch, depth={depth}, {samples} samples",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=6.6,
        color="#4A4A4A",
    )
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.grid(True, which="major", color="#D6D6D6", linewidth=0.6, alpha=0.85)
    ax.set_axisbelow(True)
    ax.legend(
        loc="upper left",
        frameon=True,
        framealpha=0.96,
        edgecolor="#BDBDBD",
        handlelength=2.2,
        borderpad=0.4,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / "figure6_model_update.pdf", format="pdf", bbox_inches="tight")
    fig.savefig(output_dir / "figure6_model_update.png", dpi=400, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build Figure 6 from freshly measured FS key-update costs."
    )
    parser.add_argument("--fsdbs-raw", type=Path, nargs="+", required=True)
    parser.add_argument("--afi06-raw", type=Path, nargs="+", required=True)
    parser.add_argument("--summary-dir", type=Path, required=True)
    parser.add_argument("--figure-dir", type=Path, required=True)
    parser.add_argument("--tree-depth", type=int, default=20)
    parser.add_argument("--releases-per-epoch", type=int, default=5)
    args = parser.parse_args()

    if args.releases_per_epoch <= 0:
        raise ValueError("releases per epoch must be positive")
    fsdbs, fsdbs_raw = aggregate_raw_measurements(
        args.fsdbs_raw, "FS-DBS", args.tree_depth
    )
    afi06, afi06_raw = aggregate_raw_measurements(
        args.afi06_raw, "AFI06", args.tree_depth
    )
    measurements = {"FS-DBS": fsdbs, "AFI06": afi06}
    releases = [5, 10, 20, 40, 60, 80, 100]
    rows = build_rows(measurements, releases, args.releases_per_epoch)

    args.summary_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([fsdbs, afi06]).to_csv(
        args.summary_dir / "figure6_keyupdate_measurements.csv", index=False
    )
    pd.DataFrame(fsdbs_raw + afi06_raw).to_csv(
        args.summary_dir / "figure6_keyupdate_raw_combined.csv", index=False
    )
    data = pd.DataFrame(rows)
    data.to_csv(args.summary_dir / "figure6_model_update.csv", index=False)

    sensitivity_rows: list[dict[str, object]] = []
    for frequency in [1, 5, 10]:
        sensitivity_rows.extend(build_rows(measurements, releases, frequency))
    pd.DataFrame(sensitivity_rows).to_csv(
        args.summary_dir / "figure6_keyupdate_sensitivity.csv", index=False
    )

    definition = (
        "Figure 6 experiment definition\n"
        "================================\n"
        "Metric: cumulative measured KeyUpdate time only.\n"
        f"Tree depth: {args.tree_depth}.\n"
        f"Key epoch: {args.releases_per_epoch} model releases.\n"
        f"Independent runs per scheme: {len(args.fsdbs_raw)}.\n"
        f"Timed samples per scheme: {measurements['FS-DBS']['samples']}.\n"
        "Initial condition: setup leaves each device at the tree root; one "
        "KeyUpdate enters the first epoch.\n"
        "Update count: ceil(model releases / releases per key epoch).\n"
        "Schemes: FS-DBS and AFI06, because these benchmark implementations "
        "both provide forward-secure KeyUpdate.\n"
        "The same epoch policy is applied to both schemes. Encryption and "
        "decryption are reported separately in Figures 1 and 2.\n"
        "Security granularity: forward security is enforced between key epochs, "
        "not between releases that share one epoch. A compromise can therefore "
        "expose other releases in the current epoch, but not earlier epochs.\n"
        "\nRaw sources:\n"
        + "\n".join(str(path.resolve()) for path in args.fsdbs_raw + args.afi06_raw)
        + "\n"
    )
    (args.summary_dir / "figure6_experiment_definition.txt").write_text(
        definition, encoding="utf-8"
    )
    plot(data, args.figure_dir)


if __name__ == "__main__":
    main()
