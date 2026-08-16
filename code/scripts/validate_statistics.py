import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, required=True)
args = parser.parse_args()

receiver_key_columns = ("scheme", "phase", "axis_name", "axis_value")
stat_columns = (
    "mean_ms",
    "median_ms",
    "stddev_ms",
    "min_ms",
    "max_ms",
    "ci95_low_ms",
    "ci95_high_ms",
)
validated_rows = 0

raw_directory = args.results / "raw"
raw_paths = set(raw_directory.glob("figure*_time_raw.csv"))
raw_paths.update(raw_directory.glob("figure*_times_raw.csv"))

for raw_path in sorted(raw_paths):
    summary_path = args.results / "summary" / raw_path.name.replace("_raw.csv", ".csv")
    if not summary_path.is_file():
        raise SystemExit(f"missing summary for {raw_path}")

    depth_summary = raw_path.name.startswith("figure3_")
    groups = defaultdict(list)
    with raw_path.open(newline="", encoding="utf-8") as handle:
        raw_rows = list(csv.DictReader(handle))
        for row in raw_rows:
            if depth_summary:
                key = (row["scheme"], row["axis_value"])
            else:
                key = tuple(row[column] for column in receiver_key_columns)
            groups[key].append(float(row["elapsed_ms"]))

    with summary_path.open(newline="", encoding="utf-8") as handle:
        parsed_summary = list(csv.DictReader(handle))
        if parsed_summary and "tree_depth" in parsed_summary[0]:
            summary_rows = {
                (row["scheme"], row["tree_depth"]): row for row in parsed_summary
            }
        else:
            summary_rows = {
                tuple(row[column] for column in receiver_key_columns): row
                for row in parsed_summary
            }

    if groups.keys() != summary_rows.keys():
        raise SystemExit(f"raw/summary group mismatch for {raw_path.name}")

    for key, samples in groups.items():
        count = len(samples)
        if count < 2:
            raise SystemExit(f"fewer than two samples for {key}")
        mean = statistics.fmean(samples)
        stddev = statistics.stdev(samples)
        half_width = 1.96 * stddev / math.sqrt(count)
        expected = {
            "mean_ms": mean,
            "median_ms": statistics.median(samples),
            "stddev_ms": stddev,
            "min_ms": min(samples),
            "max_ms": max(samples),
            "ci95_low_ms": mean - half_width,
            "ci95_high_ms": mean + half_width,
        }
        actual = summary_rows[key]
        if int(actual["samples"]) != count:
            raise SystemExit(f"sample-count mismatch for {key}")
        for column in stat_columns:
            if not math.isclose(float(actual[column]), expected[column], abs_tol=1e-8):
                raise SystemExit(
                    f"{column} mismatch for {key}: "
                    f"{actual[column]} != {expected[column]:.12f}"
                )
        validated_rows += 1

print(f"Validated {validated_rows} timing summaries against raw samples in {args.results}")
