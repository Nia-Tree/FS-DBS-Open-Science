import argparse
import shutil
from pathlib import Path

import pandas as pd


parser = argparse.ArgumentParser()
parser.add_argument("--inputs", type=Path, nargs="+", required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--exclude_schemes", nargs="*", default=[])
args = parser.parse_args()

inputs = [path.resolve() for path in args.inputs]
output = args.output.resolve()
raw_output = output / "raw"
summary_output = output / "summary"
raw_output.mkdir(parents=True, exist_ok=True)
summary_output.mkdir(parents=True, exist_ok=True)


def concatenate(relative_path: str, subset: list[str]) -> None:
    frames = []
    for source in inputs:
        path = source / relative_path
        if path.is_file():
            frames.append(pd.read_csv(path))
    if not frames:
        return
    combined = pd.concat(frames, ignore_index=True)
    if "scheme" in combined.columns and args.exclude_schemes:
        combined = combined[~combined["scheme"].isin(args.exclude_schemes)]
    combined = combined.drop_duplicates(subset=subset, keep="last")
    combined.to_csv(output / relative_path, index=False)


for stem in ("figure1_encrypt_time", "figure2_decrypt_time"):
    concatenate(
        f"raw/{stem}_raw.csv",
        ["scheme", "phase", "axis_name", "axis_value", "sample"],
    )
    concatenate(
        f"summary/{stem}.csv",
        ["scheme", "phase", "axis_name", "axis_value"],
    )

concatenate(
    "summary/figure4_ciphertext_size.csv", ["scheme", "receiver_size"]
)

# Only evolving-key schemes contribute to these depth-dependent figures, but
# more than one audited scheme may contribute rows.
concatenate(
    "raw/figure3_update_time_raw.csv",
    ["scheme", "phase", "axis_name", "axis_value", "sample"],
)
concatenate("summary/figure3_update_time.csv", ["scheme", "tree_depth"])
concatenate("summary/figure5_secret_key_size.csv", ["scheme", "tree_depth"])

# The last phase contains the latest audited capabilities and operation counts.
for name in (
    "table_operation_counts.csv",
    "table_security_features.csv",
    "figure6_component_times.csv",
    "figure6_model_update.csv",
    "figure6_model_update_end_to_end.csv",
):
    for source in reversed(inputs):
        source_path = source / "summary" / name
        if source_path.is_file():
            shutil.copy2(source_path, summary_output / name)
            break

for name in ("figure6_component_times_raw.csv",):
    for source in reversed(inputs):
        source_path = source / "raw" / name
        if source_path.is_file():
            shutil.copy2(source_path, raw_output / name)
            break

timing_frames = []
for path in sorted(summary_output.glob("figure*_time.csv")):
    frame = pd.read_csv(path)
    frame.insert(0, "source_file", path.name)
    timing_frames.append(frame)
if timing_frames:
    pd.concat(timing_frames, ignore_index=True).to_csv(
        summary_output / "all_timing_summaries.csv", index=False
    )

with (output / "provenance.txt").open("w", encoding="utf-8", newline="\n") as handle:
    handle.write("Combined benchmark inputs:\n")
    for source in inputs:
        handle.write(f"- {source}\n")
        environment = source / "environment.txt"
        if environment.is_file():
            handle.write(environment.read_text(encoding="utf-8"))
            handle.write("\n")

print(f"Combined {len(inputs)} phase directories into {output}")
