import argparse
from pathlib import Path

import pandas as pd


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
args = parser.parse_args()

summary_dir = args.results / "summary"
frames = []
for path in sorted(summary_dir.glob("figure*_time.csv")):
    frame = pd.read_csv(path)
    frame.insert(0, "source_file", path.name)
    frames.append(frame)
if frames:
    pd.concat(frames, ignore_index=True).to_csv(
        summary_dir / "all_timing_summaries.csv", index=False
    )
print(f"Validated summary directory: {summary_dir}")
