import argparse
from pathlib import Path

import pandas as pd

from plot_common import draw_series, finish, new_figure


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
parser.add_argument("--figures", type=Path, default=Path("figures"))
args = parser.parse_args()

data = pd.read_csv(args.results / "summary/figure3_update_time.csv")
fig, ax = new_figure()
draw_series(ax, data, "tree_depth", "median_ms")
finish(
    ax,
    "Key Update Time",
    "Time-Tree Depth d",
    "Time (ms)",
    args.figures,
    "figure3_update_time",
)
