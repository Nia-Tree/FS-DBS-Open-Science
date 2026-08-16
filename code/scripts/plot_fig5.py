import argparse
from pathlib import Path

import pandas as pd

from plot_common import draw_series, finish, new_figure


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
parser.add_argument("--figures", type=Path, default=Path("figures"))
args = parser.parse_args()

data = pd.read_csv(args.results / "summary/figure5_secret_key_size.csv")
fig, ax = new_figure()
draw_series(ax, data, "tree_depth", "serialized_bytes")
finish(
    ax,
    "Secret-Key Storage",
    "Time-Tree Depth d",
    "Serialized Secret Key (Bytes)",
    args.figures,
    "figure5_secret_key_size",
)
