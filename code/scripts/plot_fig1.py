import argparse
from pathlib import Path

import pandas as pd

from plot_common import draw_series, finish, new_figure


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
parser.add_argument("--figures", type=Path, default=Path("figures"))
args = parser.parse_args()

data = pd.read_csv(args.results / "summary/figure1_encrypt_time.csv")
fig, ax = new_figure(wide=True)
draw_series(ax, data, "axis_value", "median_ms")
finish(
    ax,
    "Signcryption Time",
    "Number of Receivers |S|",
    "Median Time (ms)",
    args.figures,
    "figure1_encrypt_time",
)
