import argparse
from pathlib import Path

import pandas as pd

from plot_common import draw_series, finish, new_figure


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
parser.add_argument("--figures", type=Path, default=Path("figures"))
args = parser.parse_args()

data = pd.read_csv(args.results / "summary/figure6_model_update.csv")
fig, ax = new_figure(wide=True)
draw_series(ax, data, "periods", "cumulative_security_layer_s")
finish(
    ax,
    "Cumulative Model-Update Overhead",
    "Number of Model Update Periods",
    "Security-Layer Time (s)",
    args.figures,
    "figure6_model_update",
)
