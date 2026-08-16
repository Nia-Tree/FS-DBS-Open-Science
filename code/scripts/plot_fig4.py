import argparse
from pathlib import Path

import pandas as pd

from plot_common import draw_series, finish, new_figure


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, default=Path("results"))
parser.add_argument("--figures", type=Path, default=Path("figures"))
args = parser.parse_args()

data = pd.read_csv(args.results / "summary/figure4_ciphertext_size.csv")
fig, ax = new_figure(wide=True)
draw_series(ax, data, "receiver_size", "cryptographic_ciphertext_bytes")
finish(
    ax,
    "Cryptographic Header Size",
    "Number of Receivers |S|",
    "Header Size (Bytes)",
    args.figures,
    "figure4_ciphertext_size",
)
