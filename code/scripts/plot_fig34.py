import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

from plot_common import configure, draw_series


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, required=True)
parser.add_argument("--figures", type=Path, required=True)
args = parser.parse_args()

encrypt = pd.read_csv(args.results / "summary/figure1_encrypt_time.csv")
decrypt = pd.read_csv(args.results / "summary/figure2_decrypt_time.csv")

configure()
fig, axes = plt.subplots(1, 2, figsize=(7.15, 2.75), constrained_layout=True)

draw_series(axes[0], encrypt, "axis_value", "median_ms")
draw_series(axes[1], decrypt, "axis_value", "median_ms")

for ax in axes:
    ax.set_xlabel("Number of Receivers |S|")
    ax.grid(True, which="major", color="#D7D7D7", linewidth=0.55, alpha=0.8)
    ax.set_axisbelow(True)

axes[0].set_ylabel("Signcryption Time (ms)")
axes[1].set_ylabel("Unsigncryption Time (ms)")

handles, labels = axes[0].get_legend_handles_labels()
fig.legend(
    handles,
    labels,
    loc="upper center",
    bbox_to_anchor=(0.5, 1.12),
    ncol=len(labels),
    frameon=True,
    framealpha=0.95,
    edgecolor="#BDBDBD",
    columnspacing=0.9,
    handlelength=1.8,
    borderpad=0.35,
)

args.figures.mkdir(parents=True, exist_ok=True)
for suffix, options in (("pdf", {}), ("png", {"dpi": 320})):
    fig.savefig(
        args.figures / f"figure34_online_time.{suffix}",
        format=suffix,
        bbox_inches="tight",
        **options,
    )

plt.close(fig)
