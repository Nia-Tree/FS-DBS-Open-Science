import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


STYLES = {
    "FS-DBS": ("#1565C0", "o", "-"),
    "KMW23": ("#D84315", "s", "--"),
    "Lee25-SS": ("#2E7D32", "^", "-."),
    "AFI06": ("#6A1B9A", "D", ":"),
    "Li17-AAGKA": ("#00838F", "v", "--"),
    "Zhang23-DAAGKA": ("#C2185B", "P", "-."),
}
ORDER = list(STYLES)


parser = argparse.ArgumentParser()
parser.add_argument("--results", type=Path, required=True)
parser.add_argument("--figures", type=Path, required=True)
args = parser.parse_args()

data = pd.read_csv(args.results / "summary" / "epoch_transition_time.csv")

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": "#333333",
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 7.5,
        "font.family": "serif",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    }
)
fig, (ax_top, ax_bottom) = plt.subplots(
    2,
    1,
    sharex=True,
    figsize=(3.42, 3.30),
    gridspec_kw={"height_ratios": (0.43, 1.0), "hspace": 0.05},
    constrained_layout=True,
)
for scheme in ORDER:
    group = data[data["scheme"] == scheme].sort_values("axis_value")
    color, marker, linestyle = STYLES[scheme]
    for axis in (ax_top, ax_bottom):
        axis.plot(
            group["axis_value"],
            group["median_ms"],
            color=color,
            marker=marker,
            linestyle=linestyle,
            linewidth=1.8,
            markersize=4.2,
            markeredgewidth=0.8,
            label=scheme,
        )

ax_bottom.set_xlabel("Number of Receivers")
fig.supylabel("Transition Time (ms)", fontsize=8.3)
ax_top.set_ylim(175, 725)
ax_bottom.set_ylim(0, 145)
ax_top.spines["bottom"].set_visible(False)
ax_bottom.spines["top"].set_visible(False)
ax_top.tick_params(axis="x", which="both", bottom=False, labelbottom=False)
ax_bottom.xaxis.tick_bottom()
for axis in (ax_top, ax_bottom):
    axis.set_xlim(80, 1020)
    axis.set_xticks(range(100, 1001, 100))
    axis.grid(True, which="major", color="#D7D7D7", linewidth=0.6, alpha=0.85)
    axis.set_axisbelow(True)

break_style = {
    "marker": [(-1, -0.55), (1, 0.55)],
    "markersize": 2.6,
    "linestyle": "none",
    "color": "#B0B0B0",
    "markeredgewidth": 0.4,
    "clip_on": False,
}
ax_top.plot([0, 1], [0, 0], transform=ax_top.transAxes, **break_style)
ax_bottom.plot([0, 1], [1, 1], transform=ax_bottom.transAxes, **break_style)

handles, labels = ax_bottom.get_legend_handles_labels()
ax_top.legend(
    handles,
    labels,
    loc="lower center",
    bbox_to_anchor=(0.5, 1.01),
    ncol=3,
    frameon=True,
    framealpha=0.96,
    edgecolor="#BDBDBD",
    columnspacing=0.65,
    handlelength=1.5,
    handletextpad=0.35,
    borderpad=0.3,
)

args.figures.mkdir(parents=True, exist_ok=True)
for extension, options in (("pdf", {}), ("png", {"dpi": 360})):
    fig.savefig(
        args.figures / f"figure3_epoch_transition_time.{extension}",
        format=extension,
        bbox_inches="tight",
        **options,
    )
plt.close(fig)
