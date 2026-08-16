from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt


STYLES = {
    "FS-DBS": {"color": "#1565C0", "marker": "o", "linestyle": "-"},
    "KMW23": {"color": "#D84315", "marker": "s", "linestyle": "--"},
    "Lee25-SS": {"color": "#2E7D32", "marker": "^", "linestyle": "-."},
    "AFI06": {"color": "#6A1B9A", "marker": "D", "linestyle": ":"},
    "Selvi09": {"color": "#00838F", "marker": "v", "linestyle": "--"},
    "Gao25": {"color": "#5D4037", "marker": "P", "linestyle": "-."},
    "Li17-AAGKA": {"color": "#00838F", "marker": "v", "linestyle": "--"},
    "Zhang23-DAAGKA": {"color": "#C2185B", "marker": "P", "linestyle": "-."},
}

SCHEME_ORDER = [
    "FS-DBS",
    "KMW23",
    "Lee25-SS",
    "AFI06",
    "Li17-AAGKA",
    "Zhang23-DAAGKA",
    "Selvi09",
    "Gao25",
]


def configure() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#333333",
            "axes.labelsize": 9,
            "axes.titlesize": 9,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 7.5,
            "font.family": "serif",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def new_figure(wide: bool = False):
    configure()
    size = (5.35, 2.75) if wide else (3.45, 2.65)
    return plt.subplots(figsize=size, constrained_layout=True)


def draw_series(ax, frame, x_column: str, y_column: str) -> None:
    present = set(frame["scheme"])
    ordered = [scheme for scheme in SCHEME_ORDER if scheme in present]
    ordered.extend(sorted(present.difference(ordered)))
    for scheme in ordered:
        group = frame[frame["scheme"] == scheme]
        group = group.sort_values(x_column)
        style = STYLES.get(
            scheme,
            {"color": "#424242", "marker": "x", "linestyle": "-"},
        )
        ax.plot(
            group[x_column],
            group[y_column],
            label=scheme,
            linewidth=1.8,
            markersize=4.6,
            markeredgewidth=0.7,
            **style,
        )


def finish(ax, title: str, xlabel: str, ylabel: str, output_dir: Path, stem: str) -> None:
    ax.set_title(title, pad=5)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, which="major", color="#D7D7D7", linewidth=0.55, alpha=0.8)
    if ax.get_yscale() == "log":
        ax.grid(True, which="minor", color="#ECECEC", linewidth=0.35, alpha=0.65)
    ax.set_axisbelow(True)
    handles, labels = ax.get_legend_handles_labels()
    many_series = len(labels) > 3
    legend_options = {
        "loc": "center left" if many_series else "upper left",
        "ncol": 1,
    }
    if many_series:
        legend_options["bbox_to_anchor"] = (1.01, 0.5)
    ax.legend(
        handles,
        labels,
        frameon=True,
        framealpha=0.95,
        edgecolor="#BDBDBD",
        columnspacing=0.8,
        handlelength=1.8,
        borderpad=0.35,
        **legend_options,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    figure = ax.get_figure()
    figure.savefig(output_dir / f"{stem}.pdf", format="pdf", bbox_inches="tight")
    figure.savefig(output_dir / f"{stem}.png", dpi=320, bbox_inches="tight")
    plt.close(figure)
