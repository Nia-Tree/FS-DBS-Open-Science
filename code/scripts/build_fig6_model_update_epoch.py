import argparse
import math
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCHEME_ORDER = [
    "FS-DBS",
    "KMW23",
    "Lee25-SS",
    "AFI06",
    "Li17-AAGKA",
    "Zhang23-DAAGKA",
]

STYLES = {
    "FS-DBS": dict(color="#1565C0", marker="o", linestyle="-"),
    "KMW23": dict(color="#D84315", marker="s", linestyle="--"),
    "Lee25-SS": dict(color="#2E7D32", marker="^", linestyle="-."),
    "AFI06": dict(color="#6A1B9A", marker="D", linestyle=":"),
    "Li17-AAGKA": dict(color="#00838F", marker="v", linestyle="--"),
    "Zhang23-DAAGKA": dict(color="#C2185B", marker="P", linestyle="-."),
}


def load_release_components(path: Path) -> pd.DataFrame:
    data = pd.read_csv(path)
    data = data[data["periods"] == 1].copy()
    missing = set(SCHEME_ORDER).difference(data["scheme"])
    if missing:
        raise ValueError(f"missing schemes in {path}: {sorted(missing)}")
    if data["scheme"].duplicated().any():
        raise ValueError(f"duplicate period-1 rows in {path}")
    return data.set_index("scheme").loc[SCHEME_ORDER]


def load_update_medians(path: Path) -> dict[str, float]:
    data = pd.read_csv(path)
    medians = dict(zip(data["scheme"], data["median_ms"]))
    for scheme in ("FS-DBS", "AFI06"):
        if scheme not in medians:
            raise ValueError(f"missing fresh {scheme} KeyUpdate measurement in {path}")
    return {scheme: float(medians[scheme]) for scheme in ("FS-DBS", "AFI06")}


def build_rows(
    components: pd.DataFrame,
    update_medians: dict[str, float],
    releases_per_epoch: int,
) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for scheme in SCHEME_ORDER:
        source = components.loc[scheme]
        encrypt_ms = float(source["scheme_encrypt_ms"])
        decrypt_ms = float(source["scheme_decrypt_ms"])
        signature_ms = float(source["signature_ms"])
        verification_ms = float(source["verification_ms"])
        online_per_release_ms = (
            encrypt_ms + decrypt_ms + signature_ms + verification_ms
        )
        supports_key_update = scheme in update_medians
        update_ms = update_medians.get(scheme, 0.0)

        for releases in [1, 5, 10, 20, 50, 100]:
            # A device enters the first authorization epoch from its setup state.
            # The same epoch policy is applied to both forward-secure schemes.
            key_updates = (
                math.ceil(releases / releases_per_epoch)
                if supports_key_update
                else 0
            )
            cumulative_online_ms = releases * online_per_release_ms
            cumulative_update_ms = key_updates * update_ms
            cumulative_security_ms = cumulative_online_ms + cumulative_update_ms
            aes_encrypt_ms = float(source["aes_encrypt_ms"])
            aes_decrypt_ms = float(source["aes_decrypt_ms"])
            cumulative_end_to_end_ms = cumulative_security_ms + releases * (
                aes_encrypt_ms + aes_decrypt_ms
            )
            rows.append(
                {
                    "scheme": scheme,
                    "periods": releases,
                    "model_releases": releases,
                    "supports_key_update": supports_key_update,
                    "releases_per_key_epoch": (
                        releases_per_epoch if supports_key_update else 0
                    ),
                    "key_updates": key_updates,
                    "scheme_encrypt_ms": encrypt_ms,
                    "scheme_decrypt_ms": decrypt_ms,
                    "signature_ms": signature_ms,
                    "verification_ms": verification_ms,
                    "key_update_ms": update_ms,
                    "per_release_online_ms": online_per_release_ms,
                    "cumulative_online_ms": cumulative_online_ms,
                    "cumulative_key_update_ms": cumulative_update_ms,
                    "cumulative_security_layer_ms": cumulative_security_ms,
                    "cumulative_security_layer_s": cumulative_security_ms / 1000.0,
                    "aes_encrypt_ms": aes_encrypt_ms,
                    "aes_decrypt_ms": aes_decrypt_ms,
                    "cumulative_end_to_end_processing_ms": cumulative_end_to_end_ms,
                    "cumulative_end_to_end_processing_s": cumulative_end_to_end_ms
                    / 1000.0,
                }
            )
    return pd.DataFrame(rows)


def plot(data: pd.DataFrame, output_dir: Path, releases_per_epoch: int) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#303030",
            "axes.labelsize": 8.8,
            "axes.titlesize": 9.2,
            "xtick.labelsize": 7.8,
            "ytick.labelsize": 7.8,
            "legend.fontsize": 6.5,
            "font.family": "serif",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, ax = plt.subplots(figsize=(3.45, 3.0), constrained_layout=True)
    for scheme in SCHEME_ORDER:
        group = data[data["scheme"] == scheme].sort_values("model_releases")
        ax.plot(
            group["model_releases"],
            group["cumulative_security_layer_s"],
            label=scheme,
            linewidth=1.9,
            markersize=4.7,
            markeredgecolor="white",
            markeredgewidth=0.65,
            **STYLES[scheme],
        )

    ax.set_title("Cumulative Model-Update Overhead", pad=6)
    ax.set_xlabel("Number of Model Update Periods")
    ax.set_ylabel("Security-Layer Time (s)")
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.grid(True, which="major", color="#D5D5D5", linewidth=0.55, alpha=0.85)
    ax.set_axisbelow(True)
    ax.text(
        0.985,
        0.035,
        f"FS schemes: {releases_per_epoch} releases/key epoch",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=6.3,
        color="#4A4A4A",
    )
    ax.legend(
        loc="upper left",
        ncol=2,
        frameon=True,
        framealpha=0.96,
        edgecolor="#BDBDBD",
        handlelength=1.8,
        columnspacing=0.75,
        borderpad=0.35,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / "figure6_model_update.pdf", format="pdf", bbox_inches="tight")
    fig.savefig(output_dir / "figure6_model_update.png", dpi=400, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild Figure 6 as cumulative model-update overhead."
    )
    parser.add_argument("--original-figure6", type=Path, required=True)
    parser.add_argument("--fresh-keyupdates", type=Path, required=True)
    parser.add_argument("--summary-dir", type=Path, required=True)
    parser.add_argument("--figure-dir", type=Path, required=True)
    parser.add_argument("--releases-per-epoch", type=int, default=5)
    args = parser.parse_args()
    if args.releases_per_epoch <= 0:
        raise ValueError("releases per epoch must be positive")

    components = load_release_components(args.original_figure6)
    updates = load_update_medians(args.fresh_keyupdates)
    data = build_rows(components, updates, args.releases_per_epoch)
    args.summary_dir.mkdir(parents=True, exist_ok=True)
    data.to_csv(args.summary_dir / "figure6_model_update.csv", index=False)

    sensitivity: list[pd.DataFrame] = []
    for frequency in [1, 5, 10]:
        frame = build_rows(components, updates, frequency)
        frame.insert(3, "sensitivity_releases_per_epoch", frequency)
        sensitivity.append(frame)
    pd.concat(sensitivity, ignore_index=True).to_csv(
        args.summary_dir / "figure6_model_update_sensitivity.csv", index=False
    )

    definition = (
        "Corrected Figure 6 experiment definition\n"
        "========================================\n"
        "Metric: cumulative model-update security-layer time.\n"
        "Each release includes the scheme's measured online encryption, online "
        "decryption, and any required external signature and verification.\n"
        f"FS-DBS and AFI06 invoke KeyUpdate once per {args.releases_per_epoch} "
        "model releases; their fresh 200-sample median KeyUpdate times are "
        f"{updates['FS-DBS']:.4f} ms and {updates['AFI06']:.4f} ms.\n"
        "AES-256-GCM model-body processing and network transfer are common to "
        "all schemes and are excluded from the plotted security-layer metric.\n"
        "Forward-security granularity follows the key epoch: releases within a "
        "compromised current epoch share an evolving state, while completed "
        "epochs remain protected.\n"
        f"Original per-release source: {args.original_figure6.resolve()}\n"
        f"Fresh KeyUpdate source: {args.fresh_keyupdates.resolve()}\n"
    )
    (args.summary_dir / "figure6_experiment_definition.txt").write_text(
        definition, encoding="utf-8"
    )
    plot(data, args.figure_dir, args.releases_per_epoch)


if __name__ == "__main__":
    main()
