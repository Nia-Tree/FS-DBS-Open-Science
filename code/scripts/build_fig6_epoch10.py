import argparse
import math
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCHEMES = [
    "FS-DBS",
    "KMW23",
    "AFI06",
    "Lee25-SS",
    "Li17-AAGKA",
    "Zhang23-DAAGKA",
]

ONLINE_DIRS = {
    "FS-DBS": "fsdbs",
    "KMW23": "kmw23",
    "AFI06": "afi06",
    "Lee25-SS": "lee25-ss",
    "Li17-AAGKA": "li17-aagka",
    "Zhang23-DAAGKA": "zhang23-daagka",
}

STYLES = {
    "FS-DBS": dict(color="#1565C0", marker="o", linestyle="-"),
    "KMW23": dict(color="#D84315", marker="s", linestyle="--"),
    "AFI06": dict(color="#6A1B9A", marker="D", linestyle=":"),
    "Lee25-SS": dict(color="#2E7D32", marker="^", linestyle="-."),
    "Li17-AAGKA": dict(color="#00838F", marker="v", linestyle="--"),
    "Zhang23-DAAGKA": dict(color="#C2185B", marker="P", linestyle="-."),
}

EXTERNAL_AUTH = {"KMW23", "AFI06", "Lee25-SS"}


def median(path: Path) -> float:
    data = pd.read_csv(path)
    if len(data) != 1:
        raise ValueError(f"expected one summary row in {path}, got {len(data)}")
    return float(data.iloc[0]["median_ms"])


def load_online(online_root: Path) -> dict[str, dict[str, float]]:
    result = {}
    for scheme in SCHEMES:
        root = online_root / ONLINE_DIRS[scheme] / "summary"
        result[scheme] = {
            "encrypt_ms": median(root / "figure1_encrypt_time.csv"),
            "decrypt_ms": median(root / "figure2_decrypt_time.csv"),
        }
    return result


def load_application(path: Path) -> dict[str, float]:
    data = pd.read_csv(path).set_index("phase")
    required = {
        "aes_encrypt_ms": "AES-256-GCM Encryption",
        "aes_decrypt_ms": "AES-256-GCM Decryption",
        "signature_ms": "Ed25519 Sign",
        "verification_ms": "Ed25519 Verify",
    }
    return {
        name: float(data.loc[phase, "median_ms"])
        for name, phase in required.items()
    }


def load_rekey_events(
    rekey_path: Path,
    sequence_path: Path,
    epochs: int,
    group_size: int,
) -> tuple[dict[str, list[float]], dict[str, list[float]]]:
    rekey = pd.read_csv(rekey_path)
    sequence = pd.read_csv(sequence_path)
    representative: dict[str, list[float]] = {}
    aggregate: dict[str, list[float]] = {}

    for scheme, representative_factor, aggregate_factor in [
        ("FS-DBS", 2, group_size + 1),
        ("AFI06", 1, group_size),
    ]:
        rows = sequence[sequence["scheme"] == scheme].sort_values("axis_value")
        values = rows["median_ms"].astype(float).tolist()
        if len(values) < epochs:
            raise ValueError(f"{sequence_path} has only {len(values)} events for {scheme}")
        representative[scheme] = [value * representative_factor for value in values[:epochs]]
        aggregate[scheme] = [value * aggregate_factor for value in values[:epochs]]

    for scheme in ["KMW23", "Lee25-SS", "Li17-AAGKA", "Zhang23-DAAGKA"]:
        rep = rekey[
            (rekey["scheme"] == scheme)
            & (rekey["phase"] == "Epoch Rekey / Representative Path")
        ]
        agg = rekey[
            (rekey["scheme"] == scheme)
            & (rekey["phase"] == "Epoch Rekey / Aggregate Work")
        ]
        if len(rep) != 1 or len(agg) != 1:
            raise ValueError(f"missing unique epoch-rekey rows for {scheme}")
        representative[scheme] = [float(rep.iloc[0]["median_ms"])] * epochs
        aggregate[scheme] = [float(agg.iloc[0]["median_ms"])] * epochs
    return representative, aggregate


def build_results(
    online: dict[str, dict[str, float]],
    application: dict[str, float],
    representative_events: dict[str, list[float]],
    aggregate_events: dict[str, list[float]],
    group_size: int,
    releases_per_epoch: int,
    max_releases: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    critical_rows = []
    aggregate_rows = []
    shares = []
    for scheme in SCHEMES:
        external = scheme in EXTERNAL_AUTH
        signature_ms = application["signature_ms"] if external else 0.0
        verification_ms = application["verification_ms"] if external else 0.0
        encrypt_ms = online[scheme]["encrypt_ms"]
        decrypt_ms = online[scheme]["decrypt_ms"]
        critical_online_ms = encrypt_ms + decrypt_ms + signature_ms + verification_ms
        aggregate_online_ms = (
            encrypt_ms
            + signature_ms
            + group_size * (decrypt_ms + verification_ms)
        )
        for releases in range(max_releases + 1):
            events = min(releases // releases_per_epoch, len(representative_events[scheme]))
            critical_rekey_ms = sum(representative_events[scheme][:events])
            aggregate_rekey_ms = sum(aggregate_events[scheme][:events])
            critical_security_ms = releases * critical_online_ms + critical_rekey_ms
            aggregate_security_ms = releases * aggregate_online_ms + aggregate_rekey_ms
            critical_rows.append(
                {
                    "scheme": scheme,
                    "model_releases": releases,
                    "epoch_events": events,
                    "group_size": group_size,
                    "encrypt_ms_per_release": encrypt_ms,
                    "decrypt_ms_per_release": decrypt_ms,
                    "signature_ms_per_release": signature_ms,
                    "verification_ms_per_release": verification_ms,
                    "online_ms_per_release": critical_online_ms,
                    "cumulative_online_ms": releases * critical_online_ms,
                    "cumulative_epoch_ms": critical_rekey_ms,
                    "cumulative_security_ms": critical_security_ms,
                    "cumulative_security_s": critical_security_ms / 1000.0,
                    "cumulative_end_to_end_ms": critical_security_ms
                    + releases
                    * (application["aes_encrypt_ms"] + application["aes_decrypt_ms"]),
                }
            )
            aggregate_rows.append(
                {
                    "scheme": scheme,
                    "model_releases": releases,
                    "epoch_events": events,
                    "group_size": group_size,
                    "sender_online_ms_per_release": encrypt_ms + signature_ms,
                    "receiver_online_ms_per_release": decrypt_ms + verification_ms,
                    "aggregate_online_ms_per_release": aggregate_online_ms,
                    "cumulative_online_ms": releases * aggregate_online_ms,
                    "cumulative_epoch_ms": aggregate_rekey_ms,
                    "cumulative_security_ms": aggregate_security_ms,
                    "cumulative_security_s": aggregate_security_ms / 1000.0,
                    "cumulative_end_to_end_ms": aggregate_security_ms
                    + releases
                    * (
                        application["aes_encrypt_ms"]
                        + group_size * application["aes_decrypt_ms"]
                    ),
                }
            )

        final_online_critical = max_releases * critical_online_ms
        final_rekey_critical = sum(representative_events[scheme])
        final_critical = final_online_critical + final_rekey_critical
        final_online_aggregate = max_releases * aggregate_online_ms
        final_rekey_aggregate = sum(aggregate_events[scheme])
        final_aggregate = final_online_aggregate + final_rekey_aggregate
        critical_aead_ms = max_releases * (
            application["aes_encrypt_ms"] + application["aes_decrypt_ms"]
        )
        critical_end_to_end_ms = final_critical + critical_aead_ms
        aggregate_aead_ms = max_releases * (
            application["aes_encrypt_ms"]
            + group_size * application["aes_decrypt_ms"]
        )
        aggregate_end_to_end_ms = final_aggregate + aggregate_aead_ms
        shares.append(
            {
                "scheme": scheme,
                "model_releases": max_releases,
                "epoch_events": max_releases // releases_per_epoch,
                "critical_online_ms": final_online_critical,
                "critical_epoch_ms": final_rekey_critical,
                "critical_total_ms": final_critical,
                "critical_online_share_pct": 100.0 * final_online_critical / final_critical,
                "critical_epoch_share_pct": 100.0 * final_rekey_critical / final_critical,
                "critical_aead_ms": critical_aead_ms,
                "critical_end_to_end_ms": critical_end_to_end_ms,
                "critical_online_share_of_end_to_end_pct": 100.0
                * final_online_critical
                / critical_end_to_end_ms,
                "critical_epoch_share_of_end_to_end_pct": 100.0
                * final_rekey_critical
                / critical_end_to_end_ms,
                "critical_aead_share_of_end_to_end_pct": 100.0
                * critical_aead_ms
                / critical_end_to_end_ms,
                "aggregate_online_ms": final_online_aggregate,
                "aggregate_epoch_ms": final_rekey_aggregate,
                "aggregate_total_ms": final_aggregate,
                "aggregate_online_share_pct": 100.0
                * final_online_aggregate
                / final_aggregate,
                "aggregate_epoch_share_pct": 100.0
                * final_rekey_aggregate
                / final_aggregate,
                "aggregate_aead_ms": aggregate_aead_ms,
                "aggregate_end_to_end_ms": aggregate_end_to_end_ms,
                "aggregate_online_share_of_end_to_end_pct": 100.0
                * final_online_aggregate
                / aggregate_end_to_end_ms,
                "aggregate_epoch_share_of_end_to_end_pct": 100.0
                * final_rekey_aggregate
                / aggregate_end_to_end_ms,
                "aggregate_aead_share_of_end_to_end_pct": 100.0
                * aggregate_aead_ms
                / aggregate_end_to_end_ms,
            }
        )
    return pd.DataFrame(critical_rows), pd.DataFrame(aggregate_rows), pd.DataFrame(shares)


def plot(critical: pd.DataFrame, aggregate: pd.DataFrame, output_dir: Path) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#303030",
            "axes.labelsize": 8.3,
            "axes.titlesize": 8.6,
            "xtick.labelsize": 7.4,
            "ytick.labelsize": 7.4,
            "legend.fontsize": 6.4,
            "font.family": "serif",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, axes = plt.subplots(2, 1, figsize=(3.45, 5.05), sharex=True)
    for ax, data, title in [
        (axes[0], critical, "(a) One sender and one receiver"),
        (axes[1], aggregate, "(b) Single-core-equivalent group work"),
    ]:
        for scheme in SCHEMES:
            group = data[data["scheme"] == scheme]
            ax.plot(
                group["model_releases"],
                group["cumulative_security_s"],
                label=scheme,
                linewidth=1.9,
                markersize=4.2,
                markevery=10,
                markeredgecolor="white",
                markeredgewidth=0.55,
                **STYLES[scheme],
            )
        ax.set_title(title, pad=4)
        ax.set_ylabel("Security-layer time (s)")
        ax.set_xlim(0, 100)
        ax.set_ylim(bottom=0)
        ax.grid(True, color="#D5D5D5", linewidth=0.5, alpha=0.85)
        ax.set_axisbelow(True)
    axes[1].set_xlabel("Number of model releases")
    axes[1].set_xticks([0, 20, 40, 60, 80, 100])
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.995),
        ncol=2,
        frameon=True,
        framealpha=0.97,
        edgecolor="#BDBDBD",
        handlelength=2.2,
        columnspacing=0.9,
        borderpad=0.35,
    )
    fig.subplots_adjust(top=0.865, bottom=0.09, left=0.19, right=0.97, hspace=0.30)
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / "figure6_model_update.pdf", bbox_inches="tight")
    fig.savefig(output_dir / "figure6_model_update.png", dpi=500, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online-root", type=Path, required=True)
    parser.add_argument("--rekey-summary", type=Path, required=True)
    parser.add_argument("--sequence-summary", type=Path, required=True)
    parser.add_argument("--application-summary", type=Path, required=True)
    parser.add_argument("--summary-dir", type=Path, required=True)
    parser.add_argument("--figure-dir", type=Path, required=True)
    parser.add_argument("--group-size", type=int, default=100)
    parser.add_argument("--releases-per-epoch", type=int, default=10)
    parser.add_argument("--max-releases", type=int, default=100)
    args = parser.parse_args()
    epochs = math.ceil(args.max_releases / args.releases_per_epoch)

    online = load_online(args.online_root)
    application = load_application(args.application_summary)
    representative, aggregate = load_rekey_events(
        args.rekey_summary,
        args.sequence_summary,
        epochs,
        args.group_size,
    )
    critical, aggregate_data, shares = build_results(
        online,
        application,
        representative,
        aggregate,
        args.group_size,
        args.releases_per_epoch,
        args.max_releases,
    )
    args.summary_dir.mkdir(parents=True, exist_ok=True)
    critical.to_csv(args.summary_dir / "figure6_critical_path.csv", index=False)
    aggregate_data.to_csv(args.summary_dir / "figure6_aggregate_work.csv", index=False)
    shares.to_csv(args.summary_dir / "figure6_cost_shares.csv", index=False)

    event_rows = []
    for scheme in SCHEMES:
        for event, (rep, agg) in enumerate(
            zip(representative[scheme], aggregate[scheme]), start=1
        ):
            event_rows.append(
                {
                    "scheme": scheme,
                    "epoch_event": event,
                    "after_model_release": event * args.releases_per_epoch,
                    "representative_path_ms": rep,
                    "aggregate_work_ms": agg,
                }
            )
    pd.DataFrame(event_rows).to_csv(
        args.summary_dir / "figure6_epoch_events.csv", index=False
    )
    pd.DataFrame(
        [
            {"component": key, "median_ms": value}
            for key, value in application.items()
        ]
    ).to_csv(args.summary_dir / "figure6_application_components.csv", index=False)

    definition = f"""Figure 6 experiment definition
================================
Authorized receivers: {args.group_size}
Registered slots: 1024
Time-tree depth: 20
Epoch policy: one state transition or re-agreement after every {args.releases_per_epoch} completed model releases
Maximum releases: {args.max_releases}
Epoch events included at release r: floor(r/{args.releases_per_epoch})
Critical path: one sender online operation, one representative receiver online operation, and the representative epoch path.
Aggregate work: one sender online operation, {args.group_size} receiver online operations, and all epoch work, expressed as sequential single-core-equivalent computation.
FS-DBS representative epoch path: provider KeyUpdate plus one receiver KeyUpdate.
FS-DBS aggregate epoch work: provider KeyUpdate plus {args.group_size} receiver KeyUpdates.
AFI06 representative/aggregate epoch work: one/{args.group_size} receiver KeyUpdates.
KMW23 and Lee25-SS: fresh independent receiver key pairs; this is an operational epoch-reset baseline, not a forward-security claim for the source schemes.
Li17-AAGKA and Zhang23-DAAGKA: complete Agreement plus Enc.KeyGen and one/all Dec.KeyGen operations.
All plotted values exclude common AES-256-GCM model-body processing and network transfer. End-to-end columns retain the measured common AEAD cost.
Pairing preprocessing: disabled. Formula-level set/time preparation follows each implementation's audited online/offline boundary.
Statistic: median wall-clock time from Release builds; all raw samples remain in the source result directories.
"""
    (args.summary_dir / "figure6_experiment_definition.txt").write_text(
        definition, encoding="ascii"
    )
    plot(critical, aggregate_data, args.figure_dir)


if __name__ == "__main__":
    main()
