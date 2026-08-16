import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import FixedLocator, FuncFormatter


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
LOCAL_PATH = "Epoch Local / Participant Path"


def median(path: Path) -> float:
    data = pd.read_csv(path)
    if len(data) != 1:
        raise ValueError(f"expected one summary row in {path}, got {len(data)}")
    return float(data.iloc[0]["median_ms"])


def load_online(online_root: Path) -> dict[str, dict[str, float]]:
    values = {}
    for scheme in SCHEMES:
        summary = online_root / ONLINE_DIRS[scheme] / "summary"
        values[scheme] = {
            "encrypt_ms": median(summary / "figure1_encrypt_time.csv"),
            "decrypt_ms": median(summary / "figure2_decrypt_time.csv"),
        }
    return values


def load_auth(application_summary: Path) -> tuple[float, float]:
    data = pd.read_csv(application_summary).set_index("phase")
    return (
        float(data.loc["Ed25519 Sign", "median_ms"]),
        float(data.loc["Ed25519 Verify", "median_ms"]),
    )


def load_local_events(local_summary: Path, epochs: int) -> tuple[dict, pd.DataFrame]:
    data = pd.read_csv(local_summary)
    paths = data[data["phase"] == LOCAL_PATH].copy()
    events = {}
    for scheme in SCHEMES:
        rows = paths[paths["scheme"] == scheme].sort_values("axis_value")
        if len(rows) != epochs:
            raise ValueError(
                f"expected {epochs} local-path rows for {scheme}, got {len(rows)}"
            )
        if rows["axis_value"].astype(int).tolist() != list(range(1, epochs + 1)):
            raise ValueError(f"nonconsecutive epoch events for {scheme}")
        events[scheme] = rows["median_ms"].astype(float).tolist()
    return events, data


def build_results(
    online: dict[str, dict[str, float]],
    signature_ms: float,
    verification_ms: float,
    events: dict[str, list[float]],
    releases_per_epoch: int,
    max_releases: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    lifecycle_rows = []
    event_rows = []
    share_rows = []
    for scheme in SCHEMES:
        external_auth = scheme in EXTERNAL_AUTH
        sign = signature_ms if external_auth else 0.0
        verify = verification_ms if external_auth else 0.0
        online_ms = online[scheme]["encrypt_ms"] + online[scheme]["decrypt_ms"] + sign + verify

        for event, epoch_ms in enumerate(events[scheme], start=1):
            event_rows.append(
                {
                    "scheme": scheme,
                    "epoch_event": event,
                    "after_model_release": event * releases_per_epoch,
                    "local_epoch_ms": epoch_ms,
                }
            )

        for releases in range(max_releases + 1):
            event_count = min(releases // releases_per_epoch, len(events[scheme]))
            cumulative_online_ms = releases * online_ms
            cumulative_epoch_ms = sum(events[scheme][:event_count])
            lifecycle_rows.append(
                {
                    "scheme": scheme,
                    "model_releases": releases,
                    "epoch_events": event_count,
                    "encrypt_ms_per_release": online[scheme]["encrypt_ms"],
                    "decrypt_ms_per_release": online[scheme]["decrypt_ms"],
                    "signature_ms_per_release": sign,
                    "verification_ms_per_release": verify,
                    "local_online_ms_per_release": online_ms,
                    "cumulative_online_ms": cumulative_online_ms,
                    "cumulative_local_epoch_ms": cumulative_epoch_ms,
                    "cumulative_security_ms": cumulative_online_ms + cumulative_epoch_ms,
                    "cumulative_security_s": (cumulative_online_ms + cumulative_epoch_ms)
                    / 1000.0,
                }
            )

        final_online = max_releases * online_ms
        final_epoch = sum(events[scheme])
        final_total = final_online + final_epoch
        share_rows.append(
            {
                "scheme": scheme,
                "model_releases": max_releases,
                "epoch_events": len(events[scheme]),
                "local_online_ms": final_online,
                "local_epoch_ms": final_epoch,
                "local_total_ms": final_total,
                "online_share_pct": 100.0 * final_online / final_total,
                "epoch_share_pct": 100.0 * final_epoch / final_total,
            }
        )
    return (
        pd.DataFrame(lifecycle_rows),
        pd.DataFrame(event_rows),
        pd.DataFrame(share_rows),
    )


def build_formal_comparison(
    test_shares: pd.DataFrame, formal_critical: Path
) -> pd.DataFrame:
    formal = pd.read_csv(formal_critical)
    final_release = int(formal["model_releases"].max())
    formal = formal[formal["model_releases"] == final_release][
        ["scheme", "cumulative_security_ms"]
    ].rename(columns={"cumulative_security_ms": "formal_representative_ms"})
    test = test_shares[["scheme", "local_total_ms"]].rename(
        columns={"local_total_ms": "test_local_participant_ms"}
    )
    result = test.merge(formal, on="scheme", how="left")
    result["test_minus_formal_ms"] = (
        result["test_local_participant_ms"] - result["formal_representative_ms"]
    )
    result["test_over_formal_ratio"] = (
        result["test_local_participant_ms"] / result["formal_representative_ms"]
    )
    return result


def plot(lifecycle: pd.DataFrame, event_data: pd.DataFrame, figure_dir: Path) -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#303030",
            "axes.labelsize": 8.2,
            "axes.titlesize": 8.5,
            "xtick.labelsize": 7.3,
            "ytick.labelsize": 7.3,
            "legend.fontsize": 6.25,
            "font.family": "serif",
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )
    fig, axes = plt.subplots(2, 1, figsize=(3.45, 5.05))

    for scheme in SCHEMES:
        rows = lifecycle[lifecycle["scheme"] == scheme]
        style = STYLES[scheme]
        axes[0].plot(
            rows["model_releases"],
            rows["cumulative_security_s"],
            label=scheme,
            linewidth=2.25 if scheme == "FS-DBS" else 1.75,
            markersize=4.2,
            markevery=10,
            markeredgecolor="white",
            markeredgewidth=0.5,
            **style,
        )
    axes[0].set_title("(a) One-participant lifecycle computation", pad=4)
    axes[0].set_xlabel("Number of model releases")
    axes[0].set_ylabel("Cumulative time (s)")
    axes[0].set_xlim(0, 100)
    axes[0].set_ylim(bottom=0)
    axes[0].set_xticks([0, 20, 40, 60, 80, 100])

    for scheme in SCHEMES:
        rows = event_data[event_data["scheme"] == scheme]
        style = STYLES[scheme]
        axes[1].plot(
            rows["epoch_event"],
            rows["local_epoch_ms"],
            linewidth=2.25 if scheme == "FS-DBS" else 1.75,
            markersize=4.3,
            markeredgecolor="white",
            markeredgewidth=0.5,
            **style,
        )
    axes[1].set_title("(b) One-participant epoch computation", pad=4)
    axes[1].set_xlabel("Epoch event (one per 10 releases)")
    axes[1].set_ylabel("Local epoch time (ms, log)")
    axes[1].set_xlim(1, 10)
    axes[1].set_xticks([1, 2, 4, 6, 8, 10])
    axes[1].set_yscale("log")
    axes[1].set_ylim(3.8, 125)
    axes[1].yaxis.set_major_locator(FixedLocator([5, 10, 20, 50, 100]))
    axes[1].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}"))

    for ax in axes:
        ax.grid(True, which="major", color="#D4D4D4", linewidth=0.5, alpha=0.9)
        ax.set_axisbelow(True)

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
        columnspacing=0.85,
        borderpad=0.35,
    )
    fig.subplots_adjust(top=0.865, bottom=0.09, left=0.19, right=0.97, hspace=0.42)
    figure_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(figure_dir / "figure6_model_update_test.pdf", bbox_inches="tight")
    fig.savefig(
        figure_dir / "figure6_model_update_test.png",
        dpi=500,
        bbox_inches="tight",
    )
    plt.close(fig)


def write_definition(
    path: Path,
    group_size: int,
    releases_per_epoch: int,
    max_releases: int,
    local_summary: Path,
) -> None:
    text = f"""TEST-ONLY Figure 6 alternative: local-participant accounting
================================================================
Purpose: sensitivity analysis of per-device cryptographic CPU time under ideal participant parallelism.
Authorized receivers: {group_size}
Registered slots: 1024
Time-tree depth: 20
Epoch policy: one local refresh after every {releases_per_epoch} completed model releases
Maximum releases: {max_releases}
Online work per release: one sender operation plus one receiver operation; external Ed25519 authentication is added only to schemes without integrated authentication.
FS-DBS epoch work: one sender KeyUpdate. Receiver KeyUpdate is excluded.
AFI06 epoch work: one member's forward-secure state update.
KMW23 and Lee25-SS epoch work: one user's fresh public/private key pair. This is an operational reset baseline and is not a forward-security claim for either source scheme.
Li17-AAGKA and Zhang23-DAAGKA epoch work: one member's agreement contribution plus that same member's Dec.KeyGen from an already available group aggregate.
Excluded: coordinator aggregation, every other participant, public-key redistribution, protocol messages, network latency, synchronization, and slowest-member waiting time.
Interpretation: this test estimates local CPU burden, not full agreement latency, total group work, or cloud-operator cost. The formal Figure 6 remains the complete accounting comparison.
Pairing preprocessing: disabled.
Statistic: median wall-clock time from Release builds; no outliers removed.
Local source summary: {local_summary}
"""
    path.write_text(text, encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--online-root", type=Path, required=True)
    parser.add_argument("--local-summary", type=Path, required=True)
    parser.add_argument("--application-summary", type=Path, required=True)
    parser.add_argument("--formal-critical", type=Path, required=True)
    parser.add_argument("--summary-dir", type=Path, required=True)
    parser.add_argument("--figure-dir", type=Path, required=True)
    parser.add_argument("--group-size", type=int, default=100)
    parser.add_argument("--releases-per-epoch", type=int, default=10)
    parser.add_argument("--max-releases", type=int, default=100)
    args = parser.parse_args()

    epochs = args.max_releases // args.releases_per_epoch
    if epochs * args.releases_per_epoch != args.max_releases:
        raise ValueError("max-releases must be divisible by releases-per-epoch")

    online = load_online(args.online_root)
    signature_ms, verification_ms = load_auth(args.application_summary)
    events, complete_local = load_local_events(args.local_summary, epochs)
    lifecycle, event_data, shares = build_results(
        online,
        signature_ms,
        verification_ms,
        events,
        args.releases_per_epoch,
        args.max_releases,
    )
    comparison = build_formal_comparison(shares, args.formal_critical)

    args.summary_dir.mkdir(parents=True, exist_ok=True)
    lifecycle.to_csv(args.summary_dir / "figure6_local_lifecycle_test.csv", index=False)
    event_data.to_csv(args.summary_dir / "figure6_epoch_events_test.csv", index=False)
    shares.to_csv(args.summary_dir / "figure6_cost_shares_test.csv", index=False)
    comparison.to_csv(
        args.summary_dir / "figure6_formal_vs_test_comparison.csv", index=False
    )
    complete_local.to_csv(
        args.summary_dir / "figure6_local_components_test.csv", index=False
    )
    write_definition(
        args.summary_dir / "figure6_experiment_definition_test.txt",
        args.group_size,
        args.releases_per_epoch,
        args.max_releases,
        args.local_summary,
    )
    plot(lifecycle, event_data, args.figure_dir)


if __name__ == "__main__":
    main()
