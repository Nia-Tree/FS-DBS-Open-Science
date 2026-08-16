import argparse
import csv
import math
from pathlib import Path


parser = argparse.ArgumentParser(
    description="Audit interior timing points without assuming monotonicity."
)
parser.add_argument("--results", type=Path, required=True)
parser.add_argument("--relative_threshold", type=float, default=0.20)
parser.add_argument("--standard_error_multiplier", type=float, default=3.0)
parser.add_argument("--report", type=Path)
args = parser.parse_args()

files = ("figure1_encrypt_time.csv", "figure2_decrypt_time.csv")
lines = [
    "Curve audit",
    f"Relative threshold: {args.relative_threshold:.1%}",
    f"Standard-error multiplier: {args.standard_error_multiplier:g}",
]
flagged = []

for filename in files:
    path = args.results / "summary" / filename
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    schemes = []
    for row in rows:
        if row["scheme"] not in schemes:
            schemes.append(row["scheme"])
    lines.append(f"\n{filename}")
    for scheme in schemes:
        points = sorted(
            (row for row in rows if row["scheme"] == scheme),
            key=lambda row: float(row["axis_value"]),
        )
        scheme_flags = []
        for index in range(1, len(points) - 1):
            before, point, after = points[index - 1 : index + 2]
            expected = (
                float(before["median_ms"]) + float(after["median_ms"])
            ) / 2.0
            deviation = abs(float(point["median_ms"]) - expected)
            relative = deviation / expected
            standard_error = float(point["stddev_ms"]) / math.sqrt(
                int(point["samples"])
            )
            if (
                relative > args.relative_threshold
                and deviation > args.standard_error_multiplier * standard_error
            ):
                item = (
                    scheme,
                    int(float(point["axis_value"])),
                    relative,
                    deviation / max(standard_error, 1e-15),
                )
                scheme_flags.append(item)
                flagged.append((filename, *item))
        if scheme_flags:
            rendered = ", ".join(
                f"|S|={axis} ({relative:.1%}, {se_ratio:.1f} SE)"
                for _, axis, relative, se_ratio in scheme_flags
            )
            lines.append(f"- {scheme}: {rendered}")
        else:
            lines.append(f"- {scheme}: PASS")

lines.append(f"\nFlagged points: {len(flagged)}")
report = "\n".join(lines) + "\n"
print(report, end="")
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8", newline="\n")
if flagged:
    raise SystemExit(1)
