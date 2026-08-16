import argparse
import subprocess
import sys
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument(
    "--scheme",
    default="FS-DBS",
    choices=[
        "FS-DBS",
        "KMW23",
        "AFI06",
        "Lee25-SS",
        "Li17-AAGKA",
        "Zhang23-DAAGKA",
        "Selvi09",
        "Gao25",
    ],
)
parser.add_argument("--fig", type=int)
parser.add_argument("--repetitions", type=int, default=100)
parser.add_argument("--warmup", type=int, default=20)
parser.add_argument("--inner_iterations", type=int, default=1)
parser.add_argument("--receiver_sizes", default="10,50,100,200,500,1000")
parser.add_argument("--max_users", type=int, default=1024)
parser.add_argument("--tree_depth", type=int, default=20)
parser.add_argument("--tree_depths", default="8,12,16,20,24")
parser.add_argument("--model_path", type=Path)
parser.add_argument("--comparison_results", type=Path, default=Path("results/comparison"))
parser.add_argument("--seed", type=int, default=20260810)
parser.add_argument("--output", type=Path, default=Path("results"))
parser.add_argument("--no_plots", action="store_true")
args = parser.parse_args()

root = Path(__file__).resolve().parents[1]
cargo_path = Path.home() / ".cargo/bin/cargo.exe"
cargo = str(cargo_path) if cargo_path.is_file() else "cargo"
subprocess.run([cargo, "test", "--release"], cwd=root, check=True)
command = [
    cargo,
    "run",
    "--release",
    "--bin",
    "benchmark_all",
    "--",
    "--scheme",
    args.scheme,
    "--repetitions",
    str(args.repetitions),
    "--warmup",
    str(args.warmup),
    "--inner_iterations",
    str(args.inner_iterations),
    "--receiver_sizes",
    args.receiver_sizes,
    "--max_users",
    str(args.max_users),
    "--tree_depth",
    str(args.tree_depth),
    "--tree_depths",
    args.tree_depths,
    "--seed",
    str(args.seed),
    "--output",
    str(args.output),
    "--comparison_results",
    str(args.comparison_results),
]
if args.fig is not None:
    command.extend(["--fig", str(args.fig)])
if args.model_path is not None:
    command.extend(["--model_path", str(args.model_path)])
if args.no_plots:
    command.append("--no_plots")
subprocess.run(command, cwd=root, check=True)
subprocess.run(
    [sys.executable, "scripts/summarize_results.py", "--results", str(args.output)],
    cwd=root,
    check=True,
)
