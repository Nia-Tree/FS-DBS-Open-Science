from __future__ import annotations

import argparse
import csv
import json
import time
from dataclasses import dataclass
from pathlib import Path

import win32com.client


SCHEME_ORDER = [
    "FS-DBS",
    "KMW23",
    "Lee25-SS",
    "AFI06",
    "Li17-AAGKA",
    "Zhang23-DAAGKA",
]

STYLES = {
    "FS-DBS": ("#1565C0", 1, 1),
    "KMW23": ("#D84315", 2, 2),
    "Lee25-SS": ("#2E7D32", 3, 3),
    "AFI06": ("#6A1B9A", 4, 4),
    "Selvi09": ("#008C95", 5, 2),
    "Gao25": ("#5D4037", 6, 3),
    "Li17-AAGKA": ("#008C95", 5, 2),
    "Zhang23-DAAGKA": ("#C2185B", 6, 3),
}

MARKER_SIZES = {
    "FS-DBS": 10.0,
    "KMW23": 10.5,
    "Lee25-SS": 9.5,
    "AFI06": 9.0,
    "Selvi09": 9.5,
    "Gao25": 9.5,
    "Li17-AAGKA": 9.5,
    "Zhang23-DAAGKA": 9.5,
}


@dataclass(frozen=True)
class AxisBreak:
    start: float
    end: float
    position: float
    increment_after: float | None = None


@dataclass(frozen=True)
class FigureSpec:
    stem: str
    csv_name: str
    book_name: str
    graph_name: str
    long_name: str
    x_column: str
    y_column: str
    x_label: str
    y_label: str
    schemes: tuple[str, ...]
    x_from: float
    x_to: float
    x_inc: float
    y_from: float
    y_to: float
    y_inc: float
    breaks: tuple[AxisBreak, ...] = ()
    legend_x: float | None = None
    legend_y: float | None = None


FIGURES = (
    FigureSpec(
        stem="figure1_encrypt_time",
        csv_name="figure1_encrypt_time.csv",
        book_name="F1Data",
        graph_name="F1Signcrypt",
        long_name="Figure 1 - Signcryption Time",
        x_column="axis_value",
        y_column="median_ms",
        x_label="Number of Receivers |S|",
        y_label="Median Time (ms)",
        schemes=tuple(SCHEME_ORDER),
        x_from=0,
        x_to=1050,
        x_inc=200,
        y_from=0.8,
        y_to=4.2,
        y_inc=0.5,
        legend_x=300,
        legend_y=3.9,
    ),
    FigureSpec(
        stem="figure2_decrypt_time",
        csv_name="figure2_decrypt_time.csv",
        book_name="F2Data",
        graph_name="F2Unsign",
        long_name="Figure 2 - Unsigncryption Time",
        x_column="axis_value",
        y_column="median_ms",
        x_label="Number of Receivers |S|",
        y_label="Median Time (ms)",
        schemes=tuple(SCHEME_ORDER),
        x_from=0,
        x_to=1050,
        x_inc=200,
        y_from=1.5,
        y_to=10.0,
        y_inc=1.0,
        legend_x=180,
        legend_y=9.2,
    ),
    FigureSpec(
        stem="figure3_update_time",
        csv_name="figure3_update_time.csv",
        book_name="F3Data",
        graph_name="F3KeyUpdate",
        long_name="Figure 3 - Key Update Time",
        x_column="tree_depth",
        y_column="median_ms",
        x_label="Time-Tree Depth d",
        y_label="Median Time (ms)",
        schemes=("FS-DBS", "AFI06"),
        x_from=7,
        x_to=25,
        x_inc=4,
        y_from=7,
        y_to=40,
        y_inc=5,
    ),
    FigureSpec(
        stem="figure4_ciphertext_size",
        csv_name="figure4_ciphertext_size.csv",
        book_name="F4Data",
        graph_name="F4HeaderSize",
        long_name="Figure 4 - Cryptographic Header Size",
        x_column="receiver_size",
        y_column="cryptographic_ciphertext_bytes",
        x_label="Number of Receivers |S|",
        y_label="Cryptographic Header Size (Bytes)",
        schemes=tuple(SCHEME_ORDER),
        x_from=0,
        x_to=1050,
        x_inc=200,
        y_from=140,
        y_to=430,
        y_inc=50,
        legend_x=500,
        legend_y=335,
    ),
    FigureSpec(
        stem="figure5_secret_key_size",
        csv_name="figure5_secret_key_size.csv",
        book_name="F5Data",
        graph_name="F5KeySize",
        long_name="Figure 5 - Secret-Key Storage",
        x_column="tree_depth",
        y_column="serialized_bytes",
        x_label="Time-Tree Depth d",
        y_label="Serialized Secret Key (Bytes)",
        schemes=("FS-DBS", "AFI06"),
        x_from=7,
        x_to=25,
        x_inc=4,
        y_from=900,
        y_to=2700,
        y_inc=200,
    ),
    FigureSpec(
        stem="figure6_model_update",
        csv_name="figure6_model_update.csv",
        book_name="F6Data",
        graph_name="F6ModelUpdate",
        long_name="Figure 6 - Cumulative Model-Update Overhead",
        x_column="periods",
        y_column="cumulative_security_layer_s",
        x_label="Number of Model Update Periods",
        y_label="Security-Layer Time (s)",
        schemes=tuple(SCHEME_ORDER),
        x_from=0,
        x_to=105,
        x_inc=20,
        y_from=0,
        y_to=3.8,
        y_inc=0.5,
        legend_x=30,
        legend_y=3.4,
    ),
)


def labtalk_string(value: str) -> str:
    return value.replace("\\", "/").replace('"', '\\"')


def read_wide_data(path: Path, spec: FigureSpec) -> tuple[list[float], dict[str, list[float]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    points: dict[str, dict[float, float]] = {scheme: {} for scheme in spec.schemes}
    for row in rows:
        scheme = row["scheme"]
        if scheme not in points:
            continue
        x_value = float(row[spec.x_column])
        points[scheme][x_value] = float(row[spec.y_column])

    x_values = sorted({x for series in points.values() for x in series})
    if not x_values:
        raise ValueError(f"No plotted rows found in {path}")

    wide: dict[str, list[float]] = {}
    for scheme in spec.schemes:
        missing = [x for x in x_values if x not in points[scheme]]
        if missing:
            raise ValueError(f"{path.name}: {scheme} is missing x values {missing}")
        wide[scheme] = [points[scheme][x] for x in x_values]
    return x_values, wide


def assert_breaks_do_not_hide_data(
    spec: FigureSpec, wide: dict[str, list[float]]
) -> None:
    values = [value for series in wide.values() for value in series]
    for axis_break in spec.breaks:
        hidden = [value for value in values if axis_break.start < value < axis_break.end]
        if hidden:
            raise ValueError(
                f"{spec.stem}: break ({axis_break.start}, {axis_break.end}) hides {hidden}"
            )


def execute(app, command: str) -> None:
    if not app.Execute(command.rstrip(";") + ";"):
        raise RuntimeError(f"Origin rejected LabTalk command: {command}")


def create_book(app, spec: FigureSpec, x_values: list[float], wide: dict[str, list[float]]) -> None:
    book = app.CreatePage(2, spec.book_name, "Origin")
    if not book:
        raise RuntimeError(f"Could not create workbook {spec.book_name}")

    if not app.PutWorksheet(book, x_values, 0, 0):
        raise RuntimeError(f"Could not write X data to {spec.book_name}")
    for column, scheme in enumerate(spec.schemes, start=1):
        if not app.PutWorksheet(book, wide[scheme], 0, column):
            raise RuntimeError(f"Could not write {scheme} data to {spec.book_name}")

    execute(app, f"win -a {spec.book_name}")
    execute(app, f'page.longname$="{labtalk_string(spec.long_name)} - Data"')
    execute(app, f'wks.col1.lname$="{labtalk_string(spec.x_label)}"')
    execute(app, "wks.col1.type=4")
    for column, scheme in enumerate(spec.schemes, start=2):
        execute(app, f'wks.col{column}.lname$="{labtalk_string(scheme)}"')
        execute(app, f"wks.col{column}.type=1")


def style_graph(app, spec: FigureSpec) -> None:
    execute(app, f"win -a {spec.graph_name}")
    execute(app, f'page.longname$="{labtalk_string(spec.long_name)}"')
    execute(app, "page.width=12800; page.height=7200")
    execute(app, "layer.unit=1; layer.left=10; layer.top=8; layer.width=80; layer.height=80")
    execute(app, f'label -xb "{labtalk_string(spec.x_label)}"')
    execute(app, f'label -yl "{labtalk_string(spec.y_label)}"')
    execute(app, "xb.fsize=20; yl.fsize=20")
    execute(app, "layer.x.label.pt=14; layer.y.label.pt=14")
    execute(app, "layer.x.label.font=font(Arial); layer.y.label.font=font(Arial)")
    execute(app, "xb.font=font(Arial); yl.font=font(Arial)")
    execute(app, "layer.x.thickness=1.6; layer.y.thickness=1.6")
    execute(app, "layer.x.tickthickness=1.4; layer.y.tickthickness=1.4")
    execute(app, "layer.x.mtickthickness=1.0; layer.y.mtickthickness=1.0")
    execute(app, "layer.x.ticklength=7; layer.y.ticklength=7")
    execute(app, "layer.x.mticklength=4; layer.y.mticklength=4")
    execute(app, "layer.x.ticks=10; layer.y.ticks=10")
    execute(app, "layer.x.showopposite=1; layer.y.showopposite=1")
    execute(app, "layer.x.grid.show=0; layer.y.grid.show=1")
    execute(app, "layer.y.grid.majorColor=color(232,232,232)")
    execute(app, "layer.y.grid.majorType=1; layer.y.grid.majorWidth=0.65")
    execute(app, f"layer.x.from={spec.x_from}; layer.x.to={spec.x_to}; layer.x.inc={spec.x_inc}")
    execute(app, f"layer.y.from={spec.y_from}; layer.y.to={spec.y_to}; layer.y.inc={spec.y_inc}")
    execute(app, "layer -gu")

    for index, scheme in enumerate(spec.schemes, start=1):
        color, marker, line_style = STYLES[scheme]
        line_width = 3.8 if scheme == "FS-DBS" else 3.2
        execute(app, f'layer.plot{index}.color=color("{color}")')
        execute(app, f"layer.plot{index}.symbol.kind={marker}")
        execute(app, f"layer.plot{index}.symbol.size={MARKER_SIZES[scheme]}")
        execute(app, f"layer.plot{index}.symbol.interior=1")
        execute(app, f"layer.plot{index}.line.type={line_style}")
        execute(app, f"layer.plot{index}.line.width={line_width}")
        execute(app, f"layer.plot{index}.aa=17")

    if spec.breaks:
        execute(app, "layer.y.breaks.enable=1")
        execute(app, f"layer.y.breaks.count={len(spec.breaks)}")
        execute(app, "layer.y.breaks.gap=-7; layer.y.breaks.size=7")
        for index, axis_break in enumerate(spec.breaks, start=1):
            execute(app, f"layer.y.break{index}.from={axis_break.start}")
            execute(app, f"layer.y.break{index}.to={axis_break.end}")
            execute(app, f"layer.y.break{index}.pos={axis_break.position}")
            execute(app, f"layer.y.break{index}.autoscale=0")
            if axis_break.increment_after is not None:
                execute(app, f"layer.y.break{index}.tickstype=1")
                execute(app, f"layer.y.break{index}.inc={axis_break.increment_after}")
        execute(app, "layer.y.PlotBreakSymbol=1; page.breaktype=1")

    execute(app, "legend -r")
    execute(app, "legend.font=font(Arial); legend.fsize=13")
    if spec.legend_x is not None and spec.legend_y is not None:
        execute(app, "legend.attach=2")
        execute(app, f"legend.x={spec.legend_x}; legend.y={spec.legend_y}")
    else:
        execute(app, "legend.attach=2")
        execute(app, "legend.x=layer.x.from+legend.dx/2; legend.y=layer.y.to-legend.dy/2")


def create_graph(app, spec: FigureSpec) -> None:
    first_y = 2
    last_y = len(spec.schemes) + 1
    execute(app, f"win -a {spec.book_name}")
    execute(
        app,
        f"plotxy iy:=[{spec.book_name}]Sheet1!(1,{first_y}:{last_y}) "
        f"plot:=202 ogl:=[<new template:=line name:={spec.graph_name}>]",
    )
    style_graph(app, spec)


def export_graph(app, output_dir: Path, spec: FigureSpec) -> None:
    execute(app, f"win -a {spec.graph_name}")
    export_path = labtalk_string(str(output_dir))
    for file_type in ("png", "pdf"):
        execute(
            app,
            f'expGraph type:={file_type} path:="{export_path}" '
            f'filename:="{spec.stem}_origin" overwrite:=replace tr.Margin:=2',
        )


def write_manifest(output_dir: Path, result_dir: Path) -> None:
    manifest = {
        "source_directory": str(result_dir.resolve()),
        "project": "FS_DBS_Origin_Figures.opju",
        "notes": [
            "All graph pages remain editable in Origin.",
            "All figures use continuous linear axes because the replacement baselines are on comparable scales.",
        ],
        "figures": [
            {
                "stem": spec.stem,
                "source_csv": spec.csv_name,
                "workbook": spec.book_name,
                "graph": spec.graph_name,
                "x_column": spec.x_column,
                "y_column": spec.y_column,
                "breaks": [
                    {"from": item.start, "to": item.end, "position": item.position}
                    for item in spec.breaks
                ],
            }
            for spec in FIGURES
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create editable Origin performance plots.")
    parser.add_argument(
        "--results",
        type=Path,
        default=Path("results/comparison/summary"),
        help="Directory containing the figure summary CSV files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("origin"),
        help="Output directory for the Origin project and previews.",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Leave Origin visible while the project is being generated.",
    )
    args = parser.parse_args()

    result_dir = args.results.resolve()
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    project_path = output_dir / "FS_DBS_Origin_Figures.opju"

    prepared: list[tuple[FigureSpec, list[float], dict[str, list[float]]]] = []
    for spec in FIGURES:
        x_values, wide = read_wide_data(result_dir / spec.csv_name, spec)
        assert_breaks_do_not_hide_data(spec, wide)
        prepared.append((spec, x_values, wide))

    app = None
    try:
        app = win32com.client.DispatchEx("Origin.ApplicationCOMSI")
        app.Visible = 1 if args.show else 0
        if not app.NewProject():
            raise RuntimeError("Origin could not create a new project")

        for spec, x_values, wide in prepared:
            create_book(app, spec, x_values, wide)
            create_graph(app, spec)
            export_graph(app, output_dir, spec)

        if not app.Save(str(project_path)):
            raise RuntimeError(f"Origin could not save {project_path}")
        time.sleep(2)
    finally:
        if app is not None:
            app.Exit()

    write_manifest(output_dir, result_dir)
    print(project_path)
    for spec in FIGURES:
        print(output_dir / f"{spec.stem}_origin.png")


if __name__ == "__main__":
    main()
