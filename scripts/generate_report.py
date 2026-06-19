#!/usr/bin/env python3
"""
Generate PDF report with graphs from experiment results.
Reads CSV from experiment runs and produces charts + PDF.
"""
import csv
import os
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.backends.backend_pdf import PdfPages


def load_data(csv_path: str) -> list[dict]:
    rows = []
    if not os.path.exists(csv_path):
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return rows
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["checks_per_second"] = float(row.get("checks_per_second", 0))
            row["total_time_ms"] = float(row.get("total_time_ms", 0))
            row["num_threads"] = int(row.get("num_threads", 1))
            row["password_length"] = int(row.get("password_length", 0))
            row["charset_size"] = int(row.get("charset_size", 0))
            row["total_checks"] = int(row.get("total_checks", 0))
            row["total_space_size"] = int(row.get("total_space_size", 0))
            row["archive_size_bytes"] = int(row.get("archive_size_bytes", 0))
            row["cpu_load_percent"] = float(row.get("cpu_load_percent", 0))
            rows.append(row)
    return rows


def build_pdf(data: list[dict], output_path: str):
    if not data:
        print("No data to plot", file=sys.stderr)
        return

    with PdfPages(output_path) as pdf:
        _plot_speed_vs_charset_size(data, pdf)
        _plot_time_vs_password_length(data, pdf)
        _plot_speed_vs_threads(data, pdf)
        _plot_checks_vs_threads(data, pdf)
        _plot_protection_comparison(data, pdf)
        _plot_summary_table(data, pdf)


def _plot_speed_vs_charset_size(data, pdf):
    fig, ax = plt.subplots(figsize=(8, 5))
    charsets = sorted(set(r["charset_name"] for r in data),
                      key=lambda x: {"digits": 1, "lowercase": 2, "alphanum": 3}.get(x, 99))
    series: dict[str, list[float]] = {cs: [] for cs in charsets}
    for cs in charsets:
        vals = [r["checks_per_second"] for r in data if r["charset_name"] == cs]
        series[cs] = vals

    positions = range(len(charsets))
    means = [sum(series[cs]) / len(series[cs]) if series[cs] else 0 for cs in charsets]
    colors = ["#2196F3", "#4CAF50", "#FF9800"]

    bars = ax.bar(positions, means, color=colors[: len(charsets)], edgecolor="white", linewidth=0.8)
    ax.set_xticks(positions)
    ax.set_xticklabels(charsets)
    ax.set_ylabel("Checks per second")
    ax.set_title("Password Check Speed by Charset")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 500,
                f"{val:,.0f}", ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_time_vs_password_length(data, pdf):
    fig, ax = plt.subplots(figsize=(8, 5))

    for cs in sorted(set(r["charset_name"] for r in data)):
        subset = sorted(
            [r for r in data if r["charset_name"] == cs],
            key=lambda x: x["password_length"],
        )
        if not subset:
            continue
        lengths = [r["password_length"] for r in subset]
        times = [r["total_time_ms"] / 1000.0 for r in subset]
        ax.plot(lengths, times, marker="o", label=cs, linewidth=2)

    ax.set_xlabel("Password Length")
    ax.set_ylabel("Time (seconds)")
    ax.set_title("Search Time vs Password Length")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_speed_vs_threads(data, pdf):
    by_threads: dict[int, list[float]] = {}
    for r in data:
        tc = r["num_threads"]
        by_threads.setdefault(tc, []).append(r["checks_per_second"])

    fig, ax = plt.subplots(figsize=(8, 5))
    tcs = sorted(by_threads.keys())
    means = [sum(by_threads[t]) / len(by_threads[t]) for t in tcs]
    ax.plot(tcs, means, marker="s", color="#E91E63", linewidth=2, markersize=8)
    ax.set_xlabel("Number of Threads")
    ax.set_ylabel("Checks per second")
    ax.set_title("Performance Scaling: Checks/sec vs Threads")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    ax.grid(True, alpha=0.3)

    for x, y in zip(tcs, means):
        ax.annotate(f"{y:,.0f}", (x, y), textcoords="offset points",
                    xytext=(0, 12), ha="center", fontsize=8)

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_checks_vs_threads(data, pdf):
    by_threads: dict[int, list[float]] = {}
    for r in data:
        tc = r["num_threads"]
        total = r["total_checks"]
        space = max(r["total_space_size"], 1)
        pct = total / space * 100
        by_threads.setdefault(tc, []).append(pct)

    fig, ax = plt.subplots(figsize=(8, 5))
    tcs = sorted(by_threads.keys())
    means = [sum(by_threads[t]) / len(by_threads[t]) for t in tcs]
    ax.bar(tcs, means, color="#9C27B0", edgecolor="white", linewidth=0.8)
    ax.set_xlabel("Number of Threads")
    ax.set_ylabel("Space Covered (%)")
    ax.set_title("Password Space Coverage by Thread Count")
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_protection_comparison(data, pdf):
    fig, ax = plt.subplots(figsize=(8, 5))

    for pt in sorted(set(r["protection_type"] for r in data)):
        subset = [r for r in data if r["protection_type"] == pt]
        if not subset:
            continue
        speeds = [r["checks_per_second"] for r in subset]
        avg = sum(speeds) / len(speeds)
        ax.bar([pt], [avg], color="#00BCD4" if "AES" in pt else "#607D8B",
               edgecolor="white", linewidth=0.8)
        ax.text(0 if pt == "ZipCrypto" else 1, avg + 500,
                f"{avg:,.0f}", ha="center", va="bottom", fontsize=10)

    ax.set_ylabel("Checks per second")
    ax.set_title("Check Speed: ZipCrypto vs AES-256")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_summary_table(data, pdf):
    fig, ax = plt.subplots(figsize=(11, max(3, len(data) * 0.35)))
    ax.axis("tight")
    ax.axis("off")

    columns = ["id", "archive", "charset", "len", "threads",
               "checks", "time_ms", "speed/s", "protection", "found"]
    col_widths = [0.04, 0.16, 0.09, 0.04, 0.06, 0.12, 0.10, 0.12, 0.12, 0.09]

    rows = []
    for r in sorted(data, key=lambda x: x.get("id", 0)):
        rows.append([
            str(r.get("id", "")),
            r.get("archive_name", ""),
            r.get("charset_name", ""),
            str(r.get("password_length", "")),
            str(r.get("num_threads", "")),
            f'{r.get("total_checks", 0):,}',
            f'{r.get("total_time_ms", 0):,.1f}',
            f'{r.get("checks_per_second", 0):,.0f}',
            r.get("protection_type", ""),
            "yes" if r.get("password_found") == "1" else "no",
        ])

    table = ax.table(
        cellText=rows,
        colLabels=columns,
        colWidths=col_widths,
        cellLoc="center",
        loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1.0, 1.3)

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor("#37474F")
            cell.set_text_props(color="white", fontweight="bold")

    ax.set_title("Experiment Results Summary", fontsize=12, fontweight="bold", pad=12)
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results/results.csv"
    output = sys.argv[2] if len(sys.argv) > 2 else "results/report.pdf"

    data = load_data(csv_path)
    if not data:
        print(f"No data found in {csv_path}")
        return 1

    print(f"Loaded {len(data)} experiment records")
    build_pdf(data, output)
    print(f"Report saved to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
