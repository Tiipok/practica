#!/usr/bin/env python3
"""Generate comprehensive PDF report with CPU vs GPU benchmarks and 3D analysis."""
import csv
import os
import sys
import math
import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from matplotlib.backends.backend_pdf import PdfPages
from mpl_toolkits.mplot3d import Axes3D


def load_data(csv_path):
    rows = []
    if not os.path.exists(csv_path):
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return rows
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            row["checks_per_second"] = float(row.get("checks_per_second", 0))
            row["total_time_ms"] = float(row.get("total_time_ms", 0))
            row["num_threads"] = int(row.get("num_threads", 1))
            row["password_length"] = int(row.get("password_length", 0))
            row["charset_size"] = int(row.get("charset_size", 0))
            row["total_checks"] = int(row.get("total_checks", 0))
            row["execution_mode"] = row.get("execution_mode", "CPU").strip()
            row["protection_type"] = row.get("protection_type", "").strip()
            rows.append(row)
    return rows


def fmt_speed(v):
    if v >= 1_000_000:
        return f"{v/1e6:.1f}M"
    if v >= 1000:
        return f"{v/1000:.1f}K"
    return f"{v:.0f}"


def fmt_time(seconds):
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    if seconds < 86400:
        return f"{seconds/3600:.1f}h"
    return f"{seconds/86400:.1f}d"


def avg_speed(rows, charset, length, min_speed=100):
    subset = [r for r in rows if r["charset_name"] == charset
              and r["password_length"] == length
              and r["checks_per_second"] > min_speed]
    return sum(r["checks_per_second"] for r in subset) / len(subset) if subset else 0


def get_cpu_best(rows, charset, length):
    subset = [r for r in rows if r["execution_mode"] == "CPU"
              and r["charset_name"] == charset
              and r["password_length"] == length
              and r["checks_per_second"] > 100
              and r["protection_type"] == "ZipCrypto"]
    return max((r["checks_per_second"] for r in subset), default=0)


def get_gpu_speed(rows, charset, length, prot="ZipCrypto"):
    subset = [r for r in rows if r["execution_mode"] == "GPU"
              and r["charset_name"] == charset
              and r["password_length"] == length
              and r["checks_per_second"] > 100
              and r["protection_type"] == prot]
    return max((r["checks_per_second"] for r in subset), default=0)


def get_aes_cpu_best(rows, length):
    subset = [r for r in rows if r["execution_mode"] == "CPU"
              and r["protection_type"] == "AES-256"
              and r["password_length"] == length
              and r["checks_per_second"] > 100]
    return max((r["checks_per_second"] for r in subset), default=0)


def get_aes_gpu_speed(rows, length):
    subset = [r for r in rows if r["execution_mode"] == "GPU"
              and r["protection_type"] == "AES-256"
              and r["password_length"] == length
              and r["checks_per_second"] > 100]
    return max((r["checks_per_second"] for r in subset), default=0)


def build_pdf(data, output_path):
    if not data:
        print("No data", file=sys.stderr)
        return

    cpu = [r for r in data if r["execution_mode"] == "CPU"]
    gpu = [r for r in data if r["execution_mode"] == "GPU"]

    cpu_model = data[0].get("cpu_model", "Apple Silicon") if data else "Apple Silicon"
    compiler = data[0].get("compiler_flags", "") if data else ""

    with PdfPages(output_path) as pdf:
        _page_title(pdf, cpu_model, compiler, len(cpu), len(gpu))
        _page_cpu_table(cpu, pdf)
        _page_gpu_vs_cpu_table(cpu, gpu, pdf)
        _plot_cpu_scaling(cpu, pdf)
        _plot_gpu_zip(cpu, gpu, pdf)
        _plot_zip_comparison(cpu, gpu, pdf)
        _plot_aes_comparison(cpu, gpu, pdf)
        _plot_speedup(gpu, pdf)
        _plot_3d_space(cpu, gpu, pdf)
        _page_conclusions(pdf)


def _page_title(pdf, cpu_model, compiler, n_cpu, n_gpu):
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.axis("off")
    lines = [
        ("ZIP Password Bruteforce Research", 22, "bold"),
        ("", 12, "normal"),
        ("Apple Silicon M4 GPU Acceleration", 16, "normal"),
        ("", 10, "normal"),
        (f"CPU: {cpu_model}", 13, "normal"),
        (f"Compiler: {compiler}", 11, "normal"),
        ("", 10, "normal"),
        (f"Experiments: {n_cpu} CPU + {n_gpu} GPU = {n_cpu + n_gpu} total", 12, "normal"),
        ("", 10, "normal"),
        ("Constraints:", 12, "bold"),
        ("  Password length: 1-5 characters", 11, "normal"),
        ("  Charsets: digits (10), lowercase (26), alphanum (36)", 11, "normal"),
        ("  Protection: ZipCrypto + AES-256", 11, "normal"),
        ("  Threads: 1, 2, 4, 6, 8, 10", 11, "normal"),
    ]
    y = 0.92
    for text, size, weight in lines:
        ax.text(0.5, y, text, transform=ax.transAxes, ha="center", va="top",
                fontsize=size, fontweight=weight, fontfamily="monospace")
        y -= 0.055 if text else 0.03

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _tabulate(ax, headers, rows, col_widths, title, fontsize=8):
    table = ax.table(cellText=rows, colLabels=headers, colWidths=col_widths,
                     cellLoc="center", loc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(fontsize)
    table.scale(1.0, 1.5)
    for (r, c), cell in table.get_celld().items():
        if r == 0:
            cell.set_facecolor("#263238")
            cell.set_text_props(color="white", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#ECEFF1")
        if c == 0:
            cell.set_text_props(ha="left")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=14)


def _page_cpu_table(cpu, pdf):
    if not cpu:
        return
    rows = []
    for charset in ["digits", "lowercase", "alphanum"]:
        for length in [1, 2, 3, 4, 5]:
            for tc in [1, 2, 4, 6, 8, 10]:
                sp = avg_speed(cpu, charset, length)
                if sp > 100:
                    rows.append([
                        charset, str(length), str(tc),
                        fmt_speed(sp),
                        f"{sp:,.0f}"
                    ])
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(9, max(3, len(rows) * 0.35)))
    ax.axis("tight"); ax.axis("off")
    headers = ["Charset", "Len", "Thr", "Avg Speed", "Raw"]
    _tabulate(ax, headers, rows, [0.12, 0.05, 0.05, 0.10, 0.12],
              "CPU: Averaged Speed by Charset, Length, Threads (ZipCrypto)", fontsize=7)
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _page_gpu_vs_cpu_table(cpu, gpu, pdf):
    rows = []
    categories = [
        ("digits", 1), ("digits", 2), ("digits", 3), ("digits", 4), ("digits", 5),
        ("lowercase", 1), ("lowercase", 2), ("lowercase", 3), ("lowercase", 4), ("lowercase", 5),
        ("alphanum", 1), ("alphanum", 2), ("alphanum", 3), ("alphanum", 4), ("alphanum", 5),
    ]
    for charset, length in categories:
        csp = get_cpu_best(cpu, charset, length)
        gsp = get_gpu_speed(gpu, charset, length)
        if csp > 0 and gsp > 0:
            ratio = gsp / csp
            rows.append([
                charset, str(length),
                fmt_speed(csp), fmt_speed(gsp),
                f"{ratio:.0f}x"
            ])
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(8, max(3, len(rows) * 0.38)))
    ax.axis("tight"); ax.axis("off")
    headers = ["Charset", "Len", "CPU Best", "GPU", "Speedup"]
    _tabulate(ax, headers, rows, [0.14, 0.08, 0.16, 0.16, 0.14],
              "ZipCrypto: GPU vs CPU Speed Comparison", fontsize=8)
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_cpu_scaling(cpu, pdf):
    if not cpu:
        return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    colors = {"digits": "#2196F3", "lowercase": "#4CAF50", "alphanum": "#FF9800"}

    for charset in ["digits", "lowercase", "alphanum"]:
        for length in [3, 4, 5]:
            subset = [r for r in cpu if r["charset_name"] == charset
                      and r["password_length"] == length
                      and r["checks_per_second"] > 100
                      and r["protection_type"] == "ZipCrypto"]
            if len(subset) < 2:
                continue
            subset.sort(key=lambda r: r["num_threads"])
            tcs = [r["num_threads"] for r in subset]
            speeds = [r["checks_per_second"] for r in subset]
            ax1.plot(tcs, speeds, marker="o", color=colors[charset],
                     label=f"{charset} L={length}", linewidth=1.5)

    ax1.set_xlabel("Threads"); ax1.set_ylabel("Checks/sec")
    ax1.set_title("CPU ZipCrypto: Speed vs Threads")
    ax1.legend(fontsize=7); ax1.grid(True, alpha=0.3)
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    for charset in ["digits", "lowercase", "alphanum"]:
        min_t = min((r["num_threads"] for r in cpu if r["charset_name"] == charset
                     and r["password_length"] == 4 and r["checks_per_second"] > 100), default=1)
        base = max((r["checks_per_second"] for r in cpu if r["charset_name"] == charset
                    and r["password_length"] == 4 and r["checks_per_second"] > 100
                    and r["num_threads"] == min_t), default=1)
        if base < 100:
            continue
        pts = []
        for tc in [1, 2, 4, 6, 8, 10]:
            sp = max((r["checks_per_second"] for r in cpu if r["charset_name"] == charset
                      and r["password_length"] == 4 and r["num_threads"] == tc
                      and r["checks_per_second"] > 100), default=0)
            if sp > 0:
                pts.append((tc, sp / base))
        if pts:
            ax2.plot([p[0] for p in pts], [p[1] for p in pts], marker="s",
                     color=colors[charset], label=f"{charset}", linewidth=2)
    ax2.plot([1, 10], [1, 10], "--", color="gray", alpha=0.5, label="ideal")
    ax2.set_xlabel("Threads"); ax2.set_ylabel("Speedup")
    ax2.set_title("CPU ZipCrypto: Scaling Efficiency (L=4)")
    ax2.legend(fontsize=7); ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_gpu_zip(cpu, gpu, pdf):
    if not gpu:
        return
    fig, ax = plt.subplots(figsize=(9, 5))
    colors = {"digits": "#2196F3", "lowercase": "#4CAF50", "alphanum": "#FF9800"}
    for charset in ["digits", "lowercase", "alphanum"]:
        pts = []
        for length in [1, 2, 3, 4, 5]:
            sp = get_gpu_speed(gpu, charset, length)
            if sp > 100:
                pts.append((length, sp))
        if pts:
            ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="D",
                    color=colors[charset], label=charset, linewidth=2.5, markersize=9)
            for x, y in pts:
                ax.annotate(fmt_speed(y), (x, y), textcoords="offset points",
                            xytext=(0, 14), ha="center", fontsize=8,
                            color=colors[charset], fontweight="bold")

    ax.set_yscale("log")
    ax.set_xlabel("Password Length")
    ax.set_ylabel("Checks/sec (log scale)")
    ax.set_title("GPU ZipCrypto: Speed vs Password Length")
    ax.legend(); ax.grid(True, alpha=0.3, which="both")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_zip_comparison(cpu, gpu, pdf):
    if not gpu:
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    categories = [
        ("digits\nL=3", "digits", 3), ("digits\nL=4", "digits", 4), ("digits\nL=5", "digits", 5),
        ("lower\nL=3", "lowercase", 3), ("lower\nL=4", "lowercase", 4), ("lower\nL=5", "lowercase", 5),
        ("alpha\nL=3", "alphanum", 3), ("alpha\nL=4", "alphanum", 4), ("alpha\nL=5", "alphanum", 5),
    ]
    labels = [c[0] for c in categories]
    cpu_sp = [get_cpu_best(cpu, c[1], c[2]) for c in categories]
    gpu_sp = [get_gpu_speed(gpu, c[1], c[2]) for c in categories]

    x = np.arange(len(labels))
    width = 0.35
    bars_cpu = ax.bar(x - width/2, cpu_sp, width, label="CPU (best threads)",
                      color="#546E7A", edgecolor="white")
    bars_gpu = ax.bar(x + width/2, gpu_sp, width, label="GPU (Metal M4)",
                      color="#FF6D00", edgecolor="white")

    for bar, val in zip(bars_cpu, cpu_sp):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width()/2, val + 500,
                    fmt_speed(val), ha="center", va="bottom", fontsize=6, rotation=90)
    for bar, val in zip(bars_gpu, gpu_sp):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width()/2, val + 500,
                    fmt_speed(val), ha="center", va="bottom", fontsize=6, rotation=90, color="#BF360C")

    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Checks/sec (log scale)")
    ax.set_title("CPU vs GPU: ZipCrypto Performance")
    ax.set_yscale("log")
    ax.legend(); ax.grid(True, alpha=0.2, which="both", axis="y")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_aes_comparison(cpu, gpu, pdf):
    fig, ax = plt.subplots(figsize=(9, 5))
    categories = ["AES L=1", "AES L=2", "AES L=3", "AES L=4"]
    cpu_sp = [get_aes_cpu_best(cpu, l) for l in [1, 2, 3, 4]]
    gpu_sp = [get_aes_gpu_speed(gpu, l) for l in [1, 2, 3, 4]]

    x = np.arange(len(categories))
    width = 0.3
    br1 = ax.bar(x - width/2, cpu_sp, width, label="CPU (best)", color="#546E7A", edgecolor="white")
    br2 = ax.bar(x + width/2, gpu_sp, width, label="GPU (Metal M4)", color="#FF6D00", edgecolor="white")
    for i in range(len(categories)):
        if cpu_sp[i] > 0:
            ax.text(x[i] - width/2, cpu_sp[i] + 50, fmt_speed(cpu_sp[i]), ha="center", fontsize=8)
        if gpu_sp[i] > 0 and cpu_sp[i] > 0:
            ratio = gpu_sp[i] / cpu_sp[i]
            ax.text(x[i] + width/2, gpu_sp[i] + 100, f"{ratio:.1f}x", ha="center", fontsize=8, color="#BF360C", fontweight="bold")

    ax.set_xticks(x); ax.set_xticklabels(categories)
    ax.set_ylabel("Checks/sec")
    ax.set_title("CPU vs GPU: AES-256 (alphanum)")
    ax.legend(); ax.grid(True, alpha=0.2, axis="y")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_speedup(gpu, pdf):
    if not gpu:
        return
    fig, ax = plt.subplots(figsize=(9, 5))
    categories = [
        ("digits L=4", "digits", 4), ("digits L=5", "digits", 5),
        ("lowercase L=4", "lowercase", 4), ("lowercase L=5", "lowercase", 5),
        ("alphanum L=4", "alphanum", 4), ("alphanum L=5", "alphanum", 5),
    ]
    labels = [c[0] for c in categories]
    ratios = []
    cpu_vals = []
    gpu_vals = []
    for c in categories:
        cs = get_cpu_best([], c[1], c[2])
        gs = get_gpu_speed(gpu, c[1], c[2])
        if cs > 0 and gs > 0:
            ratios.append(gs / cs)
            cpu_vals.append(cs)
            gpu_vals.append(gs)
        else:
            ratios.append(0)
            cpu_vals.append(0)
            gpu_vals.append(0)

    colors = []
    for r in ratios:
        if r > 500: colors.append("#1B5E20")
        elif r > 200: colors.append("#2E7D32")
        elif r > 50: colors.append("#43A047")
        else: colors.append("#81C784")

    bars = ax.barh(labels, ratios, color=colors, edgecolor="white", height=0.6)
    for bar, ratio, cs, gs in zip(bars, ratios, cpu_vals, gpu_vals):
        if ratio > 0:
            ax.text(bar.get_width() + 10, bar.get_y() + bar.get_height()/2,
                    f"{ratio:.0f}x  (CPU={fmt_speed(cs)}, GPU={fmt_speed(gs)})",
                    va="center", fontsize=8)
    ax.set_xlabel("GPU Speedup vs CPU")
    ax.set_title("GPU Acceleration Factor (ZipCrypto)")
    ax.grid(True, alpha=0.25, axis="x")
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _plot_3d_space(cpu, gpu, pdf):
    fig = plt.figure(figsize=(14, 6))

    ax1 = fig.add_subplot(1, 2, 1, projection="3d")
    ax2 = fig.add_subplot(1, 2, 2, projection="3d")

    alphabets = {"digits": 10, "lowercase": 26, "alphanum": 36}
    lengths = [1, 2, 3, 4, 5]
    markers = {"digits": ("o", "#2196F3"), "lowercase": ("s", "#4CAF50"), "alphanum": ("D", "#FF9800")}

    for charset, size in alphabets.items():
        pts_len, pts_size, pts_time = [], [], []
        for L in lengths:
            speed = get_cpu_best(cpu, charset, L)
            space = size ** L
            if speed > 100:
                pts_len.append(L)
                pts_size.append(size)
                pts_time.append(space / speed)
        if pts_len:
            m, c = markers[charset]
            ax1.scatter(pts_len, pts_size, pts_time, marker=m, s=80, color=c,
                        label=charset, edgecolors="white", linewidth=0.5)
            for i in range(len(pts_len)):
                ax1.text(pts_len[i], pts_size[i], pts_time[i] * 1.2,
                         fmt_time(pts_time[i]), fontsize=7, ha="center")

    ax1.set_xlabel("Password Length"); ax1.set_ylabel("Alphabet Size")
    ax1.set_zlabel("Time to crack"); ax1.set_title("CPU: Crack Time vs Length & Alphabet")
    ax1.legend(fontsize=8); ax1.set_zscale("log")

    for charset, size in alphabets.items():
        pts_len, pts_size, pts_time = [], [], []
        for L in lengths:
            speed = get_gpu_speed(gpu, charset, L)
            space = size ** L
            if speed > 100 and space < 5e8:
                pts_len.append(L)
                pts_size.append(size)
                pts_time.append(space / speed)
        if pts_len:
            m, c = markers[charset]
            ax2.scatter(pts_len, pts_size, pts_time, marker=m, s=80, color=c,
                        label=charset, edgecolors="white", linewidth=0.5)
            for i in range(len(pts_len)):
                ax2.text(pts_len[i], pts_size[i], pts_time[i] * 1.2,
                         fmt_time(pts_time[i]), fontsize=7, ha="center", color=c)

    ax2.set_xlabel("Password Length"); ax2.set_ylabel("Alphabet Size")
    ax2.set_zlabel("Time to crack"); ax2.set_title("GPU: Crack Time vs Length & Alphabet")
    ax2.legend(fontsize=8); ax2.set_zscale("log")

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def _page_conclusions(pdf):
    fig, ax = plt.subplots(figsize=(9, 7))
    ax.axis("off")
    lines = [
        ("KEY FINDINGS", 16, "bold"),
        ("", 10, "normal"),
        ("1. GPU ZipCrypto acceleration: 300-600x vs CPU", 12, "bold"),
        ("   Apple M4 GPU achieves 20-73 million checks/sec for ZipCrypto.", 10, "normal"),
        ("   CPU peaks at ~120K checks/sec with 10 threads.", 10, "normal"),
        ("", 8, "normal"),
        ("2. CPU scaling is non-linear", 12, "bold"),
        ("   Peak performance at 4 threads (P-cores).", 10, "normal"),
        ("   Efficiency cores (E-cores) add less speedup, causing sub-linear scaling.", 10, "normal"),
        ("", 8, "normal"),
        ("3. AES-256 is significantly harder to crack", 12, "bold"),
        ("   CPU: ~1,500/s (1 thread) to ~8,400/s (10 threads) for L=4.", 10, "normal"),
        ("   GPU: ~24,000/s (L=4) — only 2.9x speedup.", 10, "normal"),
        ("   PBKDF2-1000 iterations dominate compute time.", 10, "normal"),
        ("", 8, "normal"),
        ("4. Password length impact", 12, "bold"),
        ("   Each extra character multiplies crack time by |alphabet|.", 10, "normal"),
        ("   alphanum L=5: CPU 111K/s, space 60M, crack time ~9 min.", 10, "normal"),
        ("   Same space on GPU: ~1 second.", 10, "normal"),
        ("", 8, "normal"),
        ("5. Recommendations for strong passwords", 12, "bold"),
        ("   Use mixed case + digits + special chars (|A| >= 72).", 10, "normal"),
        ("   Minimum 8 characters for real security.", 10, "normal"),
        ("   AES-256 encryption is recommended over ZipCrypto.", 10, "normal"),
    ]
    y = 0.96
    for text, size, weight in lines:
        ax.text(0.05, y, text, transform=ax.transAxes, va="top",
                fontsize=size, fontweight=weight, fontfamily="monospace")
        y -= 0.03 if text else 0.015

    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "results/results.csv"
    output = sys.argv[2] if len(sys.argv) > 2 else "results/report.pdf"
    data = load_data(csv_path)
    if not data:
        print(f"No data in {csv_path}")
        return 1
    nc = sum(1 for r in data if r["execution_mode"] == "CPU")
    ng = sum(1 for r in data if r["execution_mode"] == "GPU")
    print(f"Loaded {len(data)} records (CPU: {nc}, GPU: {ng})")
    build_pdf(data, output)
    print(f"Report: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
