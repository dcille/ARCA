"""Chart generation service using matplotlib for PDF report embedding."""
import io
from typing import Optional


def _get_matplotlib():
    """Lazy import matplotlib with Agg backend."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def donut_chart(
    data: dict[str, int],
    colors: Optional[dict[str, tuple]] = None,
    title: str = "",
    center_text: str = "",
    width: int = 400,
    height: int = 300,
) -> bytes:
    """Generate a donut chart as PNG bytes.

    Args:
        data: {label: count} pairs
        colors: {label: (r,g,b)} color map (0-255 scale)
        title: Chart title
        center_text: Text in donut center
    """
    plt = _get_matplotlib()

    filtered = {k: v for k, v in data.items() if v > 0}
    if not filtered:
        filtered = {"No Data": 1}

    labels = list(filtered.keys())
    values = list(filtered.values())

    color_list = []
    default_colors = {
        "critical": (220, 38, 38),
        "high": (234, 88, 12),
        "medium": (234, 179, 8),
        "low": (59, 130, 246),
        "informational": (107, 114, 128),
        "No Data": (200, 200, 200),
    }
    cmap = colors or default_colors
    for label in labels:
        c = cmap.get(label, cmap.get(label.lower(), (100, 116, 139)))
        color_list.append((c[0] / 255, c[1] / 255, c[2] / 255))

    fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100)
    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        colors=color_list,
        autopct=lambda pct: f"{pct:.0f}%" if pct > 5 else "",
        startangle=90,
        wedgeprops={"width": 0.4, "edgecolor": "white", "linewidth": 2},
        pctdistance=0.8,
    )

    for t in autotexts:
        t.set_fontsize(8)
        t.set_color("white")
        t.set_fontweight("bold")

    # Center text
    if center_text:
        ax.text(0, 0, center_text, ha="center", va="center",
                fontsize=14, fontweight="bold", color="#0f172a")

    # Legend
    ax.legend(
        wedges,
        [f"{l} ({v})" for l, v in zip(labels, values)],
        loc="center left",
        bbox_to_anchor=(1.0, 0.5),
        fontsize=7,
        frameon=False,
    )

    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, transparent=False,
                facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def horizontal_bar_chart(
    data: dict[str, int],
    title: str = "",
    color: tuple = (34, 197, 94),
    max_items: int = 10,
    width: int = 500,
    height: int = 300,
) -> bytes:
    """Generate a horizontal bar chart as PNG bytes."""
    plt = _get_matplotlib()

    sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)[:max_items]
    if not sorted_data:
        sorted_data = [("No Data", 0)]

    labels = [item[0] for item in reversed(sorted_data)]
    values = [item[1] for item in reversed(sorted_data)]
    bar_color = (color[0] / 255, color[1] / 255, color[2] / 255)

    fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100)
    bars = ax.barh(labels, values, color=bar_color, height=0.6, edgecolor="white")

    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + max(values) * 0.02, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=8, color="#64748b")

    ax.set_xlabel("")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#e2e8f0")
    ax.spines["left"].set_color("#e2e8f0")
    ax.tick_params(axis="y", labelsize=8, colors="#334155")
    ax.tick_params(axis="x", labelsize=7, colors="#94a3b8")

    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def radar_chart(
    data: dict[str, float],
    title: str = "",
    max_value: float = 100,
    color: tuple = (34, 197, 94),
    width: int = 400,
    height: int = 400,
) -> bytes:
    """Generate a radar/spider chart as PNG bytes.

    Args:
        data: {domain_name: score} where score is 0-max_value
    """
    plt = _get_matplotlib()
    import numpy as np

    labels = list(data.keys())
    values = list(data.values())
    n = len(labels)
    if n < 3:
        # Radar charts need at least 3 points
        return horizontal_bar_chart(
            {k: int(v) for k, v in data.items()}, title=title, color=color
        )

    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    values_plot = values + [values[0]]
    angles += [angles[0]]

    fill_color = (color[0] / 255, color[1] / 255, color[2] / 255, 0.25)
    line_color = (color[0] / 255, color[1] / 255, color[2] / 255)

    fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100,
                           subplot_kw={"polar": True})
    ax.plot(angles, values_plot, "o-", linewidth=2, color=line_color, markersize=4)
    ax.fill(angles, values_plot, alpha=0.25, color=line_color)

    ax.set_thetagrids(
        [a * 180 / np.pi for a in angles[:-1]],
        [f"{l}\n({v:.0f}%)" for l, v in zip(labels, values)],
        fontsize=7,
        color="#334155",
    )
    ax.set_ylim(0, max_value)
    ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25", "50", "75", "100"], fontsize=6, color="#94a3b8")
    ax.grid(color="#e2e8f0", linewidth=0.5)

    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", pad=20)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def line_chart(
    series: dict[str, list[tuple[str, float]]],
    title: str = "",
    y_label: str = "",
    width: int = 500,
    height: int = 250,
) -> bytes:
    """Generate a line chart as PNG bytes.

    Args:
        series: {series_name: [(x_label, y_value), ...]}
    """
    plt = _get_matplotlib()

    line_colors = [
        (15 / 255, 23 / 255, 42 / 255),
        (34 / 255, 197 / 255, 94 / 255),
        (59 / 255, 130 / 255, 246 / 255),
        (234 / 255, 88 / 255, 12 / 255),
        (139 / 255, 92 / 255, 246 / 255),
    ]

    fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100)

    for idx, (name, points) in enumerate(series.items()):
        if not points:
            continue
        x_labels = [p[0] for p in points]
        y_values = [p[1] for p in points]
        color = line_colors[idx % len(line_colors)]
        ax.plot(x_labels, y_values, "o-", label=name, color=color, linewidth=2, markersize=4)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#e2e8f0")
    ax.spines["left"].set_color("#e2e8f0")
    ax.tick_params(axis="both", labelsize=7, colors="#64748b")

    if y_label:
        ax.set_ylabel(y_label, fontsize=8, color="#64748b")
    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", pad=10)

    if len(series) > 1:
        ax.legend(fontsize=7, frameon=False)

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def stacked_bar_chart(
    categories: list[str],
    groups: dict[str, list[int]],
    colors: Optional[dict[str, tuple]] = None,
    title: str = "",
    width: int = 500,
    height: int = 300,
) -> bytes:
    """Generate a stacked bar chart as PNG bytes.

    Args:
        categories: x-axis labels
        groups: {group_name: [values_per_category]}
        colors: {group_name: (r,g,b)} 0-255 scale
    """
    plt = _get_matplotlib()
    import numpy as np

    default_colors = {
        "critical": (220, 38, 38),
        "high": (234, 88, 12),
        "medium": (234, 179, 8),
        "low": (59, 130, 246),
        "informational": (107, 114, 128),
    }
    cmap = colors or default_colors

    fig, ax = plt.subplots(figsize=(width / 100, height / 100), dpi=100)
    x = np.arange(len(categories))
    bar_width = 0.6
    bottom = np.zeros(len(categories))

    for group_name, values in groups.items():
        c = cmap.get(group_name, (100, 116, 139))
        bar_color = (c[0] / 255, c[1] / 255, c[2] / 255)
        ax.bar(x, values, bar_width, bottom=bottom, label=group_name.title(),
               color=bar_color, edgecolor="white", linewidth=0.5)
        bottom += np.array(values)

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=7, rotation=45, ha="right", color="#334155")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#e2e8f0")
    ax.spines["left"].set_color("#e2e8f0")
    ax.tick_params(axis="y", labelsize=7, colors="#94a3b8")
    ax.legend(fontsize=7, frameon=False, loc="upper right")

    if title:
        ax.set_title(title, fontsize=10, fontweight="bold", color="#0f172a", pad=10)

    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()
