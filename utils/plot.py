import states


def plot_overview(queries: list[str], data: dict[str, list]) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    assert len(queries) == len(list(data.values())[0])

    x = np.arange(len(queries))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0

    fig, ax = plt.subplots(layout="constrained")

    for attribute, measurement in data.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        ax.bar_label(rects, padding=3)
        multiplier += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel("metirc for query")
    ax.set_title("local queries overview")
    ax.set_xticks(x + width, queries)
    ax.legend(loc="upper left", ncols=3)
    # ax.set_ylim(0, 250)

    plt.show()
