#!/usr/bin/env python3
import argparse

from matplotlib import pyplot
import pandas
import seaborn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("--max-rows", help="The maximum number of rows to "
                        "read from the CSV. This can be useful during testing "
                        "or if you run out of memory",
                        type=int)
    args = parser.parse_args()

    df = pandas.read_csv(
        args.filename,
        header=0,
        usecols=["function", "first difference", "time"],
        nrows=args.max_rows
    )
    df.time *= 1000000

    n_ticks = 8
    ticks = df["first difference"].unique()
    ticks.sort()
    divisor = max(1, int(len(ticks) // n_ticks))
    x_ticks = [i if i % divisor == 0 else None for i in ticks]

    seaborn.set()
    g = seaborn.catplot(
        data=df,
        kind="box",
        x="first difference",
        y="time",
        col="function",
        col_wrap=3,
        sharey=False,
        showfliers=False)
    g.set_axis_labels("Index of first difference", "Time (μs)")
    g.set_xticklabels(x_ticks)
    pyplot.show()


if __name__ == "__main__":
    main()
