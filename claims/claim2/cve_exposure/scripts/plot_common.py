import pandas as pd
import seaborn as sns
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

def plot_cdf(input_dict, xlabel, ylabel, x_percent, xticks, xticks_sparse, aspect, fontsize, save_path, plt_style="seaborn-v0_8-whitegrid"):
    """ Input Dict: Simple dictionary with string keys and numeric values
        Plots the CDF
        Saves the figure in PDF format at save_path
    """
    # We plot the values on X-Axis and denote the cumulative distribution on the Y-Axis
    data_values = np.sort(np.array(list(input_dict.values()))) 
    
    cdf_plot = sns.ecdfplot(data=data_values, color='steelblue')
    
    cdf_plot.set(xticks=xticks,yticks=np.arange(0,1.1,0.1), xlabel=xlabel, ylabel=f"{ylabel} (n={len(data_values)})")
    
    # Have the distribution on Y-Axis in percentage
    plt.gca().set_yticklabels(['{:.0f}%'.format(y * 100) for y in plt.gca().get_yticks()])

    # Check for x-axis
    if x_percent:
        # Have percentage
        plt.gca().set_xticklabels(['{:.0f}%'.format(x * 100) for x in plt.gca().get_xticks()])

    if xticks_sparse:
        unique_x_values = np.unique(data_values)
        plt.xticks(unique_x_values)
        plt.grid(axis='x', linestyle="--")
        
    # Get current axis limits
    xlim = plt.xlim()
    ylim = plt.ylim()

    plt.gcf().subplots_adjust(bottom=0.05)
    plt.gcf().subplots_adjust(top=0.1)
    
    # Set new limits with a gap
    plt.xlim(xlim[0] - 0.02, xlim[1] + 0.02)
    plt.ylim(ylim[0], ylim[1] + 0.02)

    # Make a thicker plot boundary
    for spine in plt.gca().spines.values():
        spine.set_linewidth(1.0)
        spine.set_edgecolor('black')

    # Set the default font size for labels globally
    plt.rcParams['axes.labelsize'] = fontsize
    plt.style.use(plt_style)
    plt.gca().set_aspect(aspect=aspect, anchor='SW')
    plt.tight_layout(pad=1.0)
    # plt.figure(figsize=(10, 4))
    plt.savefig(save_path, bbox_inches='tight')
    # Show the plot
    plt.show()

def plot_cdf_and_hist(
    input_dict,
    xlabel,
    ylabel_cdf,
    ylabel_hist,
    x_percent,
    xticks,
    xticks_sparse,
    legend_loc,
    aspect,
    fontsize,
    save_path,
    plt_style="seaborn-v0_8-whitegrid",
    bins="auto",
):
    """Histogram (left y‑axis, raw counts) + CDF (right y‑axis, % of CVEs)."""

    # ------------------------------ setup ---------------------------------
    plt.style.use(plt_style)
    sns.set_context("talk", font_scale=fontsize / 9)

    # convert 0–1 fractions → 0–100 %
    data_values = np.sort(np.array(list(input_dict.values())) * 100)

    fig, ax_cdf = plt.subplots(figsize=(16, 9))

    sns.ecdfplot(
        data_values,
        ax=ax_cdf,
        color="steelblue",
        linewidth=3,
        label=f"{ylabel_cdf}",
    )
    ax_cdf.set_ylabel(f"{ylabel_cdf} (n={len(data_values)})", labelpad=12)
    ax_cdf.set_ylim(0, 1)
    ax_cdf.yaxis.set_major_formatter(mtick.PercentFormatter(1.0))

    ax_hist = ax_cdf.twinx()
    sns.histplot(
        data_values,
        bins=20,
        stat="count",
        edgecolor=None,         # ← no outlines
        linewidth=0,
        alpha=0.30,
        ax=ax_hist,
        label=ylabel_hist,
    )
    ax_cdf.set_xlabel(xlabel)
    ax_hist.set_ylabel(ylabel_hist, labelpad=12)    
    ax_hist.grid(False)

    # ---------------- shared x‑axis --------------------------------------
    if xticks is not None:
        ax_hist.set_xticks(xticks)

    # format x‑axis as 0–100 %
    if x_percent:
        ax_hist.xaxis.set_major_formatter(mtick.PercentFormatter(100))

    # unique‑value ticks if requested and auto‑bins
    if xticks_sparse and bins == "auto":
        ax_hist.set_xticks(np.unique(data_values))
        ax_hist.grid(axis="x", linestyle="--", linewidth=0.5)

    # optional custom grid for sparse ticks
    ax_hist.set_xticks(np.arange(0, 101, 10))   # 0,10,…,100

    # optional aspect ratio
    # if aspect != "auto":
    #     ax_hist.set_aspect(aspect, anchor="SW")
        
    ax_hist.set_ylim(bottom=0)                  # keep bars on baseline

    # thicker border on main axes
    for spine in (*ax_hist.spines.values(), *ax_cdf.spines.values()):
        spine.set_linewidth(1.0)
        spine.set_edgecolor("black")

    # --------------- combined legend -------------------------------------
    handles, labels = [], []
    for ax in (ax_hist, ax_cdf):
        h, l = ax.get_legend_handles_labels()
        handles.extend(h)
        labels.extend(l)
    print(labels)
    ax_hist.legend(handles, 
                   labels,
                   loc=legend_loc,
                   # bbox_to_anchor=(1.02, 0.5),   # x, y in axes fraction coords
                   # borderaxespad=0,
                   # frameon=True
                  )

    plt.tight_layout(pad=1.0)
    # plt.rcParams.update({"font.weight": "bold"})
    plt.savefig(save_path, bbox_inches="tight")
    plt.show()
            
def plot_cdf_size(input_dict, xlabel, ylabel, x_percent, xticks, xticks_sparse, aspect, fontsize, save_path, plt_style="seaborn-v0_8-whitegrid"):
    """ Input Dict: Simple dictionary with string keys and numeric values
        Plots the CDF
        Saves the figure in PDF format at save_path
    """
    # We plot the values on X-Axis and denote the cumulative distribution on the Y-Axis
    data_values = sorted(input_dict.values())
    
    cdf_plot = sns.ecdfplot(data=data_values, x=data_values, linewidth=5, color='steelblue')
    
    cdf_plot.set(xticks=xticks,yticks=np.arange(0,1.1,0.1), xlabel=xlabel, ylabel=f"{ylabel} (n={len(data_values)})")
    
    # Have the distribution on Y-Axis in percentage
    plt.gca().set_yticklabels(['{:.0f}%'.format(y * 100) for y in plt.gca().get_yticks()])

    # Check for x-axis
    if x_percent:
        # Have percentage
        plt.gca().set_xticklabels(['{:.0f}%'.format(x * 100) for x in plt.gca().get_xticks()])

    if xticks_sparse:
        unique_x_values = np.unique(data_values)
        plt.xticks(unique_x_values)
        plt.grid(axis='x', linestyle="--")
        
    # Get current axis limits
    xlim = plt.xlim()
    ylim = plt.ylim()

    plt.gcf().subplots_adjust(bottom=0.05)
    plt.gcf().subplots_adjust(top=0.1)
    
    # Set new limits with a gap
    plt.xlim(xlim[0] - 0.02, xlim[1] + 0.02)
    plt.ylim(ylim[0], ylim[1] + 0.02)

    # Make a thicker plot boundary
    for spine in plt.gca().spines.values():
        spine.set_linewidth(1.0)
        spine.set_edgecolor('black')

    # Set the default font size for labels globally
    plt.rcParams['axes.labelsize'] = fontsize
    plt.style.use(plt_style)
    plt.gcf().set_size_inches((6.5,4))
    # plt.gca().set_aspect(aspect=aspect, anchor='SW')
    # plt.figure().set_figwidth(15)
    # plt.figure().set_figheight(15)
    plt.tight_layout(pad=1.0)
    # plt.figure(figsize=(10, 4))
    plt.savefig(save_path, bbox_inches='tight')
    # Show the plot
    plt.show()
