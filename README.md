# Supply Chain Reaction: Enhancing the Precision of Vulnerability Triage using Code Reachability Information

Camera Ready Paper Link: https://harshvp1621.github.io/assets/papers/vpchecker_acsac.pdf

This repository contains the code artifacts of our tool VPChecker. This work was accepted in ACSAC 2025. Due to the large size of our dataset, this git repository includes just the code. We have also uploaded this repository with the dataset to Zenodo (https://zenodo.org/records/17110050). We recommend downloading the repository from Zenodo for ease of use.

## VPChecker - Vulnerable Path Checker

## Citation

If you use VPChecker in your research, please cite our paper:

```bibtex
@inproceedings{vpchecker2025,
  title={Supply Chain Reaction: Enhancing the Precision of Vulnerability Triage using Code Reachability Information},
  author={Harshvardhan Patel, Alexander Snit, Michalis Polychronakis},
  booktitle={Proceedings of the Annual Computer Security Applications Conference (ACSAC)},
  year={2025}
}
```

This archive provides the dataset and code that can be used to inspect and
verify the claims of our paper. We have structured the artifacts as follows:

```tree
├── artifact
│   ├── db_dump
│   ├── llvm_g_truth
│   └── VPChecker
├── claims
│   ├── claim1
│   └── claim2
├── infrastructure
│   ├── arangodb
│   └── virtual_env
├── install.sh
├── license.txt
├── README.txt
└── use.txt
```

## Artifacts Overview and Background

In this paper, we present a large-scale vulnerability reachability study of the
Debian ecosystem using a new tool, VPChecker. VPChecker has two main
components:

1. Program analysis
2. CVE localization pipeline

The use case for VPChecker is to demonstrate that constructing function-level
dependency graphs for a C/C++ supply chain using sound off-the-shelf static
analysis tools, and recording CVE information at the function level, can
greatly reduce false alarms raised by security scanners that operate at a much
coarser granularity (package or ELF level).

To show the effectiveness of this approach, we conduct a large-scale study on
over 24000 C/C++ binaries from more than 6000 Debian Sid packages. The program
analysis stage produced raw data—binaries and compressed call-graph
files—exceeding 1.4 terabytes and took more than 10 days on a 48-core Xeon
Silver-4116 (2.1 GHz) server with 372 GB of RAM running Ubuntu 22.04.1 LTS. We
then parsed all call-graph files and populated an ArangoDB graph database,
resulting in a 35 GB database. The analysis took a few additional weeks to
complete.

As part of the artifacts, we provide a dump of our database in the
`artifact/db_dump` directory. All code used to build VPChecker is in the
`artifact/VPChecker` directory. Together, these constitute the complete
codebase and dataset used to generate the results in our study.

To verify the claims in our paper, we provide the raw data needed to generate
the figures. For more information, see the "Claims Verification" section below.
The claims can be verified on public infrastructure such as Google Colab.

For scaled-down versions of the experiments that generate the raw data for the
claims, we provide scripts with each claim. However, running these experiments
requires a compute VM (https://submit.acsac.org/docs/artifact_guide/) and
installation of all software listed in the Infrastructure Setup section below.

For scaled-down versions of our full study, we provide scripts in
artifacts/VPChecker/scaled_down. These scripts generate a new graph database
from scratch for the top 10 most popular Debian packages and their
dependencies, resulting in 178 ELF binaries for analysis. However, the program
analysis and parsing into the database in the scaled-down version still take at
least a few days to complete.

## Full Dataset and Artifacts
Our full dataset and artifacts are available on Zenodo. The archive includes
the program analysis outputs, ArangoDB database dump, and Docker images used in
our experiments.

[Zenodo (full archive) — download the complete dataset and
artifacts](https://zenodo.org/records/17110050)

Quick usage notes:

1. If you only need the plots and claim verification data, download the
   claim-specific archives inside the `claims/` directory (these are small and
suitable for Colab).
2. To restore the full knowledge graph locally, download the ArangoDB dump from
   the archive and follow the instructions in
`infrastructure/arangodb/README.txt` to restore into ArangoDB.
3. To reproduce program analysis or re-run scaled experiments, use the Docker
   images or the `artifact/VPChecker` scripts and the scaled_down examples (see
`artifact/VPChecker/scaled_down`).

## Infrastructure Setup

Note: Not required for claim verification; only required for scaled-down experiments.

Base Operating System: Install Ubuntu 22.04

```text
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

1. Install the required Debian packages: `./install.sh` (requires root privileges).
2. Install ArangoDB and restore the database dump. See the README in `infrastructure/arangodb/`.
3. Install Anaconda and import the virtual environment. See the README in `infrastructure/virtual_env/`.
4. Install Docker for Linux: https://docs.docker.com/engine/install/ubuntu/

## Claims Verification

We provide verification of the two main claims in our paper: the percentage
reduction in CVE Impact and CVE Exposure scores when using VPChecker. These
claims are illustrated in Figure 5 (Section 7.2) for CVE Impact and Figure 6
(Section 7.3) for CVE Exposure. For claim verification, evaluators can use the
scripts we provide to regenerate these plots.

The claims directory has the following layout:

```tree
claims/
├── claim1
│   ├── claim.txt
│   ├── cve_impact
│   │   ├── CVE_Impact.ipynb
│   │   ├── data
│   │   ├── figs
│   │   ├── for_colab.zip
│   │   └── scripts
│   ├── expected
│   │   ├── cve_spread_redn_percent_cdf_hist.pdf
│   │   └── funcs_per_cve.pdf
│   └── run.sh
└── claim2
    ├── claim.txt
    ├── cve_exposure
    │   ├── CVE_Exposure.ipynb
    │   ├── data
    │   ├── figs
    │   ├── for_colab.zip
    │   └── scripts
    ├── expected
    │   └── cve_redn_per_bin_cdf_hist.pdf
    └── run.sh
```

We provide Jupyter notebooks for creating and visualizing plots generated from
the raw data in the `claim1/cve_impact/data` and `claim2/cve_exposure/data`
directories.

## Using Public Infrastructure for verification

We have packaged the claim artifacts to simplify running and verification on
public infrastructure such as Google Colab. The steps below show how to verify
claim 1:

1. Upload the `claim1/cve_impact/CVE_Impact.ipynb` Jupyter notebook to Google
   Colab. Plot generation is not compute-intensive, so no special hardware is
   required; the default runtime is sufficient.
2. Upload the `claim1/cve_impact/for_colab.zip` archive to Google Colab. Use
   the Upload files option in the left pane of the Colab interface.
3. Execute all cells in the notebook sequentially.
4. The cells near the end of the notebook generate the plots; for CVE Impact,
   this corresponds to Figure 5 in the paper.

Similarly, claim 2 can be evaluated using Google Colab.

## Running Scaled Down versions of Claim Experiments

The plots generated in the previous sections use raw data produced over our
entire dataset.

For claim 1, the raw data file is: `claim1/cve_impact/data/vuln_table.json`
For claim 2, the raw data file is: `claim2/cve_exposure/combine_cve_reduction.json`

This raw data is generated by performing graph traversals on our graph database
stored in artifact/db_dump. However, regenerating these files for evaluation is
not feasible because graph traversal over large, dense graphs is
compute-intensive. For the paper, our knowledge graph contains more than 16
million nodes and 70 million edges, and the experiments ran on a 48-core Intel
Xeon Silver-4116 (2.1 GHz) server with 372 GB of RAM running Ubuntu 22.04.1 LTS
and took more than a week.

For artifact evaluation, we propose running scaled-down experiments to generate
the raw data files. The experiments for each claim are as follows:

1. Claim 1 (CVE Impact): Use `claim1/cve_impact/scripts/get_vuln_reach.py` to
   compute raw CVE impact at the function and ELF levels for 9 CVEs in
   `libxml2.so.2`. For details, see the markdown cells in the CVE_Impact.ipynb
   notebook.

2. Claim 2 (CVE Exposure): Use
   `claim2/cve_exposure/scripts/get_cves_for_all.py` to compute CVE exposure
   scores at the function and ELF levels for all binaries in the `coreutils`
   package. For details, see the markdown cells in the CVE_Exposure.ipynb
   notebook.

Before running any scaled-down version of the experiment, please set up the
infrastructure, which includes:

1. Installing ArangoDB
2. Restoring the database from db_dump
3. Setting up our Python 3.11 virtual environment using Anaconda
4. Installing and setting up Docker
