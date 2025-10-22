Contents:
This artifact contains the source code and dataset for our study. The two main
claims of our paper are presented in Figure 5, Section 7.2, and Figure 6,
Section 7.3. We provide the code and raw data to generate these figures.
Furthermore, since we perform a large-scale study in our paper, we also provide
a scaled-down version of the experiments, which may be used by evaluators.  We
deliver this artifact in the form of a compressed tar archive named
`acsac_2025_artifact_submission.tar.gz`, hosted on zenodo.org and accessible
via this link: <link>

Dependencies:

Claim Verification:
We include iPython notebooks to verify Claim 1 and Claim 2, corresponding to
Section 7.2 and Section 7.3. These can be run out of the box on the default
runtime of Google Colab. More information on how to upload the notebook and
data to Colab can be found in the top-level README of our artifact archive and
the documentation of the claims directories.

Scaled-Down Experiments:
To carry out scaled-down experiments, we recommend using an Ubuntu 22.04
compute VM with at least 32GB RAM and 100GB of disk space. We provide
instructions for the installation of necessary software in our top-level
README.

Infrastructure:
Google Colab is sufficient to generate the plots from raw data in Section 7.2
and Section 7.3. However, performing full experiments is highly
compute-intensive and requires a VM with ArangoDB and Docker installed. We
provide scripts to carry out scaled-down versions of these experiments.

Execution:
Claims can be verified by uploading iPython notebooks to Google Colab. More
detailed instructions are in the top-level README of our artifact archive.

Repository Links:
Hosted on Zenodo.org

Note:
Our submission is currently under minor revision under the guidance of an
anonymous shepherd. Hence we are uploading a de-anonymized copy of our paper as it
was reviewed for minor revision, given that the final edits to the paper are
still under review.
