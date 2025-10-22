## Running VPChecker on Top-10 Most Popular Debian Packages

We take the top-10 most popular Debian packages from here:
https://popcon.debian.org/main/by_inst. This will serve as a scaled-down
version of our full study.

### Preliminaries
Before starting this experiment, please ensure that all software mentioned in
the infrastructure folder is installed and set up, including ArangoDB, Python
Virtual Environment, and Docker Engine.

### Setup

The first step in VPChecker is program analysis. For this, we will consider the
list of the 10 most popular Debian packages and their dependent packages as our
supply chain. Each Debian package may contain one or more ELF64 binaries. We
will only be concerned with ELF64 binaries and ignore all other files. Further,
we will attempt to download debug packages for these regular Debian packages to
facilitate accurate program analysis.

The program analysis tool that we use is sysfilter
(https://www.usenix.org/conference/raid2020/presentation/demarinis). For more
details, refer to the documentation in the `sysfilter_extend` directory. We
patch sysfilter to suit our needs and build it from source. For the purpose of
this experiment, we have bundled a tar archive of our Docker image that
contains the patched sysfilter. We carry out all experiments inside a Debian
sid Docker container. Since the program analysis of all ELF64 binaries shipped
by a Debian package is independent of the binaries shipped by other Debian
packages, we can analyze these Debian packages in parallel in different
containers. We use docker-compose for that.

```
$ ./setup-docker-vols.sh
```

This will set up volume mounts in the `docker_vols` directory and load the
`sysfilter:patched` image from the tar archive in the `sysfilter_image`
directory.

```
$ docker compose up
```

This will spool 10 containers - each for a Debian package in the
`TOP_10_POPULAR_DEBS_LIST.txt` file. Completion of this stage will take
anywhere between 2-3 hours. After the analysis, about 178 binaries will have
their call graphs dumped into JSON files.

```
$ find docker_vols -name "*.fcg.json"
```

This will give a list of all function call graph JSON files for each binary
under a Debian package.

### Change Permissions
The directories under `docker_vols` were volume mounts for the Docker
containers. However, since the Docker daemon runs as root, we need to change
the owner of these volume mounts and the contents inside them back to a regular
user.

```
$ sudo chown -R $USER:$USER ./docker_vols
```

### ELF Processing
We will now extract data from the ELFs we analyzed, which will be used later to
create an ELF-level dependency graph - a coarse-grained view of our supply
chain consisting of 178 binaries.
```
$ cd elf_processing
$ python3 extract_ldd_info.py # Reads the ELF headers and dynamic sections to
                                create a CSV file of the binary with information containining its SONAME and
                                dynamic dependencies.
$ python3 elf_to_deb_mapping.py
```

### Initializing Databases

We will now initialize a new database `sysfilter_scaled_down`, which will house
the graphs for function-level, ELF-level, and Debian-level dependencies.

```
$ cd create_graphs
$ python3 initialize_db.py -n sysfilter_scaled_down -c call_graph
$ python3 initialize_db.py -n sysfilter_scaled_down -c ldd_graph
$ python3 initialize_db.py -n sysfilter_scaled_down -c deb_graph
```

### Creating LDD Graph

We will now create the ELF-level dependency graph. This will use the data that
we extracted in the `ELF Processing` stage.

```
$ cd create_graphs/ldd_graph
$ python3 create_ldd_graph -p ../../docker_vols
```

This will create the `ldd_graph`, which can be browsed using the ArangoDB web
interface at http://localhost:8529 by selecting the `sysfilter_scaled_down`
database.

### Creating Debian Graph

Similarly, we create the Debian graph:

```
$ cd create_graph/deb_graph
$ python3 create_deb_graph.py
```

### Creating the Function Call Graph

This graph is the core of VPChecker's contribution. It will parse all the
function call graph (FCG) JSON files of all binaries and aggregate all the
function nodes and edges into a single graph.

This has to proceed in two stages:

1. Aggregate the call graphs of all executables:
```
$ cd create_graphs/call_graph
$ python3 add_exe_to_db.py
```

2. [CAUTION: long running] Aggregate the call graphs of all dynamic shared libraries:
```
$ cd create_graphs/call_graph
$ python3 add_libs_to_db.py
```
This tends to run long, and in the most recent run on a 16-core machine, took
about 2 days to complete. This is primarily because of large shared libraries
like libcrypto, which have over 5000 exported functions. During program
analysis, we use each of those exported functions as an entry point to create a
full call graph to ensure maximum and sound coverage.

Note that while the script is running, the ArangoDB web interface is still
accessible and can be inspected to check the progress.

After this concludes, the database is ready - we have three knowledge graphs:
`call_graph`, `ldd_graph`, and `deb_graph`.
