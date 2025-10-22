## Cloning, Building and Patching Sysfilter

Note that we make use of `sysfilter` (https://www.usenix.org/conference/raid2020/presentation/demarinis) - an open source research static binary analysis tool to extract FCG. We introduce some custom patches to modify the functionality of `sysfilter` to suit our needs.\
Clone sysfilter into the `sysfilter_extend` directory:
```
$ cd sysfilter_extend
$ clone --recursive git@gitlab.com:egalito/sysfilter

# Checkout to the specified commit on top of which we apply our patches
$ cd sysfilter
$ git checkout 1469319ba6ea7cab87638c1f879541e78d72d470
```
## The Docker Container
The `Dockerfile` is used to build the `sysfilter:patched` image. This image provides a debian sid container that runs a patched version of `sysfilter`. The patches we use are in the `sysfilter_extend/patches` directory. The docker image can be built as follows:
```
$ docker build -t sysfilter:patched .
```
The image is now ready to analyze binaries. In order to test that `sysfilter` is installed and running correctly, do the following test:
```
$ docker container run -it --entrypoint=/bin/bash --rm sysfilter:patched
# Inside the docker container, verify sysfilter is running, for test commands refer documentation
$ sysfilter_extract --help
```
The `docker-compose.yml` file can be used to spin up multiple containers based on the `sysfilter:patched` image to analyze binaries of a large number of deb packages in batches and in parallel.

## Analyzing Binaries of Deb Packages

A list of deb packages can be specified in the file `FINAL_ANALYSIS_DEB_LIST.txt`. This serves as an input to `pre-start.sh` script that splits the list into `n` batches where `n` is the number of cores on the machine. It also creates the directory structure `docker_vols` with sub-directories that will be used as `volume mounts` for Docker containers.\
The `docker-compose.yml` file spools up `n` containers based off the `sysfilter:patched` Docker image.\
The objective is the following:
- Have a container for each batch of deb packages
- For each deb package - perform a clean installation of the package and all its dependencies
- Run sysfilter analysis on all ELF64 binaries installed by the deb packages and its dependencies
- Collect the FCG json files in the volume mounts
- Purge the installation of the package and its dependencies to enable a clean installation for the next package
The sysfilter analysis of all binaries installed by a deb package and its dependencies is done by `scripts/install_packages.sh`. When building `sysfilter:patched` image, this folder is added to the image and this script serves as the entrypoint.

## Running
After the setup, to spool up all containers run the following:
```
$ docker compose up
```

