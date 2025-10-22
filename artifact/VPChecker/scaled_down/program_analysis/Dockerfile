FROM debian:sid

# Create apt debug package list
# Install critical packages, mark and hold them to prevent uninstallation during autoremove
RUN 	DEBIAN_FRONTEND=noninteractive apt update && \
	echo "deb http://debug.mirrors.debian.org/debian-debug/ unstable-debug main" | tee /etc/apt/sources.list.d/ddebian.list && \
	DEBIAN_FRONTEND=noninteractive apt update && \
	DEBIAN_FRONTEND=noninteractive apt upgrade -y  &&\
	DEBIAN_FRONTEND=noninteractive apt install -y \
				binutils \
				tar \
				pigz \
				git \
				lsb-release \
				build-essential \
				gdb \
				file \
				libc6-dbg \
				libreadline-dev &&\
#				libcapstone5 \
#				libcapstone-dev &&\
	DEBIAN_FRONTEND=noninteractive apt-mark manual \
				binutils \
				tar \
				pigz \
				lsb-release \
				build-essential \
				gdb \
				file \
				libc6-dbg \
				libreadline-dev
#				libcapstone5 \
#				libcapstone-dev
ADD sysfilter_extend /sysfilter_extend

# Build sysfilter
WORKDIR /sysfilter_extend/sysfilter/extraction

# Compile sysfilter
RUN make -j$(nproc)

# Create symlink for sysfilter_extract
RUN ln -s /sysfilter_extend/sysfilter/extraction/app/build_x86_64/sysfilter_extract /usr/bin/sysfilter_extract

ADD scripts /home
RUN mkdir -p /home/SYSFILTER_ANALYSIS/EXE_DEBS && mkdir -p /home/SYSFILTER_ANALYSIS/LIBS

ENTRYPOINT ["/home/install_packages.sh"]
