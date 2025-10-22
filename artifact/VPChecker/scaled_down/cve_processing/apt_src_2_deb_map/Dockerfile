from debian:sid

RUN echo "deb-src http://deb.debian.org/debian/ sid main" | tee /etc/apt/sources.list.d/debian-src.list && \
    DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt install -y python3

ADD vuln_apt_sources.txt /home

ADD ./get_apt_src_bin_debs.py /home

ADD ./get_deb_tags.py /home

WORKDIR /home

ENTRYPOINT ["python3", "/home/get_apt_src_bin_debs.py"]
