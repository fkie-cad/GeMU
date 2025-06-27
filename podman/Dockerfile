FROM ubuntu:22.04

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y build-essential ninja-build git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
  git-email \
  libaio-dev libbluetooth-dev libcapstone-dev libbrlapi-dev libbz2-dev \
  libcap-ng-dev libcurl4-gnutls-dev libgtk-3-dev \
  libibverbs-dev libjpeg8-dev libncurses5-dev libnuma-dev \
  librbd-dev librdmacm-dev \
  libsasl2-dev libsdl2-dev libseccomp-dev libsnappy-dev libssh-dev \
  libvde-dev libvdeplug-dev libvte-2.91-dev libxen-dev liblzo2-dev \
  valgrind xfslibs-dev libnfs-dev libiscsi-dev lsof genisoimage


WORKDIR /gemu
ADD . /gemu
RUN mkdir /root/.roamer2 && cp ./gemu/apidoc.json ./gemu/modules.lst ./gemu/symbol_mapping.txt /root/.roamer2
RUN chmod +x ./podman/build.sh && ./podman/build.sh
