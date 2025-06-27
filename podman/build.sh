# This script is used by the Dockerfile and not meant to be run on their own!
git config --global --add safe.directory /mnt
rm -r build/
mkdir build && cd build && ../configure --target-list=x86_64-softmmu --disable-werror && make -j`nproc`
