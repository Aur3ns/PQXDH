#!/usr/bin/env bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y astyle cmake gcc git ninja-build libssl-dev libsodium-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
git submodule update --init
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON ..
make -j$(nproc)
sudo make install
cd ..
cd ..
make
