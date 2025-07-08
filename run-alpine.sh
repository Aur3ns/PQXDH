#!/usr/bin/env sh

# Installing dependencies
sudo apk update && sudo apk upgrade
sudo apk add \
    astyle \
    cmake \
    doxygen \
    gcc \
    git \
    graphviz \
    libsodium-dev \
    libxslt \
    make \
    musl-dev \
    ninja-build \
    openssl-dev \
    py3-pytest \
    py3-pytest-xdist \
    py3-yaml \
    unzip \
    valgrind
git submodule update --init

# Compiling project
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON .. && \
    make -j$(nproc) && \
    sudo make install && \
    cd ../.. && \
    make
