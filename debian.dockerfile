FROM debian:bookworm-slim

# Installing dependencies
RUN \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        astyle \
        cmake \
        doxygen \
        gcc \
        git \
        graphviz \
        libsodium-dev \
        libssl-dev \
        ninja-build \
        python3-pytest \
        python3-pytest-xdist \
        python3-yaml \
        unzip \
        valgrind \
        xsltproc && \
    apt-get clean
WORKDIR /usr/app/
COPY "." "."
RUN git submodule update --init

# Compiling project
WORKDIR /usr/app/liboqs/build/
RUN \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON .. && \
    make -j$(nproc) && \
    make install
WORKDIR /usr/app/
RUN make

# Running tests
ENTRYPOINT [ "./test_pqxdh" ]
