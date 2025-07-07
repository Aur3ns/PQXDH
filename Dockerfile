FROM debian:bookworm-slim

RUN \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y astyle cmake doxygen gcc git graphviz libsodium-dev \
        libssl-dev ninja-build python3-pytest python3-pytest-xdist \
        python3-yaml sudo unzip valgrind xsltproc
WORKDIR /usr/app/
COPY "." "."
RUN git submodule update --init
WORKDIR /usr/app/liboqs/build/
RUN \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=ON .. && \
    make -j$(nproc) && \
    make install
WORKDIR /usr/app/
RUN \
    make && \
    apt-get clean

ENTRYPOINT [ "./test_pqxdh" ]
