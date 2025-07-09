FROM alpine:3.22.0

# Installing dependencies
RUN \
    apk update && \
    apk upgrade && \
    apk add --no-cache \
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
