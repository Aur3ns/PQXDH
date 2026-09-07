FROM debian:bookworm-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        libssl-dev \
        libsodium-dev \
        ninja-build \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pqxdh
COPY . .

RUN test -f liboqs/CMakeLists.txt || \
        (echo "liboqs is missing; initialize submodules before docker build" >&2; exit 1)

RUN cmake \
        -S liboqs \
        -B liboqs/build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_USE_OPENSSL=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024" && \
    cmake --build liboqs/build --parallel && \
    cmake --install liboqs/build && \
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --parallel

ENTRYPOINT ["./build/test_pqxdh"]
