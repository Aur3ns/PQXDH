#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIBOQS_DIR="${ROOT_DIR}/liboqs"
LIBOQS_BUILD_DIR="${LIBOQS_DIR}/build"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"

sudo apk add --no-cache \
    build-base \
    cmake \
    git \
    libsodium-dev \
    ninja \
    openssl-dev \
    pkgconf

git -C "${ROOT_DIR}" submodule update --init --recursive

cmake \
    -S "${LIBOQS_DIR}" \
    -B "${LIBOQS_BUILD_DIR}" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024"

cmake --build "${LIBOQS_BUILD_DIR}" --parallel "${JOBS}"
sudo cmake --install "${LIBOQS_BUILD_DIR}"

cmake \
    -S "${ROOT_DIR}" \
    -B "${ROOT_DIR}/build" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release

cmake --build "${ROOT_DIR}/build" --parallel "${JOBS}"
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure
