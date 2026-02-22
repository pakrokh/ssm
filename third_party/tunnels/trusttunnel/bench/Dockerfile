# syntax=docker/dockerfile:1
FROM python:3.13-slim-bullseye

ARG RUST_CHANNEL=1.85
ARG LLVM_MAJOR_VER=17

# Install the required utilities
RUN apt update && \
    apt install -y build-essential curl git gnupg lsb-release iproute2 \
    net-tools software-properties-common wget tar libssl-dev xz-utils

# Install pre-built CMake
RUN set -ex; \
    CMAKE_VERSION="3.31.10"; \
    ARCH=$(uname -m); \
    case "$ARCH" in \
        x86_64)  CMAKE_ARCH="x86_64" ;; \
        aarch64) CMAKE_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac; \
    curl -L "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-${CMAKE_ARCH}.tar.gz" \
        -o /tmp/cmake.tar.gz && \
    tar -xzf /tmp/cmake.tar.gz -C /usr/local --strip-components=1 && \
    rm /tmp/cmake.tar.gz

# Install pre-built static curl with HTTP/3 support
RUN set -ex; \
    ARCH=$(uname -m); \
    case "$ARCH" in \
        x86_64)  CURL_ARCH="x86_64" ;; \
        aarch64) CURL_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac; \
    CURL_VERSION="8.18.0"; \
    curl -L "https://github.com/stunnel/static-curl/releases/download/${CURL_VERSION}/curl-linux-${CURL_ARCH}-glibc-${CURL_VERSION}.tar.xz" \
        -o /tmp/curl.tar.xz && \
    tar -xf /tmp/curl.tar.xz -C /usr/local/bin && \
    rm /tmp/curl.tar.xz && \
    chmod +x /usr/local/bin/curl

## Install LLVM
RUN curl -O https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh $LLVM_MAJOR_VER && \
    rm ./llvm.sh && \
    apt install -y libc++-${LLVM_MAJOR_VER}-dev && \
    apt install -y libclang-17-dev && \
    ln -s libc++abi.so.1 /usr/lib/llvm-$LLVM_MAJOR_VER/lib/libc++abi.so
# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_CHANNEL}
ENV PATH="/root/.cargo/bin:${PATH}"

CMD bash
