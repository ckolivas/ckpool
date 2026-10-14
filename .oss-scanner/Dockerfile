FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    CC=gcc \
    CXX=g++ \
    CFLAGS="-g -O2 -Wall -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O2 -Wall -fno-omit-frame-pointer"

# Keep the compiler, debugger and test tools in the scanner's development image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates capnproto \
        clang gdb git libcapnp-dev libsodium-dev libtool libzmq3-dev \
        pkg-config python3 yasm \
    && rm -rf /var/lib/apt/lists/*

# The scanner supplies a clean git checkout as the context. For local builds,
# use a fresh clone, not a working directory containing pool configs or keys.
COPY . /src
WORKDIR /src

# The scanner's initial clone is not recursive. Fetch the exact recorded commit
# while network access is available; scans and subsequent tests run offline.
RUN git submodule update --init --recursive

# Use the checked-in IPC C++ bindings, as in the normal project build. The
# vendored .capnp files are not a complete source set for regenerating them.
RUN ./autogen.sh \
    && ./configure --enable-sv2 \
    && grep -q '^#define HAVE_SV2 1$' config.h \
    && grep -q '^#define HAVE_CAPNP 1$' config.h \
    && pkg-config --exists libzmq \
    && make -j 32

# Leave all test drivers and debug symbols available for further investigation.
# A failing regression test fails this image build.
RUN make -j 32 check
