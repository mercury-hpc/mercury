#!/bin/bash

# Versions
BMI_VERSION=latest
MPI_VERSION=4.3.1
#OFI_PR=
OFI_VERSION=2.3.1
# PSM_VERSION=updates
UCX_VERSION=1.19.0

if [[ $MERCURY_BUILD_CONFIGURATION == 'Debug' ]]; then
  OFI_EXTRA_FLAGS="--enable-debug"
  # PSM_EXTRA_FLAGS="PSM_DEBUG=1"
  UCX_EXTRA_FLAGS="--enable-debug"
elif [[ $MERCURY_BUILD_CONFIGURATION == 'Asan' ]]; then
    BUILD_MPI=0
elif [[ $MERCURY_BUILD_CONFIGURATION == 'Tsan' ]]; then
      BUILD_MPI=0
      BUILD_UCX=0
      OFI_CFLAGS="-O1 -g -fsanitize=thread"
      OFI_EXTRA_FLAGS="--enable-debug"
      # PSM_EXTRA_FLAGS="PSM_DEBUG=1 PSM_SANITIZE=1"
      UCX_CFLAGS="-O1 -g -fsanitize=thread"
      UCX_EXTRA_FLAGS="--enable-debug"
fi

PREFIX=${RUNNER_TEMP}/${INSTALL_DIR}

set -e

# Default to GNU compilers when building dependencies
if [[ ${CC} == 'icx' ]]; then
  CC=gcc
  CXX=g++
  BUILD_MPI=0
fi

# BMI
cd $HOME && git clone https://github.com/radix-io/bmi.git bmi-${BMI_VERSION};
cd bmi-${BMI_VERSION} && ./prepare && ./configure --enable-shared --disable-static --enable-bmi-only --prefix=$PREFIX && make -j2 -s && make install;

# OFI
if [ -z "$OFI_PR" ]; then
  cd $HOME && wget --secure-protocol=TLSv1_2 https://github.com/ofiwg/libfabric/releases/download/v${OFI_VERSION}/libfabric-${OFI_VERSION}.tar.bz2
  tar -xjf libfabric-${OFI_VERSION}.tar.bz2;
  cd libfabric-${OFI_VERSION};
  patch -p1 < ${GITHUB_WORKSPACE}/Testing/script/ofi_socket_assert.patch
else
  git clone https://github.com/ofiwg/libfabric.git libfabric-${OFI_VERSION};
  cd libfabric-${OFI_VERSION};
  git fetch origin pull/${OFI_PR}/head:ofi_pr;
  git checkout ofi_pr;
  ./autogen.sh;
fi
./configure --prefix=$PREFIX --disable-usnic --disable-mrail --disable-rstream --disable-perf --disable-efa --disable-psm2 --disable-psm --disable-opx --disable-dmabuf_peer_mem --disable-hook_hmem --disable-hook_debug --disable-rxd --disable-udp --disable-verbs --disable-shm --disable-static --disable-silent-rules ${OFI_EXTRA_FLAGS} CC="${CC}" CFLAGS="${OFI_CFLAGS}" && make -j2 -s && make install;

if [[ ${RUNNER_OS} == 'Linux' ]]; then
  if [[ ${BUILD_MPI} != '0' ]]; then
    # MPI
    cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
    tar -xzf mpich-${MPI_VERSION}.tar.gz;
    cd mpich-${MPI_VERSION} && ./configure --enable-lib-depend --disable-rpath --disable-silent-rules --disable-dependency-tracking --disable-fortran --enable-shared --enable-static=no --with-pm=hydra:gforker --with-libfabric=$PREFIX --with-hwloc --prefix=$PREFIX && make -j2 -s && make install;
  fi

  if [[ ${BUILD_UCX} != '0' ]]; then
    # UCX
    cd $HOME && wget --secure-protocol=TLSv1_2 https://github.com/openucx/ucx/releases/download/v${UCX_VERSION}/ucx-${UCX_VERSION}.tar.gz
    tar -xzf ucx-${UCX_VERSION}.tar.gz;
    cd ucx-${UCX_VERSION};
    ./configure --prefix=$PREFIX --enable-profiling --enable-frame-pointer --enable-stats --enable-memtrack --enable-fault-injection --enable-mt --disable-numa --without-java --without-go --disable-silent-rules ${UCX_EXTRA_FLAGS} CC="${CC}" CXX="${CXX}" CFLAGS="${UCX_CFLAGS}" && make -j2 -s && make install;
  fi

  # PSM
  # cd $HOME && git clone https://github.com/mercury-hpc/psm.git -b ${PSM_VERSION} psm-${PSM_VERSION}
  # cd psm-${PSM_VERSION}
  # make install DESTDIR=$PREFIX ${PSM_EXTRA_FLAGS}
fi

