#!/bin/bash

BMI_VERSION=master
#MPI_VERSION=3.4.1
if [[ $MERCURY_BUILD_CONFIGURATION == 'Tsan' ]]; then
  OFI_CFLAGS="-O1 -g -fsanitize=thread"
  OFI_EXTRA_FLAGS="--enable-debug"
fi
if [[ $MERCURY_BUILD_CONFIGURATION == 'Debug' ]]; then
  OFI_EXTRA_FLAGS="--enable-debug"
fi
#OFI_PR=
OFI_VERSION=1.12.0

# UCX
if [[ $MERCURY_BUILD_CONFIGURATION == 'Tsan' ]]; then
  UCX_CFLAGS="-O1 -g -fsanitize=thread"
  UCX_EXTRA_FLAGS="--enable-debug"
fi
if [[ $MERCURY_BUILD_CONFIGURATION == 'Debug' ]]; then
  UCX_EXTRA_FLAGS="--enable-debug"
fi
UCX_VERSION=1.10.1

PREFIX=${RUNNER_TEMP}/${INSTALL_DIR}

set -e

# BMI
cd $HOME && wget --no-check-certificate http://xgitlab.cels.anl.gov/sds/bmi/-/archive/${BMI_VERSION}/bmi-${BMI_VERSION}.tar.bz2;
tar -xjf bmi-${BMI_VERSION}.tar.bz2;
cd bmi-${BMI_VERSION} && ./prepare && ./configure --enable-shared --disable-static --enable-bmi-only --prefix=$PREFIX && make -j2 -s && make install;

# MPI
#cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
#tar -xzf mpich-${MPI_VERSION}.tar.gz;
#cd mpich-${MPI_VERSION} && ./configure --disable-fortran --with-device=ch3 --prefix=$PREFIX && make -j2 -s && make install;

# OFI
if [ -z "$OFI_PR" ]; then
  cd $HOME && wget https://github.com/ofiwg/libfabric/releases/download/v${OFI_VERSION}/libfabric-${OFI_VERSION}.tar.bz2
  tar -xjf libfabric-${OFI_VERSION}.tar.bz2;
  cd libfabric-${OFI_VERSION};
  #wget https://github.com/ofiwg/libfabric/pull/6509.patch
  #patch -p1 < 6509.patch
  patch -p1 < ${GITHUB_WORKSPACE}/Testing/script/ofi_socket_assert.patch
else
  git clone https://github.com/ofiwg/libfabric.git libfabric-${OFI_VERSION};
  cd libfabric-${OFI_VERSION};
  git fetch origin pull/${OFI_PR}/head:ofi_pr;
  git checkout ofi_pr;
  ./autogen.sh;
fi
./configure --prefix=$PREFIX --disable-usnic --disable-mrail --disable-rstream --disable-perf --disable-efa --disable-psm2 --disable-psm --disable-verbs --disable-shm --disable-static --disable-silent-rules ${OFI_EXTRA_FLAGS} CC="${CC}" CFLAGS="${OFI_CFLAGS}" && make -j2 -s && make install;

if [[ ${RUNNER_OS} == 'Linux' ]]; then
  # UCX
  cd $HOME && wget https://github.com/openucx/ucx/releases/download/v${UCX_VERSION}/ucx-${UCX_VERSION}.tar.gz
  tar -xzf ucx-${UCX_VERSION}.tar.gz;
  cd ucx-${UCX_VERSION};
  ./configure --prefix=$PREFIX --enable-profiling --enable-frame-pointer --enable-stats --enable-memtrack --enable-fault-injection --enable-mt --disable-numa --without-java --disable-silent-rules ${UCX_EXTRA_FLAGS} CC="${CC}" CXX="${CXX}" CFLAGS="${UCX_CFLAGS}" && make -j2 -s && make install;
fi

