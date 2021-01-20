#!/bin/bash

BMI_VERSION=master
if [[ $MERCURY_BUILD_CONFIGURATION == 'Tsan' ]]; then
  OFI_CFLAGS="-O1 -g -fsanitize=thread"
  OFI_EXTRA_FLAGS="--enable-debug"
fi
if [[ $MERCURY_BUILD_CONFIGURATION == 'Debug' ]]; then
  OFI_EXTRA_FLAGS="--enable-debug"
fi
#OFI_PR=
OFI_VERSION=1.11.2
PREFIX=${RUNNER_TEMP}/${INSTALL_DIR}

set -e

if [[ ${RUNNER_OS} == 'Linux' ]]; then
  # BMI
  cd $HOME && wget --no-check-certificate http://xgitlab.cels.anl.gov/sds/bmi/-/archive/${BMI_VERSION}/bmi-${BMI_VERSION}.tar.bz2;
  tar -xjf bmi-${BMI_VERSION}.tar.bz2;
  # if [[ $OS_NAME == 'osx' ]]; then
  #    patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/bmi_osx.patch
  # fi
  cd bmi-${BMI_VERSION} && ./prepare && ./configure --enable-shared --disable-static --enable-bmi-only --prefix=$PREFIX && make -j2 -s && make install;

  # OFI
  if [ -z "$OFI_PR" ]; then
    cd $HOME && wget https://github.com/ofiwg/libfabric/releases/download/v${OFI_VERSION}/libfabric-${OFI_VERSION}.tar.bz2
    tar -xjf libfabric-${OFI_VERSION}.tar.bz2;
    cd libfabric-${OFI_VERSION};
    wget https://github.com/ofiwg/libfabric/pull/6509.patch
    patch -p1 < 6509.patch
  else
    git clone https://github.com/ofiwg/libfabric.git libfabric-${OFI_VERSION};
    cd libfabric-${OFI_VERSION};
    git fetch origin pull/${OFI_PR}/head:ofi_pr;
    git checkout ofi_pr;
    ./autogen.sh;
  fi
  ./configure --prefix=$PREFIX --disable-usnic --disable-mrail --disable-rstream --disable-perf --disable-efa --disable-psm2 --disable-psm --disable-verbs --disable-shm --disable-static --disable-silent-rules ${OFI_EXTRA_FLAGS} CC="${CC}" CFLAGS="${OFI_CFLAGS}" && make -j2 -s && make install;
fi
