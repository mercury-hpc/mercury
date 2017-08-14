#!/bin/bash

MPI_VERSION=3.2
CCI_VERSION=2.0
OFI_VERSION=1.5.0

set -e

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
  # BMI
  if [ ! -f "$HOME/install/include/bmi.h" ]; then
    cd $HOME && git clone git://git.mcs.anl.gov/bmi bmi && cd bmi;
    # if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    #    patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/bmi_osx.patch
    # fi
    ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$HOME/install && make -j2 -s && make install;
  else
    echo "Using cached directory for BMI";
  fi

  # MPI
  if [ ! -f "$HOME/install/bin/mpicc" ]; then
    cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
    tar -xzf mpich-${MPI_VERSION}.tar.gz;
    cd mpich-${MPI_VERSION} && ./configure --disable-fortran --prefix=$HOME/install && make -j2 -s && make install;
  else
    echo "Using cached directory for MPI";
  fi

  # CCI
  if [ ! -f "$HOME/install/bin/cci_info" ]; then
    cd $HOME && wget http://cci-forum.com/wp-content/uploads/2016/06/cci-${CCI_VERSION}.tar.gz
    tar -xzf cci-${CCI_VERSION}.tar.gz && cd cci-${CCI_VERSION};
    patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/cci_20170206.patch
    ./configure --prefix=$HOME/install && make -j2 -s && make install;
  else
    echo "Using cached directory for CCI";
  fi

  # OFI
  if [ ! -f "$HOME/install/bin/fi_info" ]; then
    cd $HOME && wget https://github.com/ofiwg/libfabric/releases/download/v${OFI_VERSION}/libfabric-${OFI_VERSION}.tar.bz2
    tar -xjf libfabric-${OFI_VERSION}.tar.bz2;
    cd libfabric-${OFI_VERSION} && ./configure --prefix=$HOME/install && make -j2 -s && make install;
  else
    echo "Using cached directory for OFI";
  fi
fi
