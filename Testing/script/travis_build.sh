#!/bin/bash

BMI_VERSION=master
CMAKE_VERSION_MAJOR=3.16
CMAKE_VERSION_MINOR=1
MPI_VERSION=3.3.2
CCI_VERSION=2.1
OFI_VERSION=1.9.0
PREFIX=$HOME/install

set -e

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
  # BMI
  if [ -f "$PREFIX/bmi_version.txt" ]; then
    BMI_INSTALLED_VERSION=`cat $PREFIX/bmi_version.txt`;
  fi
  if [ ! -f "$PREFIX/include/bmi.h" ] || [ "$BMI_INSTALLED_VERSION" != "${BMI_VERSION}" ]; then
    cd $HOME && wget --no-check-certificate http://xgitlab.cels.anl.gov/sds/bmi/-/archive/${BMI_VERSION}/bmi-${BMI_VERSION}.tar.bz2;
    tar -xjf bmi-${BMI_VERSION}.tar.bz2;
    # if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    #    patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/bmi_osx.patch
    # fi
    cd bmi-${BMI_VERSION} && ./prepare && ./configure --enable-shared --disable-static --enable-bmi-only --prefix=$PREFIX && make -j2 -s && make install;
    echo "${BMI_VERSION}" > $PREFIX/bmi_version.txt
  else
    echo "Using cached directory for BMI";
  fi

  # CMake
  if [ -f "$PREFIX/cmake_version.txt" ]; then
    CMAKE_INSTALLED_VERSION=`cat $PREFIX/cmake_version.txt`;
  fi
  if [ ! -f "$PREFIX/bin/cmake" ] || [ "$CMAKE_INSTALLED_VERSION" != "${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}" ]; then
    cd $HOME && wget --no-check-certificate http://www.cmake.org/files/v${CMAKE_VERSION_MAJOR}/cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
    tar --strip-components=1 -xzC $PREFIX -f cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
    echo "${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}" > $PREFIX/cmake_version.txt
  else
    echo "Using cached directory for CMake";
  fi

  # MPI
  if [ -f "$PREFIX/mpi_version.txt" ]; then
    MPI_INSTALLED_VERSION=`cat $PREFIX/mpi_version.txt`;
  fi
  if [ ! -f "$PREFIX/bin/mpicc" ] || [ "${MPI_INSTALLED_VERSION}" != "${MPI_VERSION}" ]; then
    cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
    tar -xzf mpich-${MPI_VERSION}.tar.gz;
    cd mpich-${MPI_VERSION} && ./configure --disable-fortran --prefix=$PREFIX && make -j2 -s && make install;
    echo "${MPI_VERSION}" > $PREFIX/mpi_version.txt
  else
    echo "Using cached directory for MPI";
  fi

  # CCI
  if [ ! -f "$PREFIX/bin/cci_info" ]; then
    cd $HOME && wget http://cci-forum.com/wp-content/uploads/2017/05/cci-${CCI_VERSION}.tar.gz
    tar -xzf cci-${CCI_VERSION}.tar.gz && cd cci-${CCI_VERSION};
    patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/cci_20170918.patch
    ./configure --disable-silent-rules --disable-static --prefix=$PREFIX && make -j2 -s && make install;
  else
    echo "Using cached directory for CCI";
  fi

  # OFI
  if [ -f "$PREFIX/ofi_version.txt" ]; then
    OFI_INSTALLED_VERSION=`cat $PREFIX/ofi_version.txt`;
  fi
  if [ ! -f "$PREFIX/bin/fi_info" ] || [ "${OFI_INSTALLED_VERSION}" != "${OFI_VERSION}" ]; then
    cd $HOME && wget https://github.com/ofiwg/libfabric/releases/download/v${OFI_VERSION}/libfabric-${OFI_VERSION}.tar.bz2
    tar -xjf libfabric-${OFI_VERSION}.tar.bz2;
    cd libfabric-${OFI_VERSION} && ./configure --prefix=$PREFIX --disable-rxd --disable-usnic --disable-mrail --disable-rstream --disable-perf --disable-efa --disable-psm2 --disable-psm --disable-udp --disable-verbs --disable-shm --disable-static --disable-silent-rules CFLAGS="-O2 -g" && make -j2 -s && make install;
    echo "${OFI_VERSION}" > $PREFIX/ofi_version.txt
  else
    echo "Using cached directory for OFI";
  fi
fi

