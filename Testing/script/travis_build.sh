#!/bin/bash

CMAKE_VERSION_MAJOR=3.5
CMAKE_VERSION_MINOR=2
GCC_VERSION=6.1.0
MPI_VERSION=3.2
CCI_VERSION=2.0

set -e

# check to see if install folder exists
if [ ! -d "$HOME/install/bin" ]; then
  if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
      # CMake
      cd $HOME && wget --no-check-certificate http://www.cmake.org/files/v${CMAKE_VERSION_MAJOR}/cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
      tar --strip-components=1 -xzC $HOME/install -f cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
      # GCC
      cd $HOME && wget ftp://ftp.gnu.org/gnu/gcc/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.bz2;
      tar -xjf gcc-${GCC_VERSION}.tar.bz2;
      cd gcc-${GCC_VERSION} && ./configure --disable-bootstrap --enable-languages=c,c++ --prefix=$HOME/install --enable-shared --enable-threads=posix --enable-checking=release --with-system-zlib --enable-linker-build-id --with-linker-hash-style=gnu --enable-initfini-array --disable-libgcj --without-isl --enable-gnu-indirect-function --with-tune=generic --disable-multilib && make -j2 -s && make install;
  else # OSX
      # CMake
      cd $HOME && wget --no-check-certificate http://www.cmake.org/files/v${CMAKE_VERSION_MAJOR}/cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Darwin-x86_64.tar.gz;
      tar --strip-components=3 -xzC $HOME/install -f cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Darwin-x86_64.tar.gz;
  fi
  # BMI
  cd $HOME && git clone git://git.mcs.anl.gov/bmi bmi && cd bmi;
  if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
      patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/bmi_osx.patch
  fi
  ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$HOME/install && make -j2 -s && make install;
  # MPI
  cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
  tar -xzf mpich-${MPI_VERSION}.tar.gz;
  cd mpich-${MPI_VERSION} && ./configure --disable-fortran --prefix=$HOME/install && make -j2 -s && make install;
  # CCI
  cd $HOME && wget http://cci-forum.com/wp-content/uploads/2016/06/cci-${CCI_VERSION}.tar.gz
  tar -xzf cci-${CCI_VERSION}.tar.gz && cd cci-${CCI_VERSION};
  patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/cci_sm.patch
  ./configure --prefix=$HOME/install && make -j2 -s && make install;
else
  echo "Using cached directory";
fi

