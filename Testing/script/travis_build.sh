#!/bin/bash

CMAKE_VERSION_MAJOR=3.7
CMAKE_VERSION_MINOR=2
GMP_VERSION=6.1.1
MPC_VERSION=1.0.3
MPFR_VERSION=3.1.5
GCC_VERSION=6.3.0
MPI_VERSION=3.2
CCI_VERSION=2.0

set -e

# check to see if install folder exists
if [ ! -d "$HOME/install/bin" ]; then
  if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
    # CMake
    cd $HOME && wget --no-check-certificate http://www.cmake.org/files/v${CMAKE_VERSION_MAJOR}/cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
    tar --strip-components=1 -xzC $HOME/install -f cmake-${CMAKE_VERSION_MAJOR}.${CMAKE_VERSION_MINOR}-Linux-x86_64.tar.gz;
    if [[ $CC == 'gcc' ]]; then
      # GMP
      cd $HOME && wget http://ftp.gnu.org/gnu/gmp/gmp-${GMP_VERSION}.tar.bz2;
      tar -xjf gmp-${GMP_VERSION}.tar.bz2;
      cd gmp-${GMP_VERSION} && ./configure --enable-fat --prefix=$HOME/install && make -j2 -s && make -s install;
      # MPFR
      cd $HOME && wget http://ftp.gnu.org/gnu/mpfr/mpfr-${MPFR_VERSION}.tar.bz2;
      tar -xjf mpfr-${MPFR_VERSION}.tar.bz2;
      cd mpfr-${MPFR_VERSION} && ./configure --prefix=$HOME/install --disable-dependency-tracking --disable-assert --disable-static --with-gmp=$HOME/install && make -j2 -s && make -s install;
      # MPC
      cd $HOME && wget http://ftp.gnu.org/gnu/mpc/mpc-${MPC_VERSION}.tar.gz;
      tar -xzf mpc-${MPC_VERSION}.tar.gz;
      cd mpc-${MPC_VERSION} && ./configure --prefix=$HOME/install --disable-dependency-tracking --disable-static --with-gmp=$HOME/install --with-mpfr=$HOME/install && make -j2 -s && make -s install;
      # GCC
      cd $HOME && wget ftp://ftp.gnu.org/gnu/gcc/gcc-${GCC_VERSION}/gcc-${GCC_VERSION}.tar.bz2;
      tar -xjf gcc-${GCC_VERSION}.tar.bz2;
      cd gcc-${GCC_VERSION} && ./configure --disable-bootstrap --enable-languages=c,c++ --prefix=$HOME/install --enable-shared --enable-threads=posix --enable-checking=release --with-system-zlib --enable-linker-build-id --with-linker-hash-style=gnu --enable-initfini-array --disable-libgcj --without-isl --enable-gnu-indirect-function --with-tune=generic --disable-multilib --with-gmp=$HOME/install --with-mpc=$HOME/install --with-mpfr=$HOME/install && make -j2 -s && make -s install;
    fi
    # MPI
    cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
    tar -xzf mpich-${MPI_VERSION}.tar.gz;
    cd mpich-${MPI_VERSION} && ./configure --disable-fortran --prefix=$HOME/install && make -j2 -s && make install;
  fi
  # BMI
  cd $HOME && git clone git://git.mcs.anl.gov/bmi bmi && cd bmi;
  if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
      patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/bmi_osx.patch
  fi
  ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$HOME/install && make -j2 -s && make install;
  # CCI
  cd $HOME && wget http://cci-forum.com/wp-content/uploads/2016/06/cci-${CCI_VERSION}.tar.gz
  tar -xzf cci-${CCI_VERSION}.tar.gz && cd cci-${CCI_VERSION};
  patch -p1 < ${TRAVIS_BUILD_DIR}/Testing/script/cci_20161121.patch
  ./configure --prefix=$HOME/install && make -j2 -s && make install;
else
  echo "Using cached directory";
fi

