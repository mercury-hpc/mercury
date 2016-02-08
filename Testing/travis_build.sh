#!/bin/sh
MPI_VERSION=3.2
CCI_VERSION=0.3.0

set -e

# check to see if install folder exists
if [ ! -d "$HOME/install/bin" ]; then
  # build bmi
  cd $HOME && git clone git://git.mcs.anl.gov/bmi bmi;
  cd bmi && ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$HOME/install && make && make install;
  # build mpi
  cd $HOME && wget http://www.mpich.org/static/downloads/${MPI_VERSION}/mpich-${MPI_VERSION}.tar.gz;
  tar -xzf mpich-${MPI_VERSION}.tar.gz;
  cd mpich-${MPI_VERSION} && ./configure --disable-fortran --prefix=$HOME/install && make && make install;
  # build cci
  cd $HOME && wget http://cci-forum.com/wp-content/uploads/2015/12/cci-${CCI_VERSION}.tar.gz
  tar -xzf cci-${CCI_VERSION}.tar.gz;
  cd cci-${CCI_VERSION} && ./configure --prefix=$HOME/install && make && make install;
else
  echo "Using cached directory";
fi

