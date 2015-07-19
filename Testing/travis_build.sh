#!/bin/sh

set -e

# check to see if install folder exists
if [ ! -d "$HOME/install/bin" ]; then
  # build bmi
  cd $HOME && git clone git://git.mcs.anl.gov/bmi bmi;
  cd bmi && ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$HOME/install && make && make install;
  # build mpi
  cd $HOME && wget http://www.mpich.org/static/downloads/3.1.4/mpich-3.1.4.tar.gz;
  tar -xzf mpich-3.1.4.tar.gz;
  cd mpich-3.1.4 && ./configure --disable-fortran --prefix=$HOME/install && make && make install;
  # build cci
  cd $HOME && wget http://cci-forum.com/wp-content/uploads/2015/07/cci-0.2.0.tar.gz;
  tar -xzf cci-0.2.0.tar.gz;
  cd cci-0.2.0 && ./configure --with-sm-cma --prefix=$HOME/install && make && make install;
else
  echo "Using cached directory";
fi

