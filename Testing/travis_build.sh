#!/bin/sh

# build bmi
git clone git://git.mcs.anl.gov/bmi bmi
cd bmi && ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=/usr && make && sudo make install

# echo mpi commands needed to compile
echo "which mpicc"
which mpicc
echo "mpicc -show"
mpicc -show

# build cci
git clone --branch=v0.2.0 https://github.com/CCI/cci.git
cd cci && ./autogen.pl && ./configure --prefix=/usr && make && sudo make install

