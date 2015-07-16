#!/bin/sh

# build bmi
git clone git://git.mcs.anl.gov/bmi bmi
cd bmi && ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=/usr && make && sudo make install

# echo mpi commands needed to compile
echo "mpicc -show"
which mpicc
mpicc -show

# build cci
#CCI_VERSION=master
#mkdir cci
#pushd cci
#cp /homes/soumagne/jenkins/cci-${CCI_VERSION}.tar.gz .
#tar -xzf cci-${CCI_VERSION}.tar.gz
#pushd cci-${CCI_VERSION}
#./configure --prefix=$WORKSPACE/.install --enable-static
#make && make install
#popd
#popd

