#!/bin/sh

echo "Running build script from repository"
echo "(current dir is repo root: $PWD)"
set
# store the current directory in a local variable to get back to it later
MERCURY_WORKSPACE_DIR=`pwd`

cd $WORKSPACE

# build bmi
git clone git://git.mcs.anl.gov/bmi bmi
pushd bmi
./prepare && ./configure --enable-shared --enable-bmi-only --prefix=$WORKSPACE/.install
make && make install
popd

# build ssm
mkdir ssm
pushd ssm
cp /homes/soumagne/jenkins/libssm_ref-0.6.6-r2263.tar.gz .
tar -xzf libssm_ref-0.6.6-r2263.tar.gz
pushd libssm_ref-0.6.6-r2263
./configure --prefix=$WORKSPACE/.install CFLAGS=-fPIC
make && make install
popd
cp /homes/soumagne/jenkins/libssmptcp_ref-0.6.6-r2264.tar.gz .
tar -xzf libssmptcp_ref-0.6.6-r2264.tar.gz
pushd libssmptcp_ref-0.6.6-r2264
./configure --prefix=$WORKSPACE/.install CFLAGS=-fPIC CPPFLAGS=-I$WORKSPACE/.install/include
make && make install
popd
popd

# get back to the location where we were at the begining
cd $MERCURY_WORKSPACE_DIR

# export variable needed for bmi testing
export MERCURY_PORT_NAME='tcp://localhost:3344'

# echo mpi commands needed to compile
echo "mpicc -show"
mpicc -show

# configure, build and test
export MERCURY_BUILD_CONFIGURATION="Debug"
export MERCURY_DASHBOARD_MODEL="Nightly"
export MERCURY_DO_COVERAGE="TRUE"
export MERCURY_DO_MEMCHECK="TRUE"
ctest -S $PWD/Testing/jenkins_mercury.cmake -VV 2>&1

