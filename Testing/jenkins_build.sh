#!/bin/sh

echo "Running build script from repository"
echo "(current dir is repo root: $PWD)"
set
# store the current directory in a local variable to get back to it later
MERCURY_WORKSPACE_DIR=$PWD

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

# build cci
CCI_VERSION=master
mkdir cci
pushd cci
cp /homes/soumagne/jenkins/cci-${CCI_VERSION}.tar.gz .
tar -xzf cci-${CCI_VERSION}.tar.gz
pushd cci-${CCI_VERSION}
./configure --prefix=$WORKSPACE/.install --enable-static
make && make install
popd
popd

# echo mpi commands needed to compile
echo "mpicc -show"
mpicc -show

# set up testing configuration
export MERCURY_BUILD_CONFIGURATION="Debug"
export MERCURY_DASHBOARD_MODEL="Nightly"
export MERCURY_DO_COVERAGE="true"
export MERCURY_DO_MEMCHECK="true"

# export variable needed for bmi testing
export MERCURY_PORT_NAME='tcp://localhost:3344'

# get back to the testing script location
pushd $MERCURY_WORKSPACE_DIR/Testing
ctest -S jenkins_mercury.cmake -VV 2>&1
popd

