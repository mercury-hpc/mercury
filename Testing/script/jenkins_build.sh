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

# build cci
CCI_VERSION=2.0
mkdir cci
pushd cci
wget http://cci-forum.com/wp-content/uploads/2016/06/cci-${CCI_VERSION}.tar.gz
tar -xzf cci-${CCI_VERSION}.tar.gz
pushd cci-${CCI_VERSION}
patch -p1 < $MERCURY_WORKSPACE_DIR/Testing/script/cci_sm.patch
./configure --prefix=$WORKSPACE/.install --enable-static && make && make install
popd
popd

# echo mpi commands needed to compile
echo "mpicc -show"
mpicc -show

# set up testing configuration
export MERCURY_BUILD_CONFIGURATION="Debug"
export MERCURY_DASHBOARD_MODEL="Nightly"
export MERCURY_DO_COVERAGE="true"
export MERCURY_DO_MEMCHECK="false"

# export variable needed for bmi testing
export MERCURY_PORT_NAME='tcp://localhost:3344'

# get back to the testing script location
pushd $MERCURY_WORKSPACE_DIR/Testing/script
ctest -S jenkins_script.cmake -VV 2>&1
popd

