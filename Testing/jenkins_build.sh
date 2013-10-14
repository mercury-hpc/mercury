#!/bin/sh

echo "Running build script from repository"
echo "(current dir is repo root: $PWD)"
set
# store the current directory in a local variable to get back to it later
MERCURY_WORKSPACE_DIR=`pwd`

# clone bmi's git repository
git clone git://git.mcs.anl.gov/bmi $WORKSPACE/bmi

# build bmi
cd $WORKSPACE/bmi
./prepare && CFLAGS=-fPIC ./configure --prefix=$WORKSPACE/.install
make && make install

# get back to the location where we were at the begining
cd $MERCURY_WORKSPACE_DIR

# export variable needed for bmi testing
export MERCURY_PORT_NAME='tcp://localhost:3344'

# configure, build and test
ctest -S $PWD/Testing/jenkins_mercury.cmake -VV 2>&1

