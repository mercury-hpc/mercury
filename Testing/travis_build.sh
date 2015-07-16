#!/bin/sh

# build bmi
cd $TRAVIS_BUILD_DIR/.. && git clone git://git.mcs.anl.gov/bmi bmi
cd bmi && ./prepare && ./configure --enable-shared --enable-bmi-only --prefix=/usr && make && sudo make install

# echo mpi commands needed to compile
echo "which mpicc"
which mpicc
echo "mpicc -show"
mpicc -show

# build cci
cd $TRAVIS_BUILD_DIR/.. && wget http://cci-forum.com/wp-content/uploads/2015/07/cci-0.2.0.tar.gz
tar -xzvf cci-0.2.0.tar.gz
cd cci-0.2.0 && ./configure --prefix=/usr && make && sudo make install

# go back to build dir
cd $TRAVIS_BUILD_DIR

