#!/bin/sh

echo "Running build script from repository"
echo "(current dir is repo root: $PWD)"
set
#cmake . && make
ctest -S $PWD/Testing/jenkins_mercury.cmake -VV 2>&1

