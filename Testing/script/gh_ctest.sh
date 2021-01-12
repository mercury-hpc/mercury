#!/bin/bash

set -e

if [ -z "$1" ]
then
  echo "Error: no step passed"
  exit 1
fi

CTEST=ctest
CTEST_SCRIPT=Testing/script/gh_script.cmake
STEP=$1

if [[ ${GITHUB_REF}  == 'refs/heads/master' ]] && [[ ${GITHUB_EVENT_NAME} == 'push' ]]; then
  DASHBOARD_MODEL="Continuous"
else
  DASHBOARD_MODEL="Experimental"
fi

export COV=`which gcov`

export DEPS_PREFIX=${RUNNER_TEMP}/${INSTALL_DIR}
export PATH=$DEPS_PREFIX/bin:$PATH
export LD_LIBRARY_PATH=$DEPS_PREFIX/lib:$DEPS_PREFIX/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=$DEPS_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH

$CTEST -VV --output-on-failure                        \
  -Ddashboard_full=FALSE -Ddashboard_do_${STEP}=TRUE  \
  -Ddashboard_model=${DASHBOARD_MODEL}                \
  -Ddashboard_allow_errors=TRUE                       \
  -S $CTEST_SCRIPT
