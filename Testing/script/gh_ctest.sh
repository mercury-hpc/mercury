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

if [[ ${GITHUB_REPOSITORY} == 'mercury-hpc/mercury' ]]; then
  DASHBOARD_SUBMIT=TRUE
else
  DASHBOARD_SUBMIT=FALSE
fi

if [[ ${MERCURY_LIBS} == 'static' ]]; then
  BUILD_SHARED=FALSE
else
  BUILD_SHARED=TRUE
fi

# Source intel env when using icc
if [[ ${CC} == 'icc' ]]; then
  ICC_LATEST_VERSION=$(ls -1 /opt/intel/oneapi/compiler/ | grep -v latest | sort | tail -1)
  source /opt/intel/oneapi/compiler/"$ICC_LATEST_VERSION"/env/vars.sh
fi

export COV=`which gcov`

export DEPS_PREFIX=${RUNNER_TEMP}/${INSTALL_DIR}
export PATH=$DEPS_PREFIX/bin:$PATH
export LD_LIBRARY_PATH=$DEPS_PREFIX/lib:$DEPS_PREFIX/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=$DEPS_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH

$CTEST -VV --output-on-failure                        \
  -Ddashboard_full=FALSE -Ddashboard_do_${STEP}=TRUE  \
  -Ddashboard_model=${DASHBOARD_MODEL}                \
  -Dbuild_shared_libs=${BUILD_SHARED}                 \
  -Ddashboard_do_submit=${DASHBOARD_SUBMIT}           \
  -Ddashboard_allow_errors=TRUE                       \
  -S $CTEST_SCRIPT
