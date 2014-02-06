# This script takes in optional environment variables.
#   MERCURY_BUILD_CONFIGURATION=Debug | Release
#   MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
#   MERCURY_BUILD_STATIC_LIBRARIES
#   MERCURY_DO_COVERAGE

# MERCURY_BUILD_CONFIGURATION = Debug | Release
set(MERCURY_BUILD_CONFIGURATION "Debug")

# MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
set(MERCURY_DASHBOARD_MODEL "Nightly")

# Disable loop when MERCURY_DASHBOARD_MODEL=Continuous
message("Disabling looping (if applicable)")
set(dashboard_disable_loop TRUE)

# Build shared libraries
set(mercury_build_shared ON)

string(TOLOWER ${MERCURY_DASHBOARD_MODEL} lower_mercury_dashboard_model)
string(TOLOWER ${MERCURY_BUILD_CONFIGURATION} lower_mercury_build_configuration)
set(CTEST_BUILD_CONFIGURATION ${MERCURY_BUILD_CONFIGURATION})
# Number of jobs to build
set(CTEST_BUILD_FLAGS "-j4")
# Build name referenced in cdash
set(CTEST_BUILD_NAME "jenkins-x64-${lower_mercury_dashboard_model}")
if($ENV{MERCURY_BUILD_STATIC_LIBRARIES})
  message("Building static libraries")
  set(CTEST_BUILD_NAME "${CTEST_BUILD_NAME}-static")
  set(mercury_build_shared OFF)
endif()

set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
# Must point to the root where we can checkout/build/run the tests
set(CTEST_DASHBOARD_ROOT 
  "$ENV{WORKSPACE}/${MERCURY_DASHBOARD_MODEL}")
# Give a site name
set(CTEST_SITE "$ENV{NODE_NAME}")
set(CTEST_TEST_TIMEOUT 180) # 3 minute timeout

# Optional coverage options
set(dashboard_do_coverage ON)
if(dashboard_do_coverage)
  message("Enabling Coverage")
  set(CTEST_COVERAGE_COMMAND "/usr/bin/gcov")
  set(CTEST_BUILD_NAME "${CTEST_BUILD_NAME}-coverage")
  # don't run parallel coverage tests, no matter what.
  # set(CTEST_TEST_ARGS PARALLEL_LEVEL 1)

  # add Coverage dir to the root so that we don't mess the non-coverage
  # dashboard.
  set(CTEST_DASHBOARD_ROOT "${CTEST_DASHBOARD_ROOT}/Coverage")
endif()

set(dashboard_source_name mercury)
set(dashboard_binary_name mercury-${lower_mercury_build_configuration})
if(NOT mercury_build_shared)
  set(dashboard_binary_name ${dashboard_binary_name}-static)
endif()
set (dashboard_model ${MERCURY_DASHBOARD_MODEL})

# Initial cache used to build mercury, options can be modified here
set(dashboard_cache "
CMAKE_C_FLAGS:STRING=-Wall -Wextra -Wshadow -Winline -Wundef -Wcast-qual -std=gnu99

BUILD_SHARED_LIBS:BOOL=${mercury_build_shared}
BUILD_TESTING:BOOL=ON

MERCURY_ENABLE_COVERAGE:BOOL=${dashboard_do_coverage}
MERCURY_USE_BOOST_PP:BOOL=OFF
MERCURY_USE_XDR:BOOL=OFF
NA_USE_BMI:BOOL=ON
BMI_INCLUDE_DIR:PATH=$ENV{WORKSPACE}/.install/include
BMI_LIBRARY:FILEPATH=$ENV{WORKSPACE}/.install/lib/libbmi.so
NA_USE_MPI:BOOL=ON
OPA_INCLUDE_DIR:PATH=/usr/include
OPA_LIBRARY:FILEPATH=/usr/lib/libopa.so
MPIEXEC_MAX_NUMPROCS:STRING=4
")

set(dashboard_git_url $ENV{GIT_URL})
#set(dashboard_git_branch $ENV{GIT_BRANCH})
#set(dashboard_git_commit $ENV{GIT_COMMIT})

#set(ENV{CC}  /usr/bin/gcc)
#set(ENV{CXX} /usr/bin/g++)
#set(ENV{FC}  /usr/bin/gfortran)

include($ENV{PWD}/Testing/mercury_common.cmake)

#######################################################################
