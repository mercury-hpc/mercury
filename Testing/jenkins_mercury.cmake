# This script takes in optional environment variables.
#   MERCURY_BUILD_CONFIGURATION=Debug | Release
#   MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
#   MERCURY_BUILD_STATIC_LIBRARIES
#   MERCURY_DO_COVERAGE

# MERCURY_BUILD_CONFIGURATION = Debug | Release
set(MERCURY_BUILD_CONFIGURATION "$ENV{MERCURY_BUILD_CONFIGURATION}")
if(NOT MERCURY_BUILD_CONFIGURATION)
  set(MERCURY_BUILD_CONFIGURATION "Debug")
endif()

# MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
set(MERCURY_DASHBOARD_MODEL "$ENV{MERCURY_DASHBOARD_MODEL}")
if(NOT MERCURY_DASHBOARD_MODEL)
  set(MERCURY_DASHBOARD_MODEL "Experimental")
endif()

# Disable loop when MERCURY_DASHBOARD_MODEL=Continuous
if($ENV{MERCURY_NO_LOOP})
  message("Disabling looping (if applicable)")
  set(dashboard_disable_loop TRUE)
endif()

# Build shared libraries
set(mercury_build_shared ON)

string(TOLOWER ${MERCURY_DASHBOARD_MODEL} lower_mercury_dashboard_model)
string(TOLOWER ${MERCURY_BUILD_CONFIGURATION} lower_mercury_build_configuration)
set(CTEST_BUILD_CONFIGURATION ${MERCURY_BUILD_CONFIGURATION})
# Number of jobs to build
set(CTEST_BUILD_FLAGS "-j2")
# Build name referenced in cdash
set(CTEST_BUILD_NAME "$ENV{MACHTYPE}-${lower_mercury_dashboard_model}")
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
set(cov_options)
if($ENV{MERCURY_DO_COVERAGE})
  message("Enabling Coverage")
  set(CTEST_COVERAGE_COMMAND "/usr/bin/gcov")
  set(cov_options "-fprofile-arcs -ftest-coverage")
  set(CTEST_BUILD_NAME "${CTEST_BUILD_NAME}-coverage")
  # don't run parallel coverage tests, no matter what.
  set(CTEST_TEST_ARGS PARALLEL_LEVEL 1)

  # needed by mercury_common.cmake 
  set(dashboard_do_coverage TRUE)

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
CMAKE_C_FLAGS:STRING=-Wall -Wextra -Wshadow ${cov_options}
CMAKE_EXE_LINKER_FLAGS:STRING=${cov_options}
CMAKE_SHARED_LINKER_FLAGS:STRING=${cov_options}

BUILD_SHARED_LIBS:BOOL=${mercury_build_shared}
BUILD_TESTING:BOOL=ON

MERCURY_USE_BOOST_PP:BOOL=ON
MERCURY_USE_XDR:BOOL=OFF
NA_USE_BMI:BOOL=ON                                           
NA_USE_MPI:BOOL=ON                                           
MPIEXEC_MAX_NUMPROCS:STRING=4
")

set(dashboard_git_url $ENV{GIT_URL})
#set(dashboard_git_branch $ENV{GIT_BRANCH})
#set(dashboard_git_commit $ENV{GIT_COMMIT})

#set(ENV{CC}  /usr/bin/gcc)
#set(ENV{CXX} /usr/bin/g++)
#set(ENV{FC}  /usr/bin/gfortran)

include(mercury_common.cmake)

#######################################################################
