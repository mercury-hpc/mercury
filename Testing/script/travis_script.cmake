# This script takes in optional environment variables.
#   MERCURY_BUILD_CONFIGURATION=Debug | Release
#   MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
#   MERCURY_BUILD_STATIC_LIBRARIES
#   MERCURY_DO_COVERAGE
#   MERCURY_DO_MEMCHECK

# MERCURY_BUILD_CONFIGURATION = Debug | Release
set(MERCURY_BUILD_CONFIGURATION "$ENV{MERCURY_BUILD_CONFIGURATION}")
if(NOT MERCURY_BUILD_CONFIGURATION)
  set(MERCURY_BUILD_CONFIGURATION "Debug")
endif()
string(TOLOWER ${MERCURY_BUILD_CONFIGURATION} lower_mercury_build_configuration)
set(CTEST_BUILD_CONFIGURATION ${MERCURY_BUILD_CONFIGURATION})

# MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
set(MERCURY_DASHBOARD_MODEL "$ENV{MERCURY_DASHBOARD_MODEL}")
if(NOT MERCURY_DASHBOARD_MODEL)
  set(MERCURY_DASHBOARD_MODEL "Experimental")
endif()
set(dashboard_model ${MERCURY_DASHBOARD_MODEL})

# Disable loop when MERCURY_DASHBOARD_MODEL=Continuous
set(MERCURY_NO_LOOP $ENV{MERCURY_NO_LOOP})
if(MERCURY_NO_LOOP)
  message("Disabling looping (if applicable)")
  set(dashboard_disable_loop TRUE)
endif()

# Disable source tree update and use current version
set(CTEST_UPDATE_VERSION_ONLY TRUE)

# Number of jobs to build and verbose mode
set(CTEST_BUILD_FLAGS "-j4")

# Build shared libraries
set(mercury_build_shared ON)
set(MERCURY_BUILD_STATIC_LIBRARIES $ENV{MERCURY_BUILD_STATIC_LIBRARIES})
if(MERCURY_BUILD_STATIC_LIBRARIES)
  message("Building static libraries")
  set(mercury_build_shared OFF)
endif()

set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
# Must point to the root where we can checkout/build/run the tests
set(CTEST_DASHBOARD_ROOT "$ENV{TRAVIS_BUILD_DIR}/..")
# Must specify existing source directory
set(CTEST_SOURCE_DIRECTORY "$ENV{TRAVIS_BUILD_DIR}")
# Give a site name
set(CTEST_SITE "worker.travis-ci.org")
set(CTEST_TEST_TIMEOUT 180) # 180s timeout

# Optional coverage options
set(MERCURY_DO_COVERAGE $ENV{MERCURY_DO_COVERAGE})
if(MERCURY_DO_COVERAGE)
  message("Enabling Coverage")
  set(CTEST_COVERAGE_COMMAND "/usr/bin/gcov-8")
  # don't run parallel coverage tests, no matter what.
  set(CTEST_TEST_ARGS PARALLEL_LEVEL 1)

  # needed by mercury_common.cmake
  set(dashboard_do_coverage TRUE)

  # build suffix
  set(coverage_suffix "-coverage")

  # add Coverage dir to the root so that we don't mess the non-coverage
  # dashboard.
  set(CTEST_DASHBOARD_ROOT "${CTEST_DASHBOARD_ROOT}/Coverage")
endif()

# Optional memcheck options
set(MERCURY_DO_MEMCHECK $ENV{MERCURY_DO_MEMCHECK})
set(MERCURY_MEMORYCHECK_TYPE "$ENV{MERCURY_MEMORYCHECK_TYPE}")
if(MERCURY_DO_MEMCHECK OR MERCURY_MEMORYCHECK_TYPE)
  message("Enabling Memcheck")

  if(NOT MERCURY_MEMORYCHECK_TYPE)
    set(MERCURY_MEMORYCHECK_TYPE "Valgrind")
  endif()
  string(TOLOWER "-${MERCURY_MEMORYCHECK_TYPE}" lower_mercury_memorycheck_type)
  set(CTEST_MEMORYCHECK_TYPE ${MERCURY_MEMORYCHECK_TYPE})

  # Valgrind
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "Valgrind")
    set(CTEST_MEMORYCHECK_COMMAND "/usr/bin/valgrind")
    set(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--gen-suppressions=all --trace-children=yes --fair-sched=yes -q --leak-check=yes --show-reachable=yes --num-callers=50 -v")
    #set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE ${CTEST_SCRIPT_DIRECTORY}/MercuryValgrindSuppressions.supp)
  endif()
  # Tsan
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "ThreadSanitizer")
    set(MERCURY_MEMCHECK_FLAGS "-O1 -fsanitize=thread -fno-omit-frame-pointer -fPIC -fuse-ld=gold -pthread")
    # Must add verbosity / Error in build if no memory output file is produced
    set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "verbosity=1")
  endif()
  # Asan
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "AddressSanitizer")
    set(MERCURY_MEMCHECK_FLAGS "-O1 -fsanitize=address -fno-omit-frame-pointer -fPIC -fuse-ld=gold -pthread")
    # Must add verbosity / Error in build if no memory output file is produced
    set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "verbosity=1")
  endif()

  # needed by mercury_common.cmake
  set(dashboard_do_memcheck TRUE)
endif()

# Build name referenced in cdash
set(CTEST_BUILD_NAME "travis-ci-$ENV{TRAVIS_OS_NAME}-x64-$ENV{CC}-${lower_mercury_build_configuration}${lower_mercury_memorycheck_type}${coverage_suffix}-$ENV{TRAVIS_BUILD_NUMBER}")

set(dashboard_binary_name mercury-${lower_mercury_build_configuration})
if(NOT mercury_build_shared)
  set(dashboard_binary_name ${dashboard_binary_name}-static)
endif()

# OS specific options
if(APPLE)
  set(SOEXT dylib)
  set(PROC_NAME_OPT -c)
  set(USE_BMI OFF)
  set(USE_MPI OFF)
  set(USE_CCI OFF)
  set(USE_SM OFF)
else()
  set(SOEXT so)
  set(PROC_NAME_OPT -r)
  set(USE_BMI ON)
  set(USE_MPI ON)
  set(USE_CCI ON)
  set(USE_SM ON)
  set(CMAKE_FIND_ROOT_PATH $ENV{HOME}/install ${CMAKE_FIND_ROOT_PATH})
endif()

if($ENV{CC} MATCHES "^gcc.*")
  set(MERCURY_C_FLAGS "-Wall -Wextra -Wshadow -Winline -Wundef -Wcast-qual -Wconversion -Wmissing-prototypes -pedantic -Wpointer-arith -Wformat=2 -std=gnu11 ${MERCURY_MEMCHECK_FLAGS}")
endif()

# Initial cache used to build mercury, options can be modified here
set(dashboard_cache "
CMAKE_C_FLAGS:STRING=${MERCURY_C_FLAGS}
CMAKE_CXX_FLAGS:STRING=${MERCURY_MEMCHECK_FLAGS}

BUILD_SHARED_LIBS:BOOL=${mercury_build_shared}
BUILD_TESTING:BOOL=ON

MEMORYCHECK_COMMAND:FILEPATH=${CTEST_MEMORYCHECK_COMMAND}
MEMORYCHECK_SUPPRESSIONS_FILE:FILEPATH=${CTEST_MEMORYCHECK_SUPPRESSIONS_FILE}
COVERAGE_COMMAND:FILEPATH=${CTEST_COVERAGE_COMMAND}

MERCURY_ENABLE_COVERAGE:BOOL=${dashboard_do_coverage}
MERCURY_ENABLE_PARALLEL_TESTING:BOOL=${USE_MPI}
MERCURY_USE_BOOST_PP:BOOL=OFF
MERCURY_USE_SELF_FORWARD:BOOL=ON
MERCURY_USE_XDR:BOOL=OFF
NA_USE_BMI:BOOL=${USE_BMI}
BMI_INCLUDE_DIR:PATH=$ENV{HOME}/install/include
BMI_LIBRARY:FILEPATH=$ENV{HOME}/install/lib/libbmi.${SOEXT}
NA_USE_MPI:BOOL=${USE_MPI}
NA_USE_CCI:BOOL=${USE_CCI}
NA_CCI_TESTING_PROTOCOL:STRING=
NA_USE_SM:BOOL=${USE_SM}
NA_USE_OFI:BOOL=ON
NA_OFI_TESTING_PROTOCOL:STRING=sockets;tcp
MPIEXEC_MAX_NUMPROCS:STRING=4

MERCURY_TEST_INIT_COMMAND:STRING=killall -9 ${PROC_NAME_OPT} hg_test_client;killall -9 ${PROC_NAME_OPT} hg_test_server;
MERCURY_TESTING_CORESIDENT:BOOL=ON
")

#set(ENV{CC}  /usr/bin/gcc)
#set(ENV{CXX} /usr/bin/g++)

include(${CTEST_SOURCE_DIRECTORY}/Testing/script/mercury_common.cmake)

#######################################################################
