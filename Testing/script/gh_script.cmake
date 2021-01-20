# This script takes in optional environment variables.
#   MERCURY_BUILD_CONFIGURATION=Debug | RelWithDebInfo | Release | Asan | Tsan
#   MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
#   MERCURY_BUILD_STATIC_LIBRARIES

set(CTEST_PROJECT_NAME "MERCURY")

if(NOT dashboard_git_url)
  set(dashboard_git_url "https://github.com/mercury-hpc/mercury.git")
endif()

# Timeout
if(NOT DEFINED CTEST_TEST_TIMEOUT)
  set(CTEST_TEST_TIMEOUT 180)
endif()

# Submit notes
if(NOT DEFINED CTEST_SUBMIT_NOTES)
  set(CTEST_SUBMIT_NOTES TRUE)
endif()

# Give a site name
set(CTEST_SITE "GitHub Actions")

# Site info
if(NOT DEFINED BUILD_NAME)
  set(BUILD_NAME "$ENV{GITHUB_WORKFLOW}")
endif()
if(NOT DEFINED OS_NAME)
  set(OS_NAME "$ENV{RUNNER_OS}")
endif()
if(NOT DEFINED BUILD_NUMBER)
  set(BUILD_NUMBER "$ENV{GITHUB_RUN_NUMBER}")
endif()

# Must specify existing source directory
set(CTEST_SOURCE_DIRECTORY "$ENV{GITHUB_WORKSPACE}")
set(CTEST_BINARY_DIRECTORY "${CTEST_SOURCE_DIRECTORY}/build")

# MERCURY_BUILD_CONFIGURATION
if(NOT DEFINED MERCURY_BUILD_CONFIGURATION)
  set(MERCURY_BUILD_CONFIGURATION "$ENV{MERCURY_BUILD_CONFIGURATION}")
  if(NOT MERCURY_BUILD_CONFIGURATION)
    set(MERCURY_BUILD_CONFIGURATION "Debug")
  endif()
endif()
string(TOLOWER ${MERCURY_BUILD_CONFIGURATION} lower_mercury_build_configuration)
set(CTEST_BUILD_CONFIGURATION ${MERCURY_BUILD_CONFIGURATION})

if(MERCURY_BUILD_CONFIGURATION MATCHES "Debug")
  set(enable_debug TRUE)
  if($ENV{CC} MATCHES "^gcc.*")
    set(MERCURY_DO_COVERAGE TRUE)
  else()
    set(MERCURY_DO_COVERAGE FALSE)
  endif()
else()
  set(enable_debug FALSE)
  set(MERCURY_DO_COVERAGE FALSE)
endif()
if(MERCURY_BUILD_CONFIGURATION MATCHES "Asan")
  set(MERCURY_MEMORYCHECK_TYPE "AddressSanitizer")
endif()
if(MERCURY_BUILD_CONFIGURATION MATCHES "Tsan")
  set(MERCURY_MEMORYCHECK_TYPE "ThreadSanitizer")
endif()
if(MERCURY_BUILD_CONFIGURATION MATCHES "Ubsan")
  set(MERCURY_MEMORYCHECK_TYPE "UndefinedBehaviorSanitizer")
endif()

# MERCURY_DASHBOARD_MODEL=Experimental | Nightly | Continuous
if(NOT dashboard_model)
  set(MERCURY_DASHBOARD_MODEL "$ENV{MERCURY_DASHBOARD_MODEL}")
  if(NOT MERCURY_DASHBOARD_MODEL)
    set(MERCURY_DASHBOARD_MODEL "Experimental")
  endif()
  set(dashboard_model ${MERCURY_DASHBOARD_MODEL})
endif()

find_program(CTEST_GIT_COMMAND git)

# Add current script to notes files
list(APPEND CTEST_UPDATE_NOTES_FILES "${CMAKE_CURRENT_LIST_FILE}")
set(CTEST_UPDATE_COMMAND ${CTEST_GIT_COMMAND})
set(CTEST_UPTATE_TYPE git)
set(CTEST_UPDATE_VERSION_ONLY TRUE)

# Number of jobs to build and keep going if some targets can't be made
set(CTEST_BUILD_FLAGS "-k -j4")

# Default num proc for MPI testing
set(MAX_NUMPROCS "4")

# Build shared libraries
set(MERCURY_BUILD_STATIC_LIBRARIES $ENV{MERCURY_BUILD_STATIC_LIBRARIES})
if(MERCURY_BUILD_STATIC_LIBRARIES)
  message("Building static libraries")
  set(mercury_build_shared OFF)
else()
  set(mercury_build_shared ON)
endif()

set(CTEST_CMAKE_GENERATOR "Unix Makefiles")

# Optional coverage options
if(MERCURY_DO_COVERAGE)
  message("Enabling coverage")

  set(MERCURY_COVERAGE_COMMAND $ENV{COV})
  if(NOT MERCURY_COVERAGE_COMMAND)
    set(MERCURY_COVERAGE_COMMAND gcov)
  endif()
  find_program(CTEST_COVERAGE_COMMAND ${MERCURY_COVERAGE_COMMAND})

  # don't run parallel coverage tests, no matter what.
  set(CTEST_TEST_ARGS PARALLEL_LEVEL 1)

  if(NOT DEFINED dashboard_full OR dashboard_full)
    set(dashboard_do_coverage TRUE)
  endif()
endif()

# Optional memcheck options
if(MERCURY_MEMORYCHECK_TYPE)
  message("Enabling memcheck")

  if(NOT MERCURY_MEMORYCHECK_TYPE)
    set(MERCURY_MEMORYCHECK_TYPE "Valgrind")
  endif()
  set(CTEST_MEMORYCHECK_TYPE ${MERCURY_MEMORYCHECK_TYPE})

  # Valgrind
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "Valgrind")
    set(CTEST_MEMORYCHECK_COMMAND "/usr/bin/valgrind")
    set(CTEST_MEMORYCHECK_COMMAND_OPTIONS "--gen-suppressions=all --trace-children=yes --fair-sched=yes -q --leak-check=yes --show-reachable=yes --num-callers=50 -v")
    #set(CTEST_MEMORYCHECK_SUPPRESSIONS_FILE ${CTEST_SCRIPT_DIRECTORY}/MercuryValgrindSuppressions.supp)
  endif()

  # Tsan
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "ThreadSanitizer")
    # Must add verbosity / Error in build if no memory output file is produced
    set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "verbosity=1")

    # Set num proc to 1 to speed up CI
    set(MAX_NUMPROCS "1")
  endif()

  # Asan
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "AddressSanitizer")
    # Must add verbosity / Error in build if no memory output file is produced
    set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "verbosity=1")
  endif()

  # Ubsan
  if(${MERCURY_MEMORYCHECK_TYPE} MATCHES "UndefinedBehaviorSanitizer")
    # Must add verbosity / Error in build if no memory output file is produced
    set(CTEST_MEMORYCHECK_SANITIZER_OPTIONS "verbosity=1")
    # Disable checksums to prevent output from checksum library
    set(USE_CHECKSUMS OFF)
  else()
    set(USE_CHECKSUMS ON)
  endif()

  if(NOT DEFINED dashboard_full OR dashboard_full)
    set(dashboard_do_memcheck TRUE)
  endif()
else()
  set(USE_CHECKSUMS ON)
endif()

# Build name referenced in cdash
set(CTEST_BUILD_NAME "${BUILD_NAME}-${OS_NAME}-$ENV{CC}-${lower_mercury_build_configuration}-${BUILD_NUMBER}")

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
  set(USE_OFI OFF)
  set(USE_SM OFF)
else()
  set(SOEXT so)
  set(PROC_NAME_OPT -r)
  set(USE_BMI OFF)
  set(USE_MPI OFF)
  set(USE_OFI OFF)
  set(USE_SM ON)
  set(CMAKE_FIND_ROOT_PATH $ENV{DEPS_PREFIX} ${CMAKE_FIND_ROOT_PATH})
endif()

if($ENV{CC} MATCHES "^gcc.*")
  set(MERCURY_C_FLAGS "-Wall -Wextra -Wshadow -Winline -Wundef -Wcast-qual -Wconversion -Wmissing-prototypes -pedantic -Wpointer-arith -Wformat=2 -std=gnu11")
endif()
set(MERCURY_C_FLAGS ${MERCURY_C_FLAGS})
set(MERCURY_CXX_FLAGS ${MERCURY_CXX_FLAGS})

# Initial cache used to build mercury, options can be modified here
set(dashboard_cache "
CMAKE_C_FLAGS:STRING=${MERCURY_C_FLAGS}
CMAKE_CXX_FLAGS:STRING=${MERCURY_CXX_FLAGS}

BUILD_SHARED_LIBS:BOOL=${mercury_build_shared}
BUILD_TESTING:BOOL=ON

MEMORYCHECK_COMMAND:FILEPATH=${CTEST_MEMORYCHECK_COMMAND}
MEMORYCHECK_SUPPRESSIONS_FILE:FILEPATH=${CTEST_MEMORYCHECK_SUPPRESSIONS_FILE}
COVERAGE_COMMAND:FILEPATH=${CTEST_COVERAGE_COMMAND}

MERCURY_ENABLE_COVERAGE:BOOL=${MERCURY_DO_COVERAGE}
MERCURY_ENABLE_DEBUG:BOOL=${enable_debug}
MERCURY_USE_BOOST_PP:BOOL=OFF
MERCURY_USE_CHECKSUMS:BOOL=${USE_CHECKSUMS}
MERCURY_USE_XDR:BOOL=OFF
NA_USE_BMI:BOOL=${USE_BMI}
BMI_INCLUDE_DIR:PATH=$ENV{DEPS_PREFIX}/include
BMI_LIBRARY:FILEPATH=$ENV{DEPS_PREFIX}/lib/libbmi.${SOEXT}
NA_USE_MPI:BOOL=${USE_MPI}
NA_USE_CCI:BOOL=OFF
NA_USE_SM:BOOL=${USE_SM}
NA_USE_OFI:BOOL=${USE_OFI}
NA_OFI_TESTING_PROTOCOL:STRING=sockets;tcp
NA_USE_UCX:BOOL=ON
MPIEXEC_MAX_NUMPROCS:STRING=${MAX_NUMPROCS}

MERCURY_TESTING_ENABLE_PARALLEL:BOOL=${USE_MPI}
MERCURY_TESTING_INIT_COMMAND:STRING=killall -9 ${PROC_NAME_OPT} hg_test_server;
")

include(${CTEST_SOURCE_DIRECTORY}/Testing/script/mercury_common.cmake)
