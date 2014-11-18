#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")
mark_as_advanced(MERCURY_TESTING_BUFFER_SIZE)

set(MERCURY_TESTING_MAX_LOOP "1" CACHE STRING
  "Loop n times for average bandwidth/time measures.")
mark_as_advanced(MERCURY_TESTING_MAX_LOOP)

set(MERCURY_TESTING_NUM_THREADS "8" CACHE STRING
  "Number of server threads used for testing.")
mark_as_advanced(MERCURY_TESTING_NUM_THREADS)

option(MERCURY_TESTING_USE_THREAD_POOL
  "Run tests using thread pool." ON)
if(MERCURY_TESTING_USE_THREAD_POOL)
  set(MERCURY_TESTING_HAS_THREAD_POOL ON)
endif(MERCURY_TESTING_USE_THREAD_POOL)
mark_as_advanced(MERCURY_TESTING_USE_THREAD_POOL)

option(MERCURY_TESTING_VERIFY_DATA
  "Verify data when running tests (disable when measuring bandwidth)." ON)
if(MERCURY_TESTING_VERIFY_DATA)
  set(MERCURY_TESTING_HAS_VERIFY_DATA ON)
endif(MERCURY_TESTING_VERIFY_DATA)
mark_as_advanced(MERCURY_TESTING_VERIFY_DATA)

option(MERCURY_ENABLE_PARALLEL_TESTING
  "Enable testing in parallel (requires MPI)." OFF)
if(MERCURY_ENABLE_PARALLEL_TESTING OR NA_USE_MPI)
  set(MERCURY_HAS_PARALLEL_TESTING 1)
  if(NA_USE_MPI AND NOT MERCURY_ENABLE_PARALLEL_TESTING)
    # Always force parallel testing if NA_USE_MPI is turned ON
    set(MERCURY_ENABLE_PARALLEL_TESTING "ON" CACHE BOOL
      "Enable testing in parallel (requires MPI)." FORCE)
  endif()
else()
  set(MERCURY_HAS_PARALLEL_TESTING 0)
endif()

set(MERCURY_TEST_INIT_COMMAND "" CACHE STRING
  "Command to run before a client/server test begins. Multiple commands are separated by ';'.")
mark_as_advanced(MERCURY_TEST_INIT_COMMAND)

set(MERCURY_TESTING_TEMP_DIRECTORY "." CACHE PATH
  "Location to use for temp data (default is current directory).")
mark_as_advanced(MERCURY_TESTING_TEMP_DIRECTORY)

option(MERCURY_TESTING_CORESIDENT "Enable testing of coresident mode." OFF)
mark_as_advanced(MERCURY_TESTING_CORESIDENT)

#------------------------------------------------------------------------------
# NA protocols used for testing
# (case where the NA plugin defines multiple protocols)
#------------------------------------------------------------------------------
if(NA_USE_BMI)
  set(NA_BMI_TESTING_PROTOCOL "" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
  mark_as_advanced(NA_BMI_TESTING_PROTOCOL)
endif()

#Does not really make sense for MPI (so do not add an option for it)
#if(NA_USE_MPI)
#  set(NA_MPI_TESTING_PROTOCOL "" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
#  mark_as_advanced(NA_MPI_TESTING_PROTOCOL)
#endif()

if(NA_USE_SSM)
  set(NA_SSM_TESTING_PROTOCOL "" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
  mark_as_advanced(NA_SSM_TESTING_PROTOCOL)
endif()

#------------------------------------------------------------------------------
# Compile kwsys library and setup TestDriver
#------------------------------------------------------------------------------
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_test_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/mercury_test_config.h
)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${MERCURY_INCLUDES_BUILD_TIME}
)

if(MERCURY_ENABLE_PARALLEL_TESTING)
  find_package(MPI REQUIRED)
  if(MPI_FOUND)
    include_directories(${MPI_INCLUDE_PATH})
    set(MERCURY_TEST_EXT_LIB_DEPENDENCIES
      ${MERCURY_TEST_EXT_LIB_DEPENDENCIES}
      ${MPI_LIBRARIES}
    )
  else()
    message(FATAL_ERROR "Could not find MPI.")
  endif()
endif()

add_subdirectory(driver)

#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
#
# hg prefix is added to executable
#
function(build_mercury_test test_name)
  add_executable(hg_test_${test_name} test_${test_name}.c)
  target_link_libraries(hg_test_${test_name} mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(hg_test_${test_name})
  endif()
endfunction()

macro(add_mercury_test_comm test_name comm protocol opt)
  # Set full test name
  set(full_test_name ${test_name})
  set(opt_names ${comm} ${protocol} ${opt})
  foreach(opt_name ${opt_names})
    set(full_test_name ${full_test_name}_${opt_name})
  endforeach()

  # Set test arguments
  set(test_args --comm ${comm})
  if(protocol)
    set(test_args ${test_args} --protocol ${protocol})
  endif()
  if(opt)
    set(test_args ${test_args} --${opt})
  endif()

  # Dynamic client/server test
  add_test(NAME "mercury_${full_test_name}"
    COMMAND $<TARGET_FILE:mercury_test_driver>
    --server $<TARGET_FILE:hg_test_server>
    --client $<TARGET_FILE:hg_test_${test_name}> ${test_args}
  )

  # Static client/server test
  if(${comm} STREQUAL "mpi")
    set(static_test_name ${full_test_name}_static)
    set(static_test_args ${test_args} --static)
    add_test(NAME "mercury_${static_test_name}"
      COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} 1
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_server> ${MPIEXEC_POSTFLAGS}
      ${static_test_args} : ${MPIEXEC_NUMPROC_FLAG} ${MPIEXEC_MAX_NUMPROCS}
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${static_test_args}
    )
  endif()

  # Coresident test
  if(MERCURY_TESTING_CORESIDENT)
    set(cores_test_name ${full_test_name}_self)
    set(cores_test_args ${test_args} --self)
    if (MERCURY_ENABLE_PARALLEL_TESTING)
      add_test(NAME "mercury_${cores_test_name}"
        COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} ${MPIEXEC_MAX_NUMPROCS}
        ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${MPIEXEC_POSTFLAGS}
        ${cores_test_args}
      )
    else()
      add_test(NAME "mercury_${cores_test_name}"
        COMMAND $<TARGET_FILE:hg_test_${test_name}> ${cores_test_args}
      )
    endif()
  endif()
endmacro()

function(add_mercury_test test_name)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    if(NA_${upper_comm}_TESTING_PROTOCOL)
      foreach(protocol ${NA_${upper_comm}_TESTING_PROTOCOL})
        add_mercury_test_comm(${test_name} ${comm} ${protocol} "")
      endforeach()
    else()
      add_mercury_test_comm(${test_name} ${comm} "" "")
    endif()
  endforeach()
endfunction()

function(add_mercury_opt_test test_name opt)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    if(NA_${upper_comm}_TESTING_PROTOCOL)
      foreach(protocol ${NA_${upper_comm}_TESTING_PROTOCOL})
        add_mercury_test_comm(${test_name} ${comm} ${protocol} ${opt})
      endforeach()
    else()
      add_mercury_test_comm(${test_name} ${comm} "" ${opt})
    endif()
  endforeach()
endfunction()

#------------------------------------------------------------------------------
# NA tests
#------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/na)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/na)

#------------------------------------------------------------------------------
# UTIL tests
#------------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)

#------------------------------------------------------------------------------
# mercury_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(mercury_test STATIC mercury_test.c mercury_rpc_cb.c)
target_link_libraries(mercury_test mercury na_test ${MERCURY_TEST_EXT_LIB_DEPENDENCIES})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury_test)
endif()

#------------------------------------------------------------------------------
# Set up test
#------------------------------------------------------------------------------

# Server used for testing
build_mercury_test(server)

set(MERCURY_tests
  rpc
  bulk
  bulk_seg
#  pipeline
  perf
  overflow
)
if(NOT WIN32)
  set(MERCURY_tests ${MERCURY_tests} posix)
endif()

# Build tests and add them to ctest
foreach(MERCURY_test ${MERCURY_tests})
  build_mercury_test(${MERCURY_test})
  add_mercury_test(${MERCURY_test})
endforeach()

add_mercury_opt_test(bulk_seg "extra")
add_mercury_opt_test(bulk_seg "variable")
