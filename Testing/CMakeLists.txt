#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")

set(MERCURY_TESTING_MAX_LOOP "1" CACHE STRING
  "Loop n times for average bandwidth/time measures.")

set(MERCURY_TESTING_NUM_THREADS "8" CACHE STRING
  "Number of server threads used for testing.")

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
function(build_mercury_test test_name)
  add_executable(${test_name} ${test_name}.c)
  target_link_libraries(${test_name} mercury_test mercury)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(${test_name})
  endif()
endfunction()

function(add_mercury_test full_test_name server client)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${comm}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:${server}>
      --client $<TARGET_FILE:${client}> ${comm}
    )
  endforeach()
endfunction()

function(add_mercury_opt_test full_test_name server client opt)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${opt}_${comm}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:${server}>
      --client $<TARGET_FILE:${client}> ${comm} ${opt}
    )
  endforeach()
endfunction()

function(add_mercury_static_test full_test_name server client)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${comm}_static"
      COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} 1
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:${server}>
      ${H5FDdsm_TESTING_LENGTH} ${comm} "static" : ${MPIEXEC_NUMPROC_FLAG}
      ${MPIEXEC_MAX_NUMPROCS} ${MPIEXEC_PREFLAGS} $<TARGET_FILE:${client}> ${comm} "static"
    )
  endforeach()
endfunction()

#------------------------------------------------------------------------------
# mercury_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(mercury_test STATIC mercury_test.c)
target_link_libraries(mercury_test na ${MERCURY_TEST_EXT_LIB_DEPENDENCIES})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury_test)
endif()

#------------------------------------------------------------------------------
# NA tests
#------------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/na)

#------------------------------------------------------------------------------
# UTIL tests
#------------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)

#------------------------------------------------------------------------------
# Set up test
#------------------------------------------------------------------------------
# Function shipper test
build_mercury_test(client_rpc)
build_mercury_test(server_rpc)

#------------------------------------------------------------------------------
# Bulk data shipper test
build_mercury_test(client_bulk)
build_mercury_test(server_bulk)

#------------------------------------------------------------------------------
# Non-contiguous bulk data shipper test
build_mercury_test(client_bulk_seg)
build_mercury_test(server_bulk_seg)

#------------------------------------------------------------------------------
# Bandwidth bulk data shipper test using pipelining
build_mercury_test(client_pipeline)
build_mercury_test(server_pipeline)

#------------------------------------------------------------------------------
# Scaling bandwidth bulk data shipper test using pipelining
build_mercury_test(client_scale)
build_mercury_test(server_scale)
if(NA_USE_MPI)
  build_mercury_test(client_pipeline_scale)
  build_mercury_test(server_pipeline_scale)
endif()

#------------------------------------------------------------------------------
# Multiple client/server test
build_mercury_test(client_multiple)
build_mercury_test(server_multiple)

#------------------------------------------------------------------------------
# POSIX test
if(NOT WIN32)
  build_mercury_test(client_posix)
  build_mercury_test(server_posix)
endif()

#------------------------------------------------------------------------------
# Set list of tests
set(MERCURY_tests
  rpc
  bulk
  bulk_seg
  pipeline
  scale
)

if(NOT WIN32)
  set(MERCURY_tests ${MERCURY_tests} posix)
endif()

foreach(MERCURY_test ${MERCURY_tests})
  add_mercury_test(mercury_${MERCURY_test}
    server_${MERCURY_test} client_${MERCURY_test})
endforeach()

set(MERCURY_opt_tests
  bulk_seg
)
foreach(MERCURY_test ${MERCURY_opt_tests})
  add_mercury_opt_test(mercury_${MERCURY_test} server_${MERCURY_test}
    client_${MERCURY_test} "extra")
  add_mercury_opt_test(mercury_${MERCURY_test} server_${MERCURY_test}
    client_${MERCURY_test} "variable")
endforeach()

#if(NA_USE_MPI)
#  foreach(MERCURY_test ${MERCURY_tests})
#    add_mercury_static_test(mercury_${MERCURY_test}
#      server_${MERCURY_test} client_${MERCURY_test})
#  endforeach()
#endif()
