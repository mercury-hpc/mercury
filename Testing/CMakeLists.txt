#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")

set(MERCURY_TESTING_MAX_LOOP "1" CACHE STRING
  "Loop n times for average bandwidth/time measures.")

set(MERCURY_TESTING_NUM_THREADS "8" CACHE STRING
  "Number of server threads used for testing.")

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

add_subdirectory(driver)

#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
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
target_link_libraries(mercury_test mercury)
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
add_executable(client_rpc client_rpc.c)
target_link_libraries(client_rpc mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_rpc)
endif()

add_executable(server_rpc server_rpc.c)
target_link_libraries(server_rpc mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_rpc)
endif()

#------------------------------------------------------------------------------
# Bulk data shipper test
add_executable(client_bulk client_bulk.c)
target_link_libraries(client_bulk mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bulk)
endif()

add_executable(server_bulk server_bulk.c)
target_link_libraries(server_bulk mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bulk)
endif()

#------------------------------------------------------------------------------
# Non-contiguous bulk data shipper test
add_executable(client_bulk_seg client_bulk_seg.c)
target_link_libraries(client_bulk_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bulk_seg)
endif()

add_executable(server_bulk_seg server_bulk_seg.c)
target_link_libraries(server_bulk_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bulk_seg)
endif()

#------------------------------------------------------------------------------
# Bandwidth bulk data shipper test using pipelining
add_executable(client_pipeline client_pipeline.c)
target_link_libraries(client_pipeline mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_pipeline)
endif()

add_executable(server_pipeline server_pipeline.c)
target_link_libraries(server_pipeline mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_pipeline)
endif()

#------------------------------------------------------------------------------
# Scaling bandwidth bulk data shipper test using pipelining
if(NA_USE_MPI)
  add_executable(client_scale client_scale.c)
  target_link_libraries(client_scale mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(client_scale)
  endif()

  add_executable(server_scale server_scale.c)
  target_link_libraries(server_scale mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(server_scale)
  endif()

  add_executable(client_pipeline_scale client_pipeline_scale.c)
  target_link_libraries(client_pipeline_scale mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(client_pipeline_scale)
  endif()

  add_executable(server_pipeline_scale server_pipeline_scale.c)
  target_link_libraries(server_pipeline_scale mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(server_pipeline_scale)
  endif()
endif()

#------------------------------------------------------------------------------
# POSIX test
if(NOT WIN32)
  add_executable(client_posix client_posix.c)
  target_link_libraries(client_posix mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(client_posix)
  endif()

  add_executable(server_posix server_posix.c)
  target_link_libraries(server_posix mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(server_posix)
  endif()
endif()

#------------------------------------------------------------------------------
# Set list of tests
set(MERCURY_tests
  rpc
  bulk
  bulk_seg
  pipeline
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

if(NA_USE_MPI)
  foreach(MERCURY_test ${MERCURY_tests})
    add_mercury_static_test(mercury_${MERCURY_test}
      server_${MERCURY_test} client_${MERCURY_test})
  endforeach()
endif()
