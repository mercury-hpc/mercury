#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")

set(MERCURY_TESTING_MAX_LOOP "1" CACHE STRING
  "Loop n times for average bandwidth/time measures.")

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
  endforeach(comm)
endfunction(add_mercury_test)

function(add_mercury_opt_test full_test_name server client opt)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${opt}_${comm}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:${server}>
      --client $<TARGET_FILE:${client}> ${comm} ${opt}
    )
  endforeach(comm)
endfunction(add_mercury_opt_test)

function(add_mercury_static_test full_test_name server client)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${comm}_static"
      COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} 1
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:${server}>
      ${H5FDdsm_TESTING_LENGTH} ${comm} "static" : ${MPIEXEC_NUMPROC_FLAG}
      ${MPIEXEC_MAX_NUMPROCS} ${MPIEXEC_PREFLAGS} $<TARGET_FILE:${client}> ${comm} "static"
    )
  endforeach(comm)
endfunction(add_mercury_static_test)

#------------------------------------------------------------------------------
# mercury_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(mercury_test mercury_test.c)
target_link_libraries(mercury_test mercury)
set_lib_options(mercury_test "mercury_test" ${MERCURY_LIBTYPE})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury_test)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Set up test
#------------------------------------------------------------------------------
# Function shipper test
add_executable(client_rpc client_rpc.c)
target_link_libraries(client_rpc mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_rpc)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_rpc server_rpc.c)
target_link_libraries(server_rpc mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_rpc)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Network abstraction test
add_executable(client_na client_na.c)
target_link_libraries(client_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_na)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_na server_na.c)
target_link_libraries(server_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_na)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Bulk data shipper test
add_executable(client_bulk client_bulk.c)
target_link_libraries(client_bulk mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bulk)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bulk server_bulk.c)
target_link_libraries(server_bulk mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bulk)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Non-contiguous bulk data shipper test
add_executable(client_bulk_seg client_bulk_seg.c)
target_link_libraries(client_bulk_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bulk_seg)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bulk_seg server_bulk_seg.c)
target_link_libraries(server_bulk_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bulk_seg)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Bandwidth bulk data shipper test using pipelining
add_executable(client_pipeline client_pipeline.c)
target_link_libraries(client_pipeline mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_pipeline)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_pipeline server_pipeline.c)
target_link_libraries(server_pipeline mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_pipeline)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Scaling bandwidth bulk data shipper test using pipelining
add_executable(client_pipeline_scale client_pipeline_scale.c)
target_link_libraries(client_pipeline_scale mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_pipeline_scale)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_pipeline_scale server_pipeline_scale.c)
target_link_libraries(server_pipeline_scale mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_pipeline_scale)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# POSIX test
add_executable(client_posix client_posix.c)
target_link_libraries(client_posix mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_posix)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_posix server_posix.c)
target_link_libraries(server_posix mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_posix)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Set list of tests
set(MERCURY_tests
  rpc
  na
  bulk
  bulk_seg
  pipeline
  posix
)
foreach(MERCURY_test ${MERCURY_tests})
  add_mercury_test(mercury_${MERCURY_test}
    server_${MERCURY_test} client_${MERCURY_test})
endforeach(MERCURY_test)

set(MERCURY_opt_tests
  bulk_seg
)
foreach(MERCURY_test ${MERCURY_opt_tests})
  add_mercury_opt_test(mercury_${MERCURY_test} server_${MERCURY_test}
    client_${MERCURY_test} "extra")
  add_mercury_opt_test(mercury_${MERCURY_test} server_${MERCURY_test}
    client_${MERCURY_test} "variable")
endforeach(MERCURY_test)

foreach(MERCURY_test ${MERCURY_tests})
  add_mercury_static_test(mercury_${MERCURY_test}
    server_${MERCURY_test} client_${MERCURY_test})
endforeach(MERCURY_test)
