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

set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")

set(MERCURY_TESTING_MAX_LOOP "1" CACHE STRING
  "Loop n times for average bandwidth/time measures.")

#------------------------------------------------------------------------------
# Set up test options and macros
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
add_executable(client_fs client_fs.c)
target_link_libraries(client_fs mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_fs)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_fs server_fs.c)
target_link_libraries(server_fs mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_fs)
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
add_executable(client_bds client_bds.c)
target_link_libraries(client_bds mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bds)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bds server_bds.c)
target_link_libraries(server_bds mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bds)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Non-contiguous bulk data shipper test
add_executable(client_bds_seg client_bds_seg.c)
target_link_libraries(client_bds_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bds_seg)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bds_seg server_bds_seg.c)
target_link_libraries(server_bds_seg mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bds_seg)
endif(MERCURY_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Bandwidth bulk data shipper test
add_executable(client_bds_bw client_bds_bw.c)
target_link_libraries(client_bds_bw mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bds_bw)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bds_bw server_bds_bw.c)
target_link_libraries(server_bds_bw mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bds_bw)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(client_bds_bw1 client_bds_bw1.c)
target_link_libraries(client_bds_bw1 mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_bds_bw1)
endif(MERCURY_ENABLE_COVERAGE)

add_executable(server_bds_bw1 server_bds_bw1.c)
target_link_libraries(server_bds_bw1 mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_bds_bw1)
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
  fs
  na
  bds
  bds_seg
  bds_bw
  posix
)
foreach(MERCURY_test ${MERCURY_tests})
  add_mercury_test(mercury_${MERCURY_test}
    server_${MERCURY_test} client_${MERCURY_test})
endforeach(MERCURY_test)

set(MERCURY_opt_tests
  bds_seg
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
