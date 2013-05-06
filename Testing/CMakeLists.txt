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
# Set up test options and macros
#------------------------------------------------------------------------------
if(NA_USE_BMI)
  set(MERCURY_comm
    ${MERCURY_comm}
    bmi
  )
endif(NA_USE_BMI)

if(NA_USE_MPI)
  set(MERCURY_comm
    ${MERCURY_comm}
    mpi
  )
endif(NA_USE_MPI)

function(add_mercury_test full_test_name server client)
  foreach(comm ${MERCURY_comm})
    add_test("${full_test_name}_${comm}"
      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/mercury_test_driver
      --server ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${server}
      --client ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${client} ${comm}
    )
  endforeach(comm)
endfunction(add_mercury_test)

#------------------------------------------------------------------------------
# mercury_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(mercury_test STATIC
  mercury_test.c
)
target_link_libraries(mercury_test mercury)

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
  posix
)
foreach(MERCURY_test ${MERCURY_tests})
    add_mercury_test(shipper_${MERCURY_test}
      server_${MERCURY_test} client_${MERCURY_test})
endforeach(MERCURY_test)
