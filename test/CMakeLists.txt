#------------------------------------------------------------------------------
# Compile kwsys library and setup TestDriver
#------------------------------------------------------------------------------
configure_file(
  ${CMAKE_SOURCE_DIR}/CMake/shipper_test_config.h.in
  ${IOFSL_SHIPPER_BINARY_DIR}/test/shipper_test_config.h
)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(driver)

#------------------------------------------------------------------------------
# Set up test options and macros
#------------------------------------------------------------------------------
set(IOFSL_SHIPPER_comm bmi mpi)

function(add_shipper_test full_test_name server client)
  foreach(comm ${IOFSL_SHIPPER_comm})
    add_test("${full_test_name}_${comm}"
      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/shipper_test_driver
      --server ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${server}
      --client ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${client} ${comm}
    )
  endforeach(comm)
endfunction(add_shipper_test)

#------------------------------------------------------------------------------
# iofsl_shipper_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(iofsl_shipper_test STATIC
  shipper_test.c
)
target_link_libraries(iofsl_shipper_test
  iofsl_shipper_na
)

#------------------------------------------------------------------------------
# Set up test
#------------------------------------------------------------------------------
# Function shipper test
add_executable(client_fs client_fs.c)
target_link_libraries(client_fs iofsl_shipper_fs iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(client_fs)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

add_executable(server_fs server_fs.c)
target_link_libraries(server_fs iofsl_shipper_fs iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(server_fs)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Network abstraction test
add_executable(client_na client_na.c)
target_link_libraries(client_na iofsl_shipper_na iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(client_na)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

add_executable(server_na server_na.c)
target_link_libraries(server_na iofsl_shipper_na iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(server_na)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
# Bulk data shipper test
add_executable(client_bds client_bds.c)
target_link_libraries(client_bds iofsl_shipper_bds iofsl_shipper_fs iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(client_bds)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

add_executable(server_bds server_bds.c)
target_link_libraries(server_bds iofsl_shipper_bds iofsl_shipper_fs iofsl_shipper_test)
if(IOFSL_SHIPPER_ENABLE_COVERAGE)
  set_coverage_flags(server_bds)
endif(IOFSL_SHIPPER_ENABLE_COVERAGE)

#------------------------------------------------------------------------------
if(MPIEXEC)
  set(IOFSL_SHIPPER_tests
    fs
    na
    bds
  )
  foreach(IOFSL_SHIPPER_test ${IOFSL_SHIPPER_tests})
      add_shipper_test(shipper_${IOFSL_SHIPPER_test}
        server_${IOFSL_SHIPPER_test} client_${IOFSL_SHIPPER_test})
  endforeach(IOFSL_SHIPPER_test)
endif(MPIEXEC)
