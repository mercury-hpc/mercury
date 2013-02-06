#-----------------------------------------------
# Compile kwsys library and setup TestDriver
#-----------------------------------------------
#set(KWSYS_NAMESPACE Shipper_sys)
#set(KWSYS_USE_SystemTools 1)
#set(KWSYS_USE_Process 1)
#set(KWSYS_USE_RegularExpression 1)
#add_subdirectory(kwsys)
#include_directories(${CMAKE_CURRENT_BINARY_DIR}/kwsys)

#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ShipperTestDriverConfig.h.in
#  ${CMAKE_CURRENT_BINARY_DIR}/ShipperTestDriverConfig.h @ONLY ESCAPE_QUOTES)
#include_directories(${CMAKE_CURRENT_BINARY_DIR})

#add_executable(ShipperTestDriver
#  ${CMAKE_CURRENT_SOURCE_DIR}/ShipperTestDriver.cxx
#)
#target_link_libraries(ShipperTestDriver Shipper_sys)

#-----------------------------------------------
# Set up test options and macros
#-----------------------------------------------

#function(add_h5fd_dsm_dynamic_test full_test_name server client)
#  foreach(comm ${Shipper_dynamic_comm})
#    add_test("${full_test_name}_${comm}_dynamic"
#      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ShipperTestDriver
#      --server ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${server}
#      --client ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${client}
#      ${MPIEXEC_MAX_NUMPROCS}
#    )
#  endforeach(comm)
#endfunction(add_h5fd_dsm_dynamic_test)

#-----------------------------------------------------------------------------
# iofsl_shipper_test : Lib used by tests contains main test initialization etc
#-----------------------------------------------------------------------------
add_library(iofsl_shipper_test STATIC
  shipper_test.c
)
target_link_libraries(iofsl_shipper_test
  iofsl_shipper_fs
  iofsl_shipper_bds
)

#-----------------------------------------------
# Set up test
#-----------------------------------------------
# Function shipper test
add_executable(client_fs client_fs.c)
target_link_libraries(client_fs iofsl_shipper_fs iofsl_shipper_test)

#add_test("client" ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/client)

add_executable(server_fs server_fs.c)
target_link_libraries(server_fs iofsl_shipper_fs iofsl_shipper_test)

#-----------------------------------------------
# Network abstraction test
add_executable(client_na client_na.c)
target_link_libraries(client_na iofsl_shipper_na iofsl_shipper_test)

add_executable(server_na server_na.c)
target_link_libraries(server_na iofsl_shipper_na iofsl_shipper_test)

#-----------------------------------------------
# Bulk data shipper test
add_executable(client_bds client_bds.c)
target_link_libraries(client_bds iofsl_shipper_bds iofsl_shipper_fs iofsl_shipper_test)

add_executable(server_bds server_bds.c)
target_link_libraries(server_bds iofsl_shipper_bds iofsl_shipper_fs iofsl_shipper_test)
#-----------------------------------------------
