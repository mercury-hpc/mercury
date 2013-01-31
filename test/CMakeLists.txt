#-----------------------------------------------
# Set up test
#-----------------------------------------------
# Function shipper test
add_executable(client_fs client_fs.c)
target_link_libraries(client_fs iofsl_shipper_fs)

#add_test("client" ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/client)

add_executable(server_fs server_fs.c)
target_link_libraries(server_fs iofsl_shipper_fs)

#-----------------------------------------------
# Network abstraction test
add_executable(client_na client_na.c)
target_link_libraries(client_na iofsl_shipper_na)

add_executable(server_na server_na.c)
target_link_libraries(server_na iofsl_shipper_na)

#-----------------------------------------------
# Bulk data shipper test
add_executable(client_bds client_bds.c)
target_link_libraries(client_bds iofsl_shipper_bds iofsl_shipper_fs)

add_executable(server_bds server_bds.c)
target_link_libraries(server_bds iofsl_shipper_bds iofsl_shipper_fs)
#-----------------------------------------------
