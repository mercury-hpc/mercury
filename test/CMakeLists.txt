#-----------------------------------------------
# Set up test
#-----------------------------------------------
add_executable(client client.c)
target_link_libraries(client iofsl_generic)

add_test("client" ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/client)

add_executable(server server.c)
target_link_libraries(server iofsl_na)
