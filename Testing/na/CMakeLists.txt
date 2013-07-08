#------------------------------------------------------------------------------
# Network abstraction test

add_executable(client_na client_na.c)
target_link_libraries(client_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_na)
endif()

add_executable(server_na server_na.c)
target_link_libraries(server_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_na)
endif()

add_executable(client_simple_na client_simple_na.c)
target_link_libraries(client_simple_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(client_simple_na)
endif()

add_executable(server_simple_na server_simple_na.c)
target_link_libraries(server_simple_na mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(server_simple_na)
endif()

# Dynamic client / server test with all enabled NA plugins
add_mercury_test(na_simple server_na client_na server_simple_na
		client_simple_na)

# Static client / server test with all enabled NA plugins
add_mercury_static_test(na_simple server_na client_na server_simple_na)
add_mercury_static_test(na_simple_ssm server_simple_na client_simple_na)

