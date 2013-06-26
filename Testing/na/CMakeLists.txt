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

# Dynamic client / server test with all enabled NA plugins
add_mercury_test(na_simple server_na client_na)

# Static client / server test with all enabled NA plugins
add_mercury_static_test(na_simple server_na client_na)
