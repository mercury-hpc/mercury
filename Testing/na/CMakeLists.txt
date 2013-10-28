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

if(NA_USE_SSM)
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
endif()

# Dynamic client / server test with all enabled NA plugins
add_mercury_test(na server_na client_na)
if(NA_USE_SSM)
  add_mercury_test(simple_na server_simple_na client_simple_na)
endif()

# Static client / server test with all enabled NA plugins
#if(NA_USE_MPI)
#  add_mercury_static_test(na server_na client_na)
#  if(NA_USE_SSM)
#    add_mercury_static_test(simple_na server_simple_na client_simple_na)
#  endif()
#endif()