#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
function(build_na_test test_name)
  add_executable(${test_name} ${test_name}.c)
  target_link_libraries(${test_name} mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(${test_name})
  endif()
endfunction()

#------------------------------------------------------------------------------
# Network abstraction test
build_na_test(client_na)
build_na_test(server_na)

if(NA_USE_SSM)
  build_na_test(client_simple_na)
  build_na_test(server_simple_na)
endif()

#------------------------------------------------------------------------------
# Set list of tests

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