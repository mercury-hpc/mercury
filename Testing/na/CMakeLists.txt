#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
#
# hg_prefix is added to executable
#
function(build_na_test test_name)
  add_executable(hg_${test_name} ${test_name}.c)
  target_link_libraries(hg_${test_name} mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(hg_${test_name})
  endif()
endfunction()

#------------------------------------------------------------------------------
# Network abstraction test
build_mercury_test(client_na)
build_mercury_test(server_na)

#------------------------------------------------------------------------------
# Set list of tests

# Dynamic client / server test with all enabled NA plugins
add_mercury_test(na server_na client_na)
