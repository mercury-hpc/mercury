#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
#
# na prefix is added to executable
#
function(build_na_test test_name)
  add_executable(na_${test_name} ${test_name}.c)
  target_link_libraries(na_${test_name} na_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(na_${test_name})
  endif()
endfunction()

function(add_na_test full_test_name server client)
  foreach(comm ${NA_PLUGINS})
    add_test(NAME "${full_test_name}_${comm}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:na_${server}>
      --client $<TARGET_FILE:na_${client}> ${comm}
    )
  endforeach()
endfunction()

#------------------------------------------------------------------------------
# na_test : Lib used by tests contains main test initialization etc
#------------------------------------------------------------------------------
add_library(na_test STATIC na_test.c)
target_link_libraries(na_test na ${MERCURY_TEST_EXT_LIB_DEPENDENCIES})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(na_test)
endif()

#------------------------------------------------------------------------------
# Network abstraction test
build_na_test(test_client)
build_na_test(test_server)

#------------------------------------------------------------------------------
# Set list of tests

# Dynamic client / server test with all enabled NA plugins
add_na_test(na test_server test_client)
