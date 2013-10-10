#------------------------------------------------------------------------------
# Mercury util tests

add_executable(test_threadpool test_threadpool.c)
target_link_libraries(test_threadpool mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(test_threadpool)
endif()

add_test(NAME threadpool COMMAND $<TARGET_FILE:test_threadpool>)

