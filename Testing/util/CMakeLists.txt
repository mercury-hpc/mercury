#------------------------------------------------------------------------------
# Mercury util tests
#------------------------------------------------------------------------------
#
# hg_prefix is added to executable
#
function(add_mercury_test_util test_name)
  add_executable(hg_test_${test_name} test_${test_name}.c)
  target_link_libraries(hg_test_${test_name} mercury_util)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(hg_test_${test_name})
  endif()
  add_test(NAME mercury_util_${test_name} COMMAND $<TARGET_FILE:hg_test_${test_name}>)
endfunction()

#------------------------------------------------------------------------------
# Set list of tests
set(MERCURY_util_tests
  atomic
  atomic_queue
  hash_table
  list
  mem_pool
  poll
  queue
  request
  thread
  thread_condition
  thread_mutex
  thread_spin
  threadpool
  time
)

foreach(test_name ${MERCURY_util_tests})
  add_mercury_test_util(${test_name})
endforeach()
