#------------------------------------------------------------------------------
# Mercury util tests

add_executable(test_threadpool test_threadpool.c)
target_link_libraries(test_threadpool mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(test_threadpool)
endif()

add_test(NAME threadpool COMMAND $<TARGET_FILE:test_threadpool>)

add_executable(test_checksum test_checksum.c)
target_link_libraries(test_checksum mercury_test)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(test_checksum)
endif()

set(TEST_HASH_TYPES crc16 crc64)
foreach(hash_type ${TEST_HASH_TYPES})
  add_test(NAME "checksum_${hash_type}"
    COMMAND $<TARGET_FILE:test_checksum> "${hash_type}"
  )
endforeach()
