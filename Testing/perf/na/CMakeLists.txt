#-----------------------------------------------------------------------------
# Create executables
#-----------------------------------------------------------------------------
add_library(na_perf OBJECT na_perf.c)
target_link_libraries(na_perf na_test_common)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(na_perf)
endif()

set(NA_PERF_TARGETS na_lat na_bw_put na_bw_get na_perf_server)
foreach(perf ${NA_PERF_TARGETS})
  add_executable(${perf} ${perf}.c)
  target_link_libraries(${perf} na_perf)
  set_target_properties(${perf} PROPERTIES INSTALL_RPATH ${MERCURY_INSTALL_LIB_DIR})
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(${perf})
  endif()
endforeach()

#-----------------------------------------------------------------------------
# Add Target(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  TARGETS
    ${NA_PERF_TARGETS}
  RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
)