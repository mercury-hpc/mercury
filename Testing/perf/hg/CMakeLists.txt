#-----------------------------------------------------------------------------
# Create executables
#-----------------------------------------------------------------------------
add_library(mercury_perf OBJECT mercury_perf.c)
target_link_libraries(mercury_perf mercury_test_common)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury_perf)
endif()

set(HG_PERF_TARGETS hg_rate hg_bw_read hg_bw_write hg_perf_server)
foreach(perf ${HG_PERF_TARGETS})
  add_executable(${perf} ${perf}.c)
  target_link_libraries(${perf} mercury_perf)
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
    ${HG_PERF_TARGETS}
  RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
)