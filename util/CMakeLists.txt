#-----------------------------------------------------------------------------
# Create executable
#-----------------------------------------------------------------------------
add_executable(hg_info info.c)
target_link_libraries(hg_info mercury)
mercury_set_exe_options(hg_info MERCURY)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(hg_info)
endif()

#-----------------------------------------------------------------------------
# Add Target(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  TARGETS
    hg_info
  RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
)