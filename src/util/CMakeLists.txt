#------------------------------------------------------------------------------
# Set sources
#------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(MERCURY_UTIL_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_hash_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_list.c
)

#------------------------------------------------------------------------------
# Libraries
#------------------------------------------------------------------------------
# UTIL
add_library(mercury_util ${MERCURY_UTIL_SRCS})
set_lib_options(mercury_util "mercury_util" ${MERCURY_LIBTYPE})

#-----------------------------------------------------------------------------
# Add Target(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  TARGETS
    mercury_util
  EXPORT
    ${MERCURY_EXPORTED_TARGETS}
  LIBRARY DESTINATION ${MERCURY_INSTALL_LIB_DIR}
  ARCHIVE DESTINATION ${MERCURY_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
)
