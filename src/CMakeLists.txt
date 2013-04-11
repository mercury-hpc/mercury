# Create single library
option(MERCURY_CREATE_SINGLE_LIB "Create one single mercury library." OFF)

#------------------------------------------------------------------------------
# External dependencies
#------------------------------------------------------------------------------
# Boost (for preprocessor macros)
option(MERCURY_USE_BOOST_PP "Use BOOST preprocessor macros." OFF)
if(MERCURY_USE_BOOST_PP)
  find_package(Boost 1.50)
  if(Boost_FOUND)
    set(MERCURY_HAS_BOOST 1)
    include_directories(${Boost_INCLUDE_DIRS})
  else(Boost_FOUND)
    message(FATAL_ERROR "Could not find Boost, please check Boost_INCLUDE_DIR.")
  endif(Boost_FOUND)
endif(MERCURY_USE_BOOST_PP)

# XDR
option(MERCURY_USE_XDR "Use XDR for generic encoding." OFF)
if(MERCURY_USE_XDR)
  set(MERCURY_HAS_XDR 1)
endif(MERCURY_USE_XDR)

set(MERCURY_DEP_INCLUDE_DIRS ${Boost_INCLUDE_DIRS})

#------------------------------------------------------------------------------
# Internal dependencies
#------------------------------------------------------------------------------
# UTIL
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${CMAKE_CURRENT_BINARY_DIR}/util
)
if(NOT MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_EXPORTED_LIBS ${MERCURY_EXPORTED_LIBS} mercury_util)
endif(NOT MERCURY_CREATE_SINGLE_LIB)

# NA
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/na)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/na
  ${CMAKE_CURRENT_BINARY_DIR}/na
)
if(NOT MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_EXPORTED_LIBS ${MERCURY_EXPORTED_LIBS} na)
else(NOT MERCURY_CREATE_SINGLE_LIB)
  include_directories(${NA_DEP_INCLUDE_DIRS})
endif(NOT MERCURY_CREATE_SINGLE_LIB)

#------------------------------------------------------------------------------
# Configure module header files
#------------------------------------------------------------------------------
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/mercury_config.h
)

#------------------------------------------------------------------------------
# Set sources
#------------------------------------------------------------------------------
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Used by config.cmake and Testing
set(MERCURY_INCLUDES_BUILD_TIME
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/na
  ${CMAKE_CURRENT_BINARY_DIR}/na
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${NA_DEP_INCLUDE_DIRS}
  ${MERCURY_DEP_INCLUDE_DIRS}
  PARENT_SCOPE
)

set(MERCURY_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_handler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_proc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_bulk.c
)

#------------------------------------------------------------------------------
# Libraries
#------------------------------------------------------------------------------
# MERCURY
if(MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_SRCS ${MERCURY_SRCS} ${MERCURY_UTIL_SRCS} ${NA_SRCS})
  set(MERCURY_EXT_DEPENCIES ${NA_DEP_LIBRARIES})
endif(MERCURY_CREATE_SINGLE_LIB)

add_library(mercury ${MERCURY_SRCS})
target_link_libraries(mercury ${MERCURY_EXPORTED_LIBS} ${MERCURY_EXT_DEPENCIES})
set_lib_options(mercury "mercury" ${MERCURY_LIBTYPE})

set(MERCURY_EXPORTED_LIBS ${MERCURY_EXPORTED_LIBS} mercury)

#-----------------------------------------------------------------------------
# Specify project header files to be installed
#-----------------------------------------------------------------------------
set(MERCURY_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_handler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_proc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_bulk.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_macros.h
  ${CMAKE_CURRENT_BINARY_DIR}/mercury_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/iofsl_compat.h
)

#-----------------------------------------------------------------------------
# Add file(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  FILES
    ${MERCURY_HEADERS}
  DESTINATION
    ${MERCURY_INSTALL_INCLUDE_DIR}
  COMPONENT
    headers
)

#-----------------------------------------------------------------------------
# Add Target(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  TARGETS
    mercury
  EXPORT
    ${MERCURY_EXPORTED_TARGETS}
  LIBRARY DESTINATION ${MERCURY_INSTALL_LIB_DIR}
  ARCHIVE DESTINATION ${MERCURY_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
)

#-----------------------------------------------------------------------------
# Add Target(s) to CMake Install for import into other projects
#-----------------------------------------------------------------------------
install(
  EXPORT
    ${MERCURY_EXPORTED_TARGETS}
  DESTINATION
    ${MERCURY_INSTALL_DATA_DIR}/cmake/mercury
  FILE
    ${MERCURY_EXPORTED_TARGETS}.cmake
)

#-----------------------------------------------------------------------------
# Export all exported targets to the build tree for use by parent project
#-----------------------------------------------------------------------------
if(NOT MERCURY_EXTERNALLY_CONFIGURED)
EXPORT (
  TARGETS
    ${MERCURY_EXPORTED_LIBS}
  FILE
    ${MERCURY_EXPORTED_TARGETS}.cmake
)
endif(NOT MERCURY_EXTERNALLY_CONFIGURED)
