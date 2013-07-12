# Create single library
option(MERCURY_CREATE_SINGLE_LIB "Create one single mercury library." OFF)

#------------------------------------------------------------------------------
# TODO We probably want to do that at some point
# Check headers / symbols / sizes
#------------------------------------------------------------------------------
#include(CheckTypeSize)
#check_type_size(size_t SIZEOF_SIZE_T)
#check_type_size(int64_t SIZEOF_INT64_T)
#check_type_size(uint8_t SIZEOF_UINT8_T)

#include(CheckIncludeFile)
#check_include_file("execinfo.h" HAVE_EXECINFO_H)

#include(CheckLibraryExists)
#check_library_exists(glib-2.0 g_atomic_int_set "" HAVE_GLIB)

#------------------------------------------------------------------------------
# External dependencies
#------------------------------------------------------------------------------
# Boost (for preprocessor macros)
option(MERCURY_USE_BOOST_PP "Use BOOST preprocessor macros." OFF)
if(MERCURY_USE_BOOST_PP)
  find_package(Boost 1.48.0 REQUIRED)
  if(Boost_FOUND)
    set(HG_HAS_BOOST 1)
    include_directories(${Boost_INCLUDE_DIRS})
  else()
    message(FATAL_ERROR "Could not find Boost, please check Boost_INCLUDE_DIR.")
  endif()
endif()

# XDR
option(MERCURY_USE_XDR "Use XDR for generic encoding." OFF)
if(MERCURY_USE_XDR)
  set(HG_HAS_XDR 1)
endif()

set(MERCURY_EXT_INCLUDE_DEPENDENCIES
  ${MERCURY_EXT_INCLUDE_DEPENDENCIES}
  ${Boost_INCLUDE_DIRS}
  )

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
  set(MERCURY_EXPORTED_LIBS mercury_util ${MERCURY_EXPORTED_LIBS})
endif()

# NA
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/na)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/na
  ${CMAKE_CURRENT_BINARY_DIR}/na
)
set(MERCURY_EXT_INCLUDE_DEPENDENCIES
  ${MERCURY_EXT_INCLUDE_DEPENDENCIES}
  ${NA_EXT_INCLUDE_DEPENDENCIES}
  )
if(NOT MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_EXPORTED_LIBS na ${MERCURY_EXPORTED_LIBS})
else()
  include_directories(${NA_EXT_INCLUDE_DEPENDENCIES})
endif()


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

set(MERCURY_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_handler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_proc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_bulk.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_context.c
)

#------------------------------------------------------------------------------
# Libraries
#------------------------------------------------------------------------------
# MERCURY
if(MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_SRCS ${MERCURY_SRCS} ${MERCURY_UTIL_SRCS} ${NA_SRCS})
  set(MERCURY_EXT_LIB_DEPENDENCIES
    ${MERCURY_EXT_LIB_DEPENDENCIES}
    ${NA_EXT_LIB_DEPENDENCIES}
    ${MERCURY_UTIL_EXT_LIB_DEPENDENCIES}
  )
endif()

add_library(mercury ${MERCURY_SRCS})
target_link_libraries(mercury ${MERCURY_EXPORTED_LIBS} ${MERCURY_EXT_LIB_DEPENDENCIES})
set_lib_options(mercury "mercury" ${MERCURY_LIBTYPE})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury)
endif()

set(MERCURY_EXPORTED_LIBS mercury ${MERCURY_EXPORTED_LIBS})

#-----------------------------------------------------------------------------
# Specify project header files to be installed
#-----------------------------------------------------------------------------
set(MERCURY_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_handler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_proc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_bulk.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_context.h
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_types.h
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
endif()

#------------------------------------------------------------------------------
# Set variables for parent scope
#------------------------------------------------------------------------------
set(NA_PLUGINS ${NA_PLUGINS} PARENT_SCOPE)

# Used by config.cmake.build.in and Testing
set(MERCURY_INCLUDES_BUILD_TIME
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/na
  ${CMAKE_CURRENT_BINARY_DIR}/na
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${CMAKE_CURRENT_BINARY_DIR}/util
  ${MERCURY_EXT_INCLUDE_DEPENDENCIES}
  PARENT_SCOPE
)

# Used by config.cmake.install.in
set(MERCURY_INCLUDES_INSTALL_TIME
  ${MERCURY_INSTALL_INCLUDE_DIR}
  ${MERCURY_EXT_INCLUDE_DEPENDENCIES}
  PARENT_SCOPE
)

# Pkg-config configuration
string(TOLOWER ${CMAKE_BUILD_TYPE} lower_cmake_build_type)

foreach(exported_lib ${MERCURY_EXPORTED_LIBS})
  if(lower_cmake_build_type MATCHES "debug")
    get_target_property(MERCURY_LIBRARY ${exported_lib} DEBUG_OUTPUT_NAME)
  else()
    get_target_property(MERCURY_LIBRARY ${exported_lib} RELEASE_OUTPUT_NAME)
  endif()
  set(MERCURY_LIBRARIES "${MERCURY_LIBRARIES} -l${MERCURY_LIBRARY}")
endforeach()
set(MERCURY_LIBRARIES ${MERCURY_LIBRARIES} PARENT_SCOPE)

if(NOT MERCURY_EXT_LIB_DEPENDENCIES)
  set(MERCURY_EXT_LIB_DEPENDENCIES
    ${NA_EXT_LIB_DEPENDENCIES}
    ${MERCURY_UTIL_EXT_LIB_DEPENDENCIES}
  )
endif()

foreach(lib_dep ${MERCURY_EXT_LIB_DEPENDENCIES})
  set(MERCURY_LIB_DEPENDENCIES "${MERCURY_LIB_DEPENDENCIES} ${lib_dep}")
endforeach()
set(MERCURY_LIB_DEPENDENCIES ${MERCURY_LIB_DEPENDENCIES} PARENT_SCOPE)

foreach(inc_dep ${MERCURY_EXT_INCLUDE_DEPENDENCIES})
  set(MERCURY_INCLUDE_DEPENDENCIES "${MERCURY_INCLUDE_DEPENDENCIES} -I${inc_dep}")
endforeach()
set(MERCURY_INCLUDE_DEPENDENCIES ${MERCURY_INCLUDE_DEPENDENCIES} PARENT_SCOPE)
