cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

# Setup cmake policies.
foreach(p
    CMP0012
    CMP0013
    CMP0014
    CMP0022 # CMake 2.8.12
    CMP0025 # CMake 3.0
    CMP0053 # CMake 3.1
    CMP0054 # CMake 3.1
  )
  if(POLICY ${p})
    cmake_policy(SET ${p} NEW)
  endif()
endforeach()

# Set a consistent MACOSX_RPATH default across all CMake versions.
# When CMake 2.8.12 is required, change this default to 1.
# When CMake 3.0.0 is required, remove this block (see CMP0042).
if(NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH 0)
endif()

project(MERCURY C)

#------------------------------------------------------------------------------
# Version information 
#------------------------------------------------------------------------------
set(MERCURY_VERSION_MAJOR "0")
set(MERCURY_VERSION_MINOR "9")
set(MERCURY_VERSION_PATCH "1")
set(MERCURY_PACKAGE "mercury")
set(MERCURY_PACKAGE_NAME "MERCURY")
set(MERCURY_PACKAGE_VERSION "${MERCURY_VERSION_MAJOR}.${MERCURY_VERSION_MINOR}.${MERCURY_VERSION_PATCH}")
set(MERCURY_PACKAGE_VERSION_MAJOR "${MERCURY_VERSION_MAJOR}.${MERCURY_VERSION_MINOR}")
set(MERCURY_PACKAGE_VERSION_MINOR "${MERCURY_VERSION_PATCH}")
set(MERCURY_PACKAGE_STRING "${MERCURY_PACKAGE_NAME} ${MERCURY_PACKAGE_VERSION}")
set(MERCURY_PACKAGE_TARNAME "${MERCURY_PACKAGE}")

#------------------------------------------------------------------------------
# Setup install and output Directories
#------------------------------------------------------------------------------
if(NOT MERCURY_INSTALL_BIN_DIR)
  set(MERCURY_INSTALL_BIN_DIR ${CMAKE_INSTALL_PREFIX}/bin)
else()
  set(NA_INSTALL_BIN_DIR ${MERCURY_INSTALL_BIN_DIR})
endif()
if(NOT MERCURY_INSTALL_LIB_DIR)
  set(MERCURY_INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
else()
  set(NA_INSTALL_LIB_DIR ${MERCURY_INSTALL_LIB_DIR})
endif()
if(NOT MERCURY_INSTALL_INCLUDE_DIR)
  # Interface include will default to prefix/include
  set(MERCURY_INSTALL_INTERFACE include)
  set(MERCURY_INSTALL_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include)
else()
  set(MERCURY_INSTALL_INTERFACE ${MERCURY_INSTALL_INCLUDE_DIR})
  set(NA_INSTALL_INCLUDE_DIR ${MERCURY_INSTALL_INCLUDE_DIR})
endif()
if(NOT MERCURY_INSTALL_DATA_DIR)
  set(MERCURY_INSTALL_DATA_DIR ${CMAKE_INSTALL_PREFIX}/share)
else()
  set(NA_INSTALL_DATA_DIR ${MERCURY_INSTALL_DATA_DIR})
endif()

# Setting this ensures that "make install" will leave rpaths to external
# libraries intact on "make install". This ensures that one can install a
# version of Mercury on the build machine without any issues. If this not
# desired, simply specify CMAKE_INSTALL_RPATH_USE_LINK_PATH when configuring
# Mercury and "make install" will strip all rpaths, which is default behavior.
if(NOT CMAKE_INSTALL_RPATH_USE_LINK_PATH)
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()

#------------------------------------------------------------------------------
# Setup CMake Environment
#------------------------------------------------------------------------------
if(APPLE)
  # We are doing a unix-style install i.e. everything will be installed in
  # CMAKE_INSTALL_PREFIX/bin and CMAKE_INSTALL_PREFIX/lib etc. as on other unix
  # platforms. We still need to setup CMAKE_INSTALL_NAME_DIR correctly so that
  # the binaries point to appropriate location for the libraries.

  # 1. Make CMAKE_INSTALL_PREFIX publicly accessible, if it was hidden in
  #    previous pass
  get_property(is_internal CACHE CMAKE_INSTALL_PREFIX PROPERTY TYPE)
  if(is_internal STREQUAL "INTERNAL")
    set(CMAKE_INSTALL_PREFIX ${CACHED_CMAKE_INSTALL_PREFIX} CACHE PATH "Install prefix" FORCE)
  else()
    set(CMAKE_INSTALL_PREFIX ${CACHED_CMAKE_INSTALL_PREFIX} CACHE PATH "Install prefix")
  endif()
  unset(MACOSX_APP_INSTALL_PREFIX CACHE)

  set(CMAKE_INSTALL_NAME_DIR "@rpath")
  mark_as_advanced(
    CMAKE_OSX_ARCHITECTURES
    CMAKE_OSX_DEPLOYMENT_TARGET
    CMAKE_OSX_SYSROOT
    )
endif()

#------------------------------------------------------------------------------
if(NOT MERCURY_EXTERNALLY_CONFIGURED)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
      ${PROJECT_BINARY_DIR}/bin CACHE PATH "Single Directory for all Executables."
  )
  set(EXECUTABLE_OUTPUT_PATH ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
      ${PROJECT_BINARY_DIR}/bin CACHE PATH "Single Directory for all Libraries"
  )
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
      ${PROJECT_BINARY_DIR}/bin CACHE PATH "Single Directory for all static libraries."
  )
endif()
set(MERCURY_CMAKE_DIR "${MERCURY_SOURCE_DIR}/CMake")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MERCURY_CMAKE_DIR})

#------------------------------------------------------------------------------
# Disallow in-source build
#------------------------------------------------------------------------------
if("${MERCURY_SOURCE_DIR}" STREQUAL "${MERCURY_BINARY_DIR}")
  message(FATAL_ERROR
    "Mercury requires an out of source Build. "
    "Please create a separate binary directory and run CMake there.")
endif()

#------------------------------------------------------------------------------
# Set a default build type if none was specified
#------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

if(NOT CMAKE_C_FLAGS AND CMAKE_COMPILER_IS_GNUCC)
  message(STATUS "GCC detected, setting additional flags")
  set(CMAKE_C_FLAGS "-Wall -Wextra -Winline -Wcast-qual -std=gnu99 -Wshadow" CACHE STRING "Flags used by the compiler during all build types." FORCE)
endif()

#-----------------------------------------------------------------------------
# Targets built within this project are exported at Install time for use
# by other projects.
#-----------------------------------------------------------------------------
if(NOT MERCURY_EXPORTED_TARGETS)
  set(MERCURY_EXPORTED_TARGETS "mercury-targets")
endif()

#------------------------------------------------------------------------------
# Choose static or shared libraries.
#------------------------------------------------------------------------------
option(BUILD_SHARED_LIBS "Build with shared libraries." OFF)
if(BUILD_SHARED_LIBS)
  set(HG_BUILD_SHARED_LIBS 1)
  set(MERCURY_LIBTYPE SHARED)
else()
  set(HG_BUILD_SHARED_LIBS 0)
  set(MERCURY_LIBTYPE STATIC)
endif()

#------------------------------------------------------------------------------
# Enable verbose error.
#------------------------------------------------------------------------------
option(MERCURY_ENABLE_VERBOSE_ERROR "Print error messages to stderr." ON)
if(MERCURY_ENABLE_VERBOSE_ERROR)
  set(HG_HAS_VERBOSE_ERROR 1)
else()
  set(HG_HAS_VERBOSE_ERROR 0)
endif()

#-------------------------------------------------------------------------------
function(mercury_set_lib_options libtarget libname libtype)
  if(${libtype} MATCHES "SHARED")
    if(WIN32 AND NOT MINGW)
      set(LIB_RELEASE_NAME "${libname}")
      set(LIB_DEBUG_NAME "${libname}_D")
      set(LIB_VERSION ${MERCURY_PACKAGE_VERSION_MAJOR})
    else()
      set(LIB_RELEASE_NAME "${libname}")
      set(LIB_DEBUG_NAME "${libname}_debug")
      set(LIB_VERSION ${MERCURY_PACKAGE_VERSION})
    endif()
  else()
    if(WIN32 AND NOT MINGW)
      set(LIB_RELEASE_NAME "lib${libname}")
      set(LIB_DEBUG_NAME "lib${libname}_D")
    else()
      # if the generator supports configuration types or if the CMAKE_BUILD_TYPE has a value
      if(CMAKE_CONFIGURATION_TYPES OR CMAKE_BUILD_TYPE)
        set(LIB_RELEASE_NAME "${libname}")
        set(LIB_DEBUG_NAME "${libname}_debug")
      else()
        set(LIB_RELEASE_NAME "lib${libname}")
        set(LIB_DEBUG_NAME "lib${libname}_debug")
      endif()
    endif()
  endif()

  set_target_properties(${libtarget}
      PROPERTIES
      DEBUG_OUTPUT_NAME          ${LIB_DEBUG_NAME}
      RELEASE_OUTPUT_NAME        ${LIB_RELEASE_NAME}
      MINSIZEREL_OUTPUT_NAME     ${LIB_RELEASE_NAME}
      RELWITHDEBINFO_OUTPUT_NAME ${LIB_RELEASE_NAME}
      VERSION                    ${LIB_VERSION}
      SOVERSION                  ${LIB_VERSION}
  )

  #----- Use MSVC Naming conventions for Shared Libraries
  if(MINGW AND ${libtype} MATCHES "SHARED")
    set_target_properties(${libtarget}
        PROPERTIES
        IMPORT_SUFFIX ".lib"
        IMPORT_PREFIX ""
        PREFIX ""
    )
  endif()
endfunction()

# Avoid explicitly including system include paths
set(MERCURY_SYSTEM_INCLUDE_PATH ${CMAKE_SYSTEM_INCLUDE_PATH}
  ${CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES})

#-----------------------------------------------------------------------------
# Coverage
#-----------------------------------------------------------------------------
if(NOT MERCURY_EXTERNALLY_CONFIGURED)
  option(MERCURY_ENABLE_COVERAGE "Enable coverage." OFF)
  if(MERCURY_ENABLE_COVERAGE)
    set(COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage" CACHE STRING
      "Flags to the coverage program that CTest uses to perform coverage inspection"
    )
    mark_as_advanced(COVERAGE_FLAGS)
  endif()

  macro(set_coverage_flags target)
    set_target_properties(${target}
      PROPERTIES
        COMPILE_FLAGS ${COVERAGE_FLAGS}
        LINK_FLAGS ${COVERAGE_FLAGS}
    )
  endmacro()
endif()

#-----------------------------------------------------------------------------
# Source
#-----------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/src)

#-----------------------------------------------------------------------------
# Build doxygen documentation.
#-----------------------------------------------------------------------------
option(BUILD_DOCUMENTATION "Build documentation." OFF)
if(BUILD_DOCUMENTATION)
  add_subdirectory(Documentation/Doxygen)
endif()

#-----------------------------------------------------------------------------
# Examples
#-----------------------------------------------------------------------------
option(BUILD_EXAMPLES "Build examples." OFF)
if(BUILD_EXAMPLES)
  # BuildExamples.cmake builds the examples as a separate project. This ensures
  # that examples can be built by themselves as well as avoiding pollution of
  # the target space with targets (and other things) from examples.
  include(${CMAKE_CURRENT_SOURCE_DIR}/Examples/BuildExamples.cmake)
endif()

#-----------------------------------------------------------------------------
# Testing
#-----------------------------------------------------------------------------
option(BUILD_TESTING "Build testing." OFF)
if(NOT MERCURY_EXTERNALLY_CONFIGURED AND BUILD_TESTING)
  enable_testing()
  include(CTest)
  add_subdirectory(Testing)
endif()

#-----------------------------------------------------------------------------
# Configure the config.cmake file for the build directory
#-----------------------------------------------------------------------------
configure_file(
  ${MERCURY_SOURCE_DIR}/CMake/mercury-config.cmake.build.in
  ${MERCURY_BINARY_DIR}/mercury-config.cmake @ONLY
)

#-----------------------------------------------------------------------------
# Configure the config.cmake file for the install directory
#-----------------------------------------------------------------------------
configure_file(
  ${MERCURY_SOURCE_DIR}/CMake/mercury-config.cmake.install.in
  ${MERCURY_BINARY_DIR}/CMakeFiles/mercury-config.cmake @ONLY
)

install(
  FILES
    ${MERCURY_BINARY_DIR}/CMakeFiles/mercury-config.cmake
  DESTINATION
    ${MERCURY_INSTALL_DATA_DIR}/cmake/mercury
)

#-----------------------------------------------------------------------------
# Configure the mercury-config-version .cmake file for the install directory
#-----------------------------------------------------------------------------
configure_file(
  ${MERCURY_SOURCE_DIR}/CMake/mercury-config-version.cmake.in
  ${MERCURY_BINARY_DIR}/CMakeFiles/mercury-config-version.cmake @ONLY
)

install(
  FILES
    ${MERCURY_BINARY_DIR}/CMakeFiles/mercury-config-version.cmake
  DESTINATION
    ${MERCURY_INSTALL_DATA_DIR}/cmake/mercury
)

#-----------------------------------------------------------------------------
# For automake compatibility, also provide a pkgconfig file
#-----------------------------------------------------------------------------
if(NOT WIN32)
  configure_file(
    ${MERCURY_SOURCE_DIR}/CMake/mercury.pc.in
    ${MERCURY_BINARY_DIR}/CMakeFiles/mercury.pc @ONLY
  )

  install(
    FILES
      ${MERCURY_BINARY_DIR}/CMakeFiles/mercury.pc
    DESTINATION
      ${MERCURY_INSTALL_LIB_DIR}/pkgconfig
  )
endif()

#-----------------------------------------------------------------------------
# CPack
#-----------------------------------------------------------------------------
if(NOT MERCURY_EXTERNALLY_CONFIGURED)
  set(CPACK_PACKAGE_DESCRIPTION_FILE ${MERCURY_SOURCE_DIR}/README.md)
  set(CPACK_RESOURCE_FILE_LICENSE ${MERCURY_SOURCE_DIR}/COPYING)
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RPC for High-Performance Computing")
  set(CPACK_PACKAGE_NAME "Mercury")
  set(CPACK_PACKAGE_VENDOR "Argonne National Laboratory / The HDF Group")
  set(CPACK_PACKAGE_VERSION_MAJOR ${MERCURY_VERSION_MAJOR})
  set(CPACK_PACKAGE_VERSION_MINOR ${MERCURY_VERSION_MINOR})
  set(CPACK_PACKAGE_VERSION_PATCH ${MERCURY_VERSION_PATCH})
  set(CPACK_GENERATOR "TBZ2")
  set(CPACK_SOURCE_PACKAGE_FILE_NAME ${MERCURY_PACKAGE_TARNAME}-${MERCURY_PACKAGE_VERSION})
  set(CPACK_SOURCE_IGNORE_FILES ".git*;/GitSetup/;/.git/;.swp$;.#;/#;.*~")
  set(CPACK_SOURCE_STRIP_FILES "")
  include(CPack)
endif()
