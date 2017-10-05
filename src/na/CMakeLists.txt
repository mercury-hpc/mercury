cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(NA C)

#------------------------------------------------------------------------------
# Setup install directories and cmake module
#------------------------------------------------------------------------------
if(NOT NA_INSTALL_BIN_DIR)
  set(NA_INSTALL_BIN_DIR ${CMAKE_INSTALL_PREFIX}/bin)
endif()
if(NOT NA_INSTALL_LIB_DIR)
  set(NA_INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()
if(NOT NA_INSTALL_INCLUDE_DIR)
  # Interface include will default to prefix/include
  set(NA_INSTALL_INCLUDE_INTERFACE include)
  set(NA_INSTALL_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include)
else()
  set(NA_INSTALL_INCLUDE_INTERFACE ${NA_INSTALL_INCLUDE_DIR})
endif()
if(NOT NA_INSTALL_DATA_DIR)
  set(NA_INSTALL_DATA_DIR ${CMAKE_INSTALL_PREFIX}/share)
endif()

#------------------------------------------------------------------------------
# Setup cmake module
#------------------------------------------------------------------------------
set(NA_CMAKE_DIR "${NA_SOURCE_DIR}/CMake")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${NA_CMAKE_DIR})

#-----------------------------------------------------------------------------
# Targets built within this project are exported at Install time for use
# by other projects.
#-----------------------------------------------------------------------------
if(NOT NA_EXPORTED_TARGETS)
  set(NA_EXPORTED_TARGETS "mercury-targets")
endif()

#------------------------------------------------------------------------------
# Include source and build directories
#------------------------------------------------------------------------------
set(NA_BUILD_INCLUDE_DEPENDENCIES
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

#------------------------------------------------------------------------------
# Internal dependencies
#------------------------------------------------------------------------------
# UTIL
#include_directories(${MERCURY_UTIL_EXT_INCLUDE_DEPENDENCIES})

# Multi progress
option(NA_ALLOW_MULTI_PROGRESS "Allow concurrent progress on single context." ON)
if(NA_ALLOW_MULTI_PROGRESS)
  set(NA_HAS_MULTI_PROGRESS 1)
endif()
mark_as_advanced(NA_ALLOW_MULTI_PROGRESS)

#------------------------------------------------------------------------------
# External dependencies / NA plugins
#------------------------------------------------------------------------------
include(CheckIncludeFiles)

# BMI
option(NA_USE_BMI "Use BMI." OFF)
if(NA_USE_BMI)
  find_package(BMI REQUIRED)
  if(BMI_FOUND)
    message(STATUS "BMI include directory: ${BMI_INCLUDE_DIR}")
    set(NA_PLUGINS ${NA_PLUGINS} bmi)
    set(NA_HAS_BMI 1)
    set(NA_INT_INCLUDE_DEPENDENCIES
      ${NA_INT_INCLUDE_DEPENDENCIES}
      ${BMI_INCLUDE_DIR}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${BMI_LIBRARIES}
    )
  else()
    message(FATAL_ERROR "Could not find BMI.")
  endif()
endif()


# MPI
option(NA_USE_MPI "Use MPI." OFF)
if(NA_USE_MPI)
  find_package(MPI REQUIRED)
  if(MPI_FOUND)
    message(STATUS "MPI include directory: ${MPI_INCLUDE_PATH}")
    set(NA_HAS_MPI 1)
    set(NA_PLUGINS ${NA_PLUGINS} mpi)
    set(NA_EXT_INCLUDE_DEPENDENCIES
      ${NA_EXT_INCLUDE_DEPENDENCIES}
      ${MPI_INCLUDE_PATH}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${MPI_LIBRARIES}
    )
    # Extra job setup for Cray MPI without ALPS support
    option(NA_MPI_USE_GNI_SETUP
      "Define NA_MPI_Gni_job_setup() to setup the Aries NIC resources for the job." OFF)
    if(NA_MPI_USE_GNI_SETUP)
      find_package(GNI REQUIRED)
      if(GNI_FOUND)
        set(NA_MPI_HAS_GNI_SETUP 1)
        set(NA_INT_INCLUDE_DEPENDENCIES
          ${NA_INT_INCLUDE_DEPENDENCIES}
          ${GNI_INCLUDE_DIRS}
        )
        set(NA_EXT_LIB_DEPENDENCIES
          ${NA_EXT_LIB_DEPENDENCIES}
          ${GNI_LIBRARIES}
        )
      else()
        message(FATAL_ERROR "Could not find GNI.")
      endif()
    endif()
  # we may want to add an option for MPI_VERSION >= 3
  else()
    message(FATAL_ERROR "Could not find MPI.")
  endif()
endif()

# CCI
option(NA_USE_CCI "Use CCI." OFF)
if(NA_USE_CCI)
  find_package(CCI REQUIRED)
  if(CCI_FOUND)
    message(STATUS "CCI include directory: ${CCI_INCLUDE_DIR}")
    set(NA_PLUGINS ${NA_PLUGINS} cci)
    set(NA_HAS_CCI 1)
    set(NA_INT_INCLUDE_DEPENDENCIES
      ${NA_INT_INCLUDE_DEPENDENCIES}
      ${CCI_INCLUDE_DIR}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${CCI_LIBRARIES}
    )
  else()
    message(FATAL_ERROR "Could not find CCI.")
  endif()
endif()

# OFI
option(NA_USE_OFI "Use libfabric plugin." OFF)
if(NA_USE_OFI)
  find_package(OFI 1.5 REQUIRED)
  if(OFI_FOUND)
    message(STATUS "OFI include directory: ${OFI_INCLUDE_DIR}")
    set(NA_PLUGINS ${NA_PLUGINS} ofi)
    set(NA_HAS_OFI 1)
    # Detect <rdma/fi_ext_gni.h>
    set(CMAKE_REQUIRED_INCLUDES ${OFI_INCLUDE_DIR})
    check_include_files("rdma/fi_ext_gni.h" NA_OFI_HAS_EXT_GNI_H)
    set(NA_INT_INCLUDE_DEPENDENCIES
      ${NA_INT_INCLUDE_DEPENDENCIES}
      ${OFI_INCLUDE_DIR}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${OFI_LIBRARIES}
    )
  else()
    message(FATAL_ERROR "Could not find OFI.")
  endif()
endif()

# SM
option(NA_USE_SM "Use shared-memory plugin." ON)
if(NA_USE_SM)
  if(WIN32)
    message(WARNING "SM plugin not supported on this platform yet.")
  else()
    include(CheckFunctionExists)
    check_function_exists(process_vm_readv NA_SM_HAS_CMA)
    if(NA_SM_HAS_CMA)
      execute_process(COMMAND /usr/sbin/sysctl -n kernel.yama.ptrace_scope
        OUTPUT_VARIABLE NA_SM_YAMA_LEVEL ERROR_VARIABLE NA_SM_YAMA_SYSCTL_ERROR)
      if(NOT NA_SM_YAMA_SYSCTL_ERROR) # Yama is present
        if(NA_SM_YAMA_LEVEL EQUAL 1)
          message(WARNING "Kernel Yama configuration only allows NA SM restricted cross-memory attach, please refer to the mercury documentation for more details.")
        elseif(NA_SM_YAMA_LEVEL GREATER 1)
          message(FATAL_ERROR "Kernel Yama configuration does not allow NA SM cross-memory attach, for more details please refer to: https://www.kernel.org/doc/Documentation/security/Yama.txt.")
        endif()
      endif()
    endif()
    if(NA_SM_HAS_CMA OR APPLE)
      set(NA_PLUGINS ${NA_PLUGINS} na)
      set(NA_HAS_SM 1)
      set(NA_SM_SHM_PREFIX "na_sm" CACHE STRING
        "Prefix to use for SHM file name.")
      set(NA_SM_TMP_DIRECTORY "/tmp" CACHE PATH
        "Location to use for NA SM temp data.")
      mark_as_advanced(NA_SM_SHM_PREFIX)
      mark_as_advanced(NA_SM_TMP_DIRECTORY)
    else()
      message(WARNING "Platform does not meet NA SM requirements.")
    endif()
  endif()
endif()

#------------------------------------------------------------------------------
# Configure module header files
#------------------------------------------------------------------------------
# Set unique vars used in the autogenerated config file (symbol import/export)
if(BUILD_SHARED_LIBS)
  set(NA_BUILD_SHARED_LIBS 1)
  set(NA_LIBTYPE SHARED)
else()
  set(NA_BUILD_SHARED_LIBS 0)
  set(NA_LIBTYPE STATIC)
endif()

if(MERCURY_ENABLE_VERBOSE_ERROR)
  set(NA_HAS_VERBOSE_ERROR 1)
else()
  set(NA_HAS_VERBOSE_ERROR 0)
endif()

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/na_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/na_config.h
)

#------------------------------------------------------------------------------
# Set sources
#------------------------------------------------------------------------------
set(NA_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/na.c
)

if(NA_HAS_BMI)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_bmi.c
  )
endif()

if(NA_HAS_MPI)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_mpi.c
  )
endif()

if(NA_HAS_CCI)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_cci.c
  )
endif()

if(NA_USE_OFI)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_ofi.c
  )
endif()

if(NA_HAS_SM)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_sm.c
  )
endif()

#----------------------------------------------------------------------------
# Libraries
#----------------------------------------------------------------------------
# NA
add_library(na ${NA_SRCS})
target_include_directories(na
  PRIVATE ${NA_INT_INCLUDE_DEPENDENCIES}
  PUBLIC  ${NA_EXT_INCLUDE_DEPENDENCIES}
         "$<BUILD_INTERFACE:${NA_BUILD_INCLUDE_DEPENDENCIES}>"
          $<INSTALL_INTERFACE:${NA_INSTALL_INCLUDE_INTERFACE}>
)
target_link_libraries(na mercury_util ${NA_EXT_LIB_DEPENDENCIES})
mercury_set_lib_options(na "na" ${NA_LIBTYPE})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(na)
endif()

#---------------------------------------------------------------------------
# Add Target(s) to CMake Install
#---------------------------------------------------------------------------
install(
  TARGETS
    na
  EXPORT
    ${NA_EXPORTED_TARGETS}
  LIBRARY DESTINATION ${NA_INSTALL_LIB_DIR}
  ARCHIVE DESTINATION ${NA_INSTALL_LIB_DIR}
  RUNTIME DESTINATION ${NA_INSTALL_BIN_DIR}
)

#-----------------------------------------------------------------------------
# Specify project header files to be installed
#-----------------------------------------------------------------------------
set(NA_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/na.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na_error.h
  ${CMAKE_CURRENT_BINARY_DIR}/na_config.h
)

if(NA_HAS_MPI)
  set(NA_HEADERS
    ${NA_HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_mpi.h
  )
endif()

#-----------------------------------------------------------------------------
# Add file(s) to CMake Install
#-----------------------------------------------------------------------------
install(
  FILES
    ${NA_HEADERS}
  DESTINATION
    ${NA_INSTALL_INCLUDE_DIR}
  COMPONENT
    headers
)

#------------------------------------------------------------------------------
# Set variables for parent scope
#------------------------------------------------------------------------------
set(NA_PLUGINS ${NA_PLUGINS} PARENT_SCOPE)
set(NA_EXT_INCLUDE_DEPENDENCIES ${NA_EXT_INCLUDE_DEPENDENCIES} PARENT_SCOPE)
set(NA_EXT_LIB_DEPENDENCIES ${NA_EXT_LIB_DEPENDENCIES} PARENT_SCOPE)
