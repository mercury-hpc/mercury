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

#------------------------------------------------------------------------------
# Version information
#------------------------------------------------------------------------------
# Hard-coded version variables are read-in from a separate file. This makes it
# easier to have a script to update version numbers automatically.
file(STRINGS version.txt version_txt)
extract_version_components("${version_txt}" "${PROJECT_NAME}")
set(NA_PACKAGE "na")
set(NA_PACKAGE_DESCRIPTION "Mercury Network Abstraction (NA) Library")
message(STATUS "${NA_PACKAGE} v${NA_VERSION_FULL}")

#-----------------------------------------------------------------------------
# Targets built within this project are exported at Install time for use
# by other projects.
#-----------------------------------------------------------------------------
if(NOT NA_EXPORTED_TARGETS)
  set(NA_EXPORTED_TARGETS "${NA_PACKAGE}-targets")
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

#------------------------------------------------------------------------------
# External dependencies / NA plugins
#------------------------------------------------------------------------------
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckVariableExists)

# BMI
option(NA_USE_BMI "Use BMI." OFF)
if(NA_USE_BMI)
  find_package(BMI REQUIRED)
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
endif()


# MPI
option(NA_USE_MPI "Use MPI." OFF)
if(NA_USE_MPI)
  find_package(MPI REQUIRED)
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
  mark_as_advanced(NA_MPI_USE_GNI_SETUP)
  if(NA_MPI_USE_GNI_SETUP)
    find_package(GNI REQUIRED)
    set(NA_MPI_HAS_GNI_SETUP 1)
    set(NA_INT_INCLUDE_DEPENDENCIES
      ${NA_INT_INCLUDE_DEPENDENCIES}
      ${GNI_INCLUDE_DIRS}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${GNI_LIBRARIES}
    )
  endif()
endif()

# CCI
option(NA_USE_CCI "Use CCI." OFF)
if(NA_USE_CCI)
  find_package(CCI REQUIRED)
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
endif()

# OFI
option(NA_USE_OFI "Use libfabric plugin." OFF)
if(NA_USE_OFI)
  find_package(OFI 1.9 REQUIRED)
  message(STATUS "OFI include directory: ${OFI_INCLUDE_DIR}")
  set(NA_PLUGINS ${NA_PLUGINS} ofi)
  set(NA_HAS_OFI 1)
  # Detect <rdma/fi_ext_gni.h>
  set(CMAKE_REQUIRED_INCLUDES ${OFI_INCLUDE_DIR})
  check_include_files("rdma/fi_ext_gni.h" NA_OFI_HAS_EXT_GNI_H)
  check_include_files("stdbool.h;rdma/fabric.h;rdma/fi_cxi_ext.h" NA_OFI_HAS_EXT_CXI_H)
  if(NA_OFI_HAS_EXT_GNI_H)
    option(NA_OFI_GNI_USE_UDREG "Force gni provider to use udreg instead of internal MR cache." OFF)
    if(NA_OFI_GNI_USE_UDREG)
      set(NA_OFI_GNI_HAS_UDREG 1)
    endif()
    mark_as_advanced(NA_OFI_GNI_USE_UDREG)
  endif()
  set(NA_INT_INCLUDE_DEPENDENCIES
    ${NA_INT_INCLUDE_DEPENDENCIES}
    ${OFI_INCLUDE_DIR}
  )
  set(NA_EXT_LIB_DEPENDENCIES
    ${NA_EXT_LIB_DEPENDENCIES}
    ${OFI_LIBRARIES}
  )
  option(NA_OFI_USE_HWLOC "Use hwloc to retrieve NIC information and select domain to use." OFF)
  if(NA_OFI_USE_HWLOC)
    find_package(HWLOC REQUIRED)
    set(NA_HAS_HWLOC 1)
    set(NA_INT_INCLUDE_DEPENDENCIES
      ${NA_INT_INCLUDE_DEPENDENCIES}
      ${HWLOC_INCLUDE_DIR}
    )
    set(NA_EXT_LIB_DEPENDENCIES
      ${NA_EXT_LIB_DEPENDENCIES}
      ${HWLOC_LIBRARIES}
    )
  endif()
  mark_as_advanced(NA_OFI_USE_HWLOC)
endif()

# UCX
option(NA_USE_UCX "Use UCX plugin." OFF)
if(NA_USE_UCX)
  find_package(UCX 1.10 REQUIRED)
  message(STATUS "UCX include directory: ${UCX_INCLUDE_DIR}")
  set(NA_PLUGINS ${NA_PLUGINS} ucx)
  set(NA_HAS_UCX 1)
  set(NA_INT_INCLUDE_DEPENDENCIES
    ${NA_INT_INCLUDE_DEPENDENCIES}
    ${UCX_INCLUDE_DIR}
  )
  set(NA_EXT_LIB_DEPENDENCIES
    ${NA_EXT_LIB_DEPENDENCIES}
    ${UCX_LIBRARIES}
  )
  # Additional cmake testing
  set(CMAKE_REQUIRED_INCLUDES ${UCX_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${UCX_LIBRARIES})
  if(CMAKE_BUILD_TYPE MATCHES "Tsan")
    set(CMAKE_REQUIRED_FLAGS ${CMAKE_C_FLAGS_TSAN})
  endif()

  # Detect ucp_lib_query
  check_symbol_exists(ucp_lib_query ucp/api/ucp.h NA_UCX_HAS_LIB_QUERY)
  # Detect whether UCX has thread mode names
  check_variable_exists(ucs_thread_mode_names NA_UCX_HAS_THREAD_MODE_NAMES)

  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_LIBRARIES)
  if(CMAKE_BUILD_TYPE MATCHES "Tsan")
    unset(CMAKE_REQUIRED_FLAGS)
  endif()
endif()

# SM
option(NA_USE_SM "Use shared-memory plugin." ON)
if(NA_USE_SM)
  if(WIN32)
    message(WARNING "SM plugin not supported on this platform yet.")
  else()
    option(NA_SM_USE_UUID "Use UUIDs for host identification instead of standard host ID." OFF)
    if(NA_SM_USE_UUID)
      find_package(UUID REQUIRED)
      set(NA_SM_HAS_UUID 1)
      set(NA_INT_INCLUDE_DEPENDENCIES
        ${NA_INT_INCLUDE_DEPENDENCIES}
        ${UUID_INCLUDE_DIRS}
      )
      set(NA_EXT_LIB_DEPENDENCIES
        ${NA_EXT_LIB_DEPENDENCIES}
        ${UUID_LIBRARIES}
      )
    endif()
    mark_as_advanced(NA_SM_USE_UUID)
    include(CheckFunctionExists)
    check_function_exists(process_vm_readv NA_SM_HAS_CMA)
    if(NA_SM_HAS_CMA)
      execute_process(COMMAND /usr/sbin/sysctl -n kernel.yama.ptrace_scope
        OUTPUT_VARIABLE NA_SM_YAMA_LEVEL ERROR_VARIABLE NA_SM_YAMA_SYSCTL_ERROR)
      if(NOT NA_SM_YAMA_SYSCTL_ERROR) # Yama is present
        if(NA_SM_YAMA_LEVEL EQUAL 1)
          message(WARNING "Kernel Yama configuration only allows NA SM restricted cross-memory attach, please refer to the NA documentation for more details.")
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

# PSM
option(NA_USE_PSM "Use PSM." OFF)
if(NA_USE_PSM)
  find_package(PSM REQUIRED)
  message(STATUS "PSM include directory: ${PSM_INCLUDE_DIR}")
  set(NA_PLUGINS ${NA_PLUGINS} psm)
  set(NA_HAS_PSM 1)
  set(NA_INT_INCLUDE_DEPENDENCIES
    ${NA_INT_INCLUDE_DEPENDENCIES}
    ${PSM_INCLUDE_DIR}
  )
  set(NA_EXT_LIB_DEPENDENCIES
    ${NA_EXT_LIB_DEPENDENCIES}
    ${PSM_LIBRARIES}
  )
endif()

# PSM2
option(NA_USE_PSM2 "Use PSM2." OFF)
if(NA_USE_PSM2)
  find_package(PSM2 REQUIRED)
  message(STATUS "PSM2 include directory: ${PSM2_INCLUDE_DIR}")
  set(NA_PLUGINS ${NA_PLUGINS} psm2)
  set(NA_HAS_PSM2 1)
  set(NA_INT_INCLUDE_DEPENDENCIES
    ${NA_INT_INCLUDE_DEPENDENCIES}
    ${PSM2_INCLUDE_DIR}
  )
  set(NA_EXT_LIB_DEPENDENCIES
    ${NA_EXT_LIB_DEPENDENCIES}
    ${PSM2_LIBRARIES}
  )
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

if(MERCURY_ENABLE_DEBUG)
  set(NA_HAS_DEBUG 1)
else()
  set(NA_HAS_DEBUG 0)
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
  ${CMAKE_CURRENT_SOURCE_DIR}/na_ip.c
  ${CMAKE_CURRENT_SOURCE_DIR}/na_loc.c
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

if(NA_USE_UCX)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_ucx.c
  )
endif()

if(NA_HAS_SM)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_sm.c
  )
endif()

if(NA_HAS_PSM)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_psm.c
  )
endif()

if(NA_HAS_PSM2)
  set(NA_SRCS
    ${NA_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_psm2.c
  )
endif()

#------------------------------------------------------------------------------
# Specify project public header files to be installed
#------------------------------------------------------------------------------
set(NA_PUBLIC_HEADERS
  ${CMAKE_CURRENT_BINARY_DIR}/na_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na_types.h
)

if(NA_HAS_MPI)
  set(NA_PUBLIC_HEADERS
    ${NA_PUBLIC_HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_mpi.h
  )
endif()

if(NA_HAS_SM)
  set(NA_PUBLIC_HEADERS
    ${NA_PUBLIC_HEADERS}
    ${CMAKE_CURRENT_SOURCE_DIR}/na_sm.h
  )
endif()

#------------------------------------------------------------------------------
# Specify project private header files
#------------------------------------------------------------------------------
set(NA_PRIVATE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/na_error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na_ip.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na_loc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/na_plugin.h
)

#----------------------------------------------------------------------------
# Libraries
#----------------------------------------------------------------------------

# Clean up system include path first
foreach(item ${MERCURY_SYSTEM_INCLUDE_PATH})
  if(NA_EXT_INCLUDE_DEPENDENCIES)
    list(REMOVE_ITEM NA_EXT_INCLUDE_DEPENDENCIES ${item})
  endif()
endforeach()
foreach(item ${MERCURY_SYSTEM_INCLUDE_PATH})
  if(NA_INT_INCLUDE_DEPENDENCIES)
    list(REMOVE_ITEM NA_INT_INCLUDE_DEPENDENCIES ${item})
  endif()
endforeach()

# NA
add_library(na ${NA_SRCS}
  ${NA_PRIVATE_HEADERS} ${NA_PUBLIC_HEADERS}
)
target_include_directories(na
  PUBLIC  "$<BUILD_INTERFACE:${NA_BUILD_INCLUDE_DEPENDENCIES}>"
          $<INSTALL_INTERFACE:${NA_INSTALL_INCLUDE_INTERFACE}>
)
target_include_directories(na
  SYSTEM PUBLIC  ${NA_EXT_INCLUDE_DEPENDENCIES}
         PRIVATE ${NA_INT_INCLUDE_DEPENDENCIES}
)
target_link_libraries(na mercury_util ${NA_EXT_LIB_DEPENDENCIES})
mercury_set_lib_options(na "na" ${NA_LIBTYPE} ${PROJECT_NAME})
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(na)
endif()
set_target_properties(na PROPERTIES
  PUBLIC_HEADER "${NA_PUBLIC_HEADERS}"
)

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
  PUBLIC_HEADER DESTINATION ${NA_INSTALL_INCLUDE_DIR}
  RUNTIME DESTINATION ${NA_INSTALL_BIN_DIR}
)

#------------------------------------------------------------------------------
# Set variables for parent scope
#------------------------------------------------------------------------------
set(NA_PLUGINS ${NA_PLUGINS} PARENT_SCOPE)

#-----------------------------------------------------------------------------
# For automake compatibility, also provide a pkgconfig file
#-----------------------------------------------------------------------------
if(NOT WIN32)
  if(CMAKE_BUILD_TYPE)
    string(TOLOWER ${CMAKE_BUILD_TYPE} lower_cmake_build_type)
  endif()

  # Retrieve NA library
  if(lower_cmake_build_type MATCHES "debug")
    get_target_property(NA_LIBRARY na OUTPUT_NAME_DEBUG)
  else()
    get_target_property(NA_LIBRARY na OUTPUT_NAME_RELEASE)
  endif()

  # Pkg dependencies
  set(NA_PKG_DEPENDENCIES mercury_util)

  # NA external library dependencies
  # Need to generate -llib if not already passed
  foreach(lib_dep ${NA_EXT_LIB_DEPENDENCIES})
    # get library name
    get_filename_component(lib_name ${lib_dep} NAME_WE)
    if(lib_name MATCHES "^-l" OR lib_name MATCHES "-pthread")
      # lib_name found is -lxxx
      set(NA_EXT_LIB_DEPENDENCIES_LIST
          ${NA_EXT_LIB_DEPENDENCIES_LIST} ${lib_name})
    else()
      # lib_name is /path/to/lib so get library path and name
      get_filename_component(lib_path ${lib_dep} PATH)
      string(REGEX REPLACE "^lib" "" lib_name ${lib_name})
      set(NA_EXT_LIB_DEPENDENCIES_LIST
          ${NA_EXT_LIB_DEPENDENCIES_LIST} -L${lib_path} -l${lib_name})
    endif()
  endforeach()
  if(NA_EXT_LIB_DEPENDENCIES_LIST)
    list(REMOVE_DUPLICATES NA_EXT_LIB_DEPENDENCIES_LIST)
    string(REPLACE ";" " "
           NA_LIB_DEPENDENCIES "${NA_EXT_LIB_DEPENDENCIES_LIST}")
  endif()

  # External include dependencies (should be rare)
  if(NA_EXT_INCLUDE_DEPENDENCIES)
    list(REMOVE_DUPLICATES NA_EXT_INCLUDE_DEPENDENCIES)
  endif()
  foreach(inc_dep ${NA_EXT_INCLUDE_DEPENDENCIES})
    set(NA_INCLUDE_DEPENDENCIES "${NA_INCLUDE_DEPENDENCIES} -I${inc_dep}")
  endforeach()

  # Configure pkg-config file
  configure_file(
    ${NA_SOURCE_DIR}/CMake/${NA_PACKAGE}.pc.in
    ${NA_BINARY_DIR}/CMakeFiles/${NA_PACKAGE}.pc @ONLY
  )

  # Install pkg-config file
  install(
    FILES
      ${NA_BINARY_DIR}/CMakeFiles/${NA_PACKAGE}.pc
    DESTINATION
      ${NA_INSTALL_LIB_DIR}/pkgconfig
  )

endif()