#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
option(MERCURY_TESTING_USE_THREAD_POOL "Run tests using thread pool." ON)
if(MERCURY_TESTING_USE_THREAD_POOL)
  set(HG_TEST_HAS_THREAD_POOL 1)
endif()
mark_as_advanced(MERCURY_TESTING_USE_THREAD_POOL)

option(MERCURY_TESTING_VERIFY_DATA
  "Verify data when running tests (disable when measuring bandwidth)." ON)
if(MERCURY_TESTING_VERIFY_DATA)
  set(HG_TEST_HAS_VERIFY_DATA 1)
endif()
mark_as_advanced(MERCURY_TESTING_VERIFY_DATA)

option(MERCURY_TESTING_PRINT_PARTIAL
  "Print partial results between loops (disable when measuring)." OFF)
if(MERCURY_TESTING_PRINT_PARTIAL)
  set(HG_TEST_PRINT_PARTIAL 1)
endif()
mark_as_advanced(MERCURY_TESTING_PRINT_PARTIAL)

option(MERCURY_TESTING_ENABLE_PARALLEL
  "Enable testing in parallel (requires MPI)." OFF)
if(MERCURY_TESTING_ENABLE_PARALLEL OR NA_USE_MPI)
  set(HG_TEST_HAS_PARALLEL 1)
  if(NA_USE_MPI AND NOT MERCURY_TESTING_ENABLE_PARALLEL)
    # Always force parallel testing if NA_USE_MPI is turned ON
    set(MERCURY_TESTING_ENABLE_PARALLEL "ON" CACHE BOOL
      "Enable testing in parallel (requires MPI)." FORCE)
  endif()
else()
  set(HG_TEST_HAS_PARALLEL 0)
endif()
mark_as_advanced(MERCURY_TESTING_ENABLE_PARALLEL)

set(MERCURY_TESTING_INIT_COMMAND "" CACHE STRING
  "Command to run before a client/server test begins. Multiple commands are separated by ';'.")
set(HG_TEST_INIT_COMMAND ${MERCURY_TESTING_INIT_COMMAND})
mark_as_advanced(MERCURY_TESTING_INIT_COMMAND)

set(MERCURY_TESTING_TEMP_DIRECTORY "." CACHE PATH
  "Location to use for temp data (default is current directory).")
set(HG_TEST_TEMP_DIRECTORY ${MERCURY_TESTING_TEMP_DIRECTORY})
mark_as_advanced(MERCURY_TESTING_TEMP_DIRECTORY)

set(HG_TEST_FAIL_REGULAR_EXPRESSION "[^a-z]Error;ERROR;Failed")

#------------------------------------------------------------------------------
# NA protocols used for testing
# (case where the NA plugin defines multiple protocols)
#------------------------------------------------------------------------------
if(NA_USE_BMI)
  set(NA_BMI_TESTING_PROTOCOL "tcp" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
  mark_as_advanced(NA_BMI_TESTING_PROTOCOL)
endif()

if(NA_USE_UCX)
  set(NA_UCX_TESTING_PROTOCOL "all" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
  mark_as_advanced(NA_UCX_TESTING_PROTOCOL)
endif()

#Does not really make sense for MPI (so do not add an option for it)
if(NA_USE_MPI)
  set(NA_MPI_TESTING_PROTOCOL "dynamic;static" CACHE STRING "Protocol(s) used for testing (e.g., dynamic;static).")
  mark_as_advanced(NA_MPI_TESTING_PROTOCOL)
endif()

if(NA_USE_CCI)
  set(NA_CCI_TESTING_PROTOCOL "tcp" CACHE STRING "Protocol(s) used for testing (e.g., tcp;sm).")
  mark_as_advanced(NA_CCI_TESTING_PROTOCOL)
endif()

if(NA_USE_OFI)
  set(NA_OFI_TESTING_PROTOCOL "sockets;tcp" CACHE STRING "Protocol(s) used for testing (e.g., sockets;psm2;verbs).")
  mark_as_advanced(NA_OFI_TESTING_PROTOCOL)

  option(NA_OFI_TESTING_USE_CRAY_DRC
    "Use Cray DRC to allow multi-job communication." OFF)
  mark_as_advanced(NA_OFI_TESTING_USE_CRAY_DRC)
  if(NA_OFI_TESTING_USE_CRAY_DRC)
    find_package(DRC REQUIRED)
    if(DRC_FOUND)
      set(HG_TEST_HAS_CRAY_DRC 1)
      include_directories(${DRC_INCLUDE_DIRS})
      set(MERCURY_TEST_EXT_LIB_DEPENDENCIES
        ${MERCURY_TEST_EXT_LIB_DEPENDENCIES}
        ${DRC_LIBRARIES}
      )
    else()
      message(FATAL_ERROR "Could not find Cray DRC.")
    endif()
  endif()
endif()

if(NA_USE_SM)
  set(NA_NA_TESTING_PROTOCOL "sm" CACHE STRING "Protocol(s) used for testing (e.g., sm).")
  mark_as_advanced(NA_NA_TESTING_PROTOCOL)
endif()

# List of plugins that support forward to self
# set(NA_TESTING_SELF "sm;ofi")

# List of progress modes to test
set(NA_TESTING_NO_BLOCK "true;false")

# Detect <sys/prctl.h>
check_include_files("sys/prctl.h" HG_TEST_HAS_SYSPRCTL_H)

#------------------------------------------------------------------------------
# Compile kwsys library and setup TestDriver
#------------------------------------------------------------------------------
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_test_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/mercury_test_config.h
)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

if(MERCURY_TESTING_ENABLE_PARALLEL)
  find_package(MPI REQUIRED)
  if(MPI_FOUND)
    include_directories(${MPI_INCLUDE_PATH})
    set(MERCURY_TEST_EXT_LIB_DEPENDENCIES
      ${MERCURY_TEST_EXT_LIB_DEPENDENCIES}
      ${MPI_LIBRARIES}
    )
  else()
    message(FATAL_ERROR "Could not find MPI.")
  endif()
endif()

add_subdirectory(driver)

#------------------------------------------------------------------------------
# Set up test macros
#------------------------------------------------------------------------------
#
# hg prefix is added to executable
#
function(build_mercury_test test_name)
  add_executable(hg_test_${test_name} test_${test_name}.c)
  target_link_libraries(hg_test_${test_name} mercury_test)
  if(MERCURY_ENABLE_COVERAGE)
    set_coverage_flags(hg_test_${test_name})
  endif()
endfunction()

macro(add_mercury_test test_name comm protocol busy parallel self scalable
  ignore_server_err)
  # Set full test name
  set(full_test_name ${test_name})
  set(opt_names ${comm} ${protocol})
  foreach(opt_name ${opt_names})
    set(full_test_name ${full_test_name}_${opt_name})
  endforeach()
  if(${busy})
    set(full_test_name ${full_test_name}_busy)
  endif()
  if(${self})
    set(full_test_name ${full_test_name}_self)
  endif()
  if(${scalable})
    set(full_test_name ${full_test_name}_scalable)
  endif()

  # Set test arguments
  set(test_args --comm ${comm} --protocol ${protocol})
  if(${busy})
    set(test_args ${test_args} --busy)
  endif()
  if(NOT ${parallel})
    set(numprocs 1)
  else()
    set(numprocs ${MPIEXEC_MAX_NUMPROCS})
  endif()
  if(${self})
    set(test_args ${test_args} --self_send)
  endif()
  if(${scalable})
    set(test_args ${test_args} -C 2)
  endif()
  if(${ignore_server_err})
    set(driver_args ${driver_args} --allow-server-errors)
  endif()

  if(NOT ${self})
    # Static client/server test (MPI only)
    if(${comm} STREQUAL "mpi" AND ${protocol} STREQUAL "static")
      set(static_test_args ${test_args} --mpi_static)
      # NB. always parallel
      add_test(NAME "mercury_${full_test_name}"
        COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} 1
        ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_server> ${MPIEXEC_POSTFLAGS}
        ${static_test_args} : ${MPIEXEC_NUMPROC_FLAG} ${numprocs}
        ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${static_test_args}
      )
      set_tests_properties("mercury_${full_test_name}" PROPERTIES
        FAIL_REGULAR_EXPRESSION ${HG_TEST_FAIL_REGULAR_EXPRESSION}
      )
    else()
      # Dynamic client/server test
      set(driver_args
        ${driver_args}
        --server $<TARGET_FILE:hg_test_server>       ${test_args}
        --client $<TARGET_FILE:hg_test_${test_name}> ${test_args})
      if(NOT ${parallel})
        set(driver_args ${driver_args} --serial)
      endif()
      add_test(NAME "mercury_${full_test_name}"
        COMMAND $<TARGET_FILE:mercury_test_driver>
        ${driver_args}
      )
    endif()
  else()
    # Test without server
    if(NOT ${parallel})
      add_test(NAME "mercury_${full_test_name}"
      COMMAND $<TARGET_FILE:hg_test_${test_name}> ${test_args}
      )
      set_tests_properties("mercury_${full_test_name}" PROPERTIES
        FAIL_REGULAR_EXPRESSION ${HG_TEST_FAIL_REGULAR_EXPRESSION}
      )
    else()
      add_test(NAME "mercury_${full_test_name}"
        COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} ${numprocs}
        ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${MPIEXEC_POSTFLAGS}
        ${test_args}
      )
      set_tests_properties("mercury_${full_test_name}" PROPERTIES
        FAIL_REGULAR_EXPRESSION ${HG_TEST_FAIL_REGULAR_EXPRESSION}
      )
    endif()
  endif()
endmacro()

macro(add_mercury_test_standalone test_name)
  add_test(NAME mercury_${test_name} COMMAND $<TARGET_FILE:hg_test_${test_name}>)
endmacro()

# Loop over all combinations
function(add_mercury_test_comm test_name comm protocols progress_modes serial self ignore_server_err)
#  message("name=${test_name} comm=${comm} protocols=${protocols} progress_modes=${progress_modes} serial=${serial} self=${self}")
  foreach(protocol ${protocols})
    foreach(busy ${progress_modes})
      add_mercury_test(${test_name}
        ${comm} ${protocol} ${busy} ${serial} ${self} false ${ignore_server_err})
    endforeach()
  endforeach()
endfunction()

function(add_mercury_test_comm_scalable test_name comm protocols progress_modes serial)
  foreach(protocol ${protocols})
    foreach(busy ${progress_modes})
      # Restrict to OFI for now
      if(${comm} STREQUAL "ofi" AND
        (NOT ((${protocol} STREQUAL "tcp") OR (${protocol} STREQUAL "verbs"))))
          add_mercury_test(${test_name}
            ${comm} ${protocol} ${busy} ${serial} false true false)
      endif()
    endforeach()
  endforeach()
endfunction()

function(add_mercury_test_comm_all test_name)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    # Forward to remote server
    add_mercury_test_comm(${test_name} ${comm}
      "${NA_${upper_comm}_TESTING_PROTOCOL}"
      "${NA_TESTING_NO_BLOCK}" ${MERCURY_TESTING_ENABLE_PARALLEL} false false)
    # Forward to self
    if(NOT ((${comm} STREQUAL "bmi") OR (${comm} STREQUAL "mpi")))
      add_mercury_test_comm(${test_name} ${comm}
        "${NA_${upper_comm}_TESTING_PROTOCOL}"
        "${NA_TESTING_NO_BLOCK}" ${MERCURY_TESTING_ENABLE_PARALLEL} true false)
    endif()
    # Scalable test
    if(MERCURY_TESTING_USE_THREAD_POOL AND NOT APPLE)
      add_mercury_test_comm_scalable(${test_name} ${comm}
        "${NA_${upper_comm}_TESTING_PROTOCOL}"
        false ${MERCURY_TESTING_ENABLE_PARALLEL} true)
    endif()
  endforeach()
endfunction()

function(add_mercury_test_comm_all_serial test_name)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    # Forward to remote server
    add_mercury_test_comm(${test_name} ${comm}
      "${NA_${upper_comm}_TESTING_PROTOCOL}"
      "${NA_TESTING_NO_BLOCK}" false false false)
    # Forward to self
    if(NOT ((${comm} STREQUAL "bmi") OR (${comm} STREQUAL "mpi")))
      add_mercury_test_comm(${test_name} ${comm}
        "${NA_${upper_comm}_TESTING_PROTOCOL}"
        "${NA_TESTING_NO_BLOCK}" false true false)
    endif()
  endforeach()
endfunction()

function(add_mercury_test_comm_kill_server test_name)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    # Forward to remote server
    if(NOT ((${comm} STREQUAL "bmi") OR (${comm} STREQUAL "mpi")))
      add_mercury_test_comm(${test_name} ${comm}
        "${NA_${upper_comm}_TESTING_PROTOCOL}"
        "${NA_TESTING_NO_BLOCK}" false false true)
    endif()
  endforeach()
endfunction()

#------------------------------------------------------------------------------
# NA tests
#------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/na)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/na)

#------------------------------------------------------------------------------
# UTIL tests
#------------------------------------------------------------------------------
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)

#------------------------------------------------------------------------------
# Set sources for mercury_test library
#------------------------------------------------------------------------------
set(MERCURY_TEST_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_rpc_cb.c
)

if(NA_OFI_TESTING_USE_CRAY_DRC)
  set(MERCURY_TEST_SRCS
    ${MERCURY_TEST_SRCS}
    ${CMAKE_CURRENT_SOURCE_DIR}/mercury_test_drc.c
  )
endif()

#----------------------------------------------------------------------------
# Libraries
#----------------------------------------------------------------------------

add_library(mercury_test STATIC ${MERCURY_TEST_SRCS})
target_link_libraries(mercury_test mercury na_test
  ${MERCURY_TEST_EXT_LIB_DEPENDENCIES}
)
if(MERCURY_ENABLE_COVERAGE)
  set_coverage_flags(mercury_test)
endif()

#------------------------------------------------------------------------------
# Tests and executables
#------------------------------------------------------------------------------

# Server used for testing
build_mercury_test(server)

# List of tests
build_mercury_test(rpc)
build_mercury_test(bulk)

build_mercury_test(lookup)
build_mercury_test(proc)

build_mercury_test(rpc_lat)
build_mercury_test(write_bw)
build_mercury_test(read_bw)

build_mercury_test(kill)

# Cray DRC test
if(NA_OFI_TESTING_USE_CRAY_DRC)
  build_mercury_test(drc_auth)
endif()

add_mercury_test_standalone(proc)

add_mercury_test_comm_all(rpc)
add_mercury_test_comm_all(bulk)

add_mercury_test_comm_all_serial(rpc_lat)
add_mercury_test_comm_all_serial(write_bw)
add_mercury_test_comm_all_serial(read_bw)

add_mercury_test_comm_kill_server(kill)

