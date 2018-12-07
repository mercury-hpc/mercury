#------------------------------------------------------------------------------
# Set up test options
#------------------------------------------------------------------------------
set(MERCURY_TESTING_BUFFER_SIZE "16" CACHE STRING
  "Total buffer size (in MB) used for testing.")
mark_as_advanced(MERCURY_TESTING_BUFFER_SIZE)

option(MERCURY_TESTING_USE_THREAD_POOL "Run tests using thread pool." ON)
if(MERCURY_TESTING_USE_THREAD_POOL)
  set(MERCURY_TESTING_HAS_THREAD_POOL ON)
endif()
mark_as_advanced(MERCURY_TESTING_USE_THREAD_POOL)

option(MERCURY_TESTING_VERIFY_DATA
  "Verify data when running tests (disable when measuring bandwidth)." ON)
if(MERCURY_TESTING_VERIFY_DATA)
  set(MERCURY_TESTING_HAS_VERIFY_DATA ON)
endif()
mark_as_advanced(MERCURY_TESTING_VERIFY_DATA)

option(MERCURY_TESTING_PRINT_PARTIAL
  "Print partial results between loops (disable when measuring)." OFF)
mark_as_advanced(MERCURY_TESTING_PRINT_PARTIAL)

option(MERCURY_ENABLE_PARALLEL_TESTING
  "Enable testing in parallel (requires MPI)." OFF)
if(MERCURY_ENABLE_PARALLEL_TESTING OR NA_USE_MPI)
  set(MERCURY_HAS_PARALLEL_TESTING 1)
  if(NA_USE_MPI AND NOT MERCURY_ENABLE_PARALLEL_TESTING)
    # Always force parallel testing if NA_USE_MPI is turned ON
    set(MERCURY_ENABLE_PARALLEL_TESTING "ON" CACHE BOOL
      "Enable testing in parallel (requires MPI)." FORCE)
  endif()
else()
  set(MERCURY_HAS_PARALLEL_TESTING 0)
endif()

set(MERCURY_TEST_INIT_COMMAND "" CACHE STRING
  "Command to run before a client/server test begins. Multiple commands are separated by ';'.")
mark_as_advanced(MERCURY_TEST_INIT_COMMAND)

set(MERCURY_TESTING_TEMP_DIRECTORY "." CACHE PATH
  "Location to use for temp data (default is current directory).")
mark_as_advanced(MERCURY_TESTING_TEMP_DIRECTORY)

if(MERCURY_USE_SELF_FORWARD)
  option(MERCURY_TESTING_CORESIDENT "Enable testing of coresident mode." OFF)
else()
  set(MERCURY_TESTING_CORESIDENT "OFF" CACHE BOOL
    "Enable testing of coresident mode." FORCE)
endif()
mark_as_advanced(MERCURY_TESTING_CORESIDENT)

#------------------------------------------------------------------------------
# NA protocols used for testing
# (case where the NA plugin defines multiple protocols)
#------------------------------------------------------------------------------
if(NA_USE_BMI)
  set(NA_BMI_TESTING_PROTOCOL "tcp" CACHE STRING "Protocol(s) used for testing (e.g., tcp;ib).")
  mark_as_advanced(NA_BMI_TESTING_PROTOCOL)
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
  set(NA_OFI_TESTING_PROTOCOL "tcp" CACHE STRING "Protocol(s) used for testing (e.g., sockets;psm2;verbs).")
  mark_as_advanced(NA_OFI_TESTING_PROTOCOL)

  option(NA_OFI_TESTING_USE_CRAY_DRC
    "Use Cray DRC to allow multi-job communication." OFF)
  mark_as_advanced(NA_OFI_TESTING_USE_CRAY_DRC)
  if(NA_OFI_TESTING_USE_CRAY_DRC)
    find_package(DRC REQUIRED)
    if(DRC_FOUND)
      set(HG_TESTING_HAS_CRAY_DRC 1)
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

# Detect <sys/prctl.h>
check_include_files("sys/prctl.h" HG_TESTING_HAS_SYSPRCTL_H)

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

if(MERCURY_ENABLE_PARALLEL_TESTING)
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

macro(add_mercury_test_comm test_name comm protocol busy)
  # Set full test name
  set(full_test_name ${test_name})
  set(opt_names ${comm} ${protocol})
  foreach(opt_name ${opt_names})
    set(full_test_name ${full_test_name}_${opt_name})
  endforeach()
  if(${busy})
    set(full_test_name ${full_test_name}_busy)
  endif()

  # Set test arguments
  set(test_args --comm ${comm} --protocol ${protocol})
  if(${busy})
    set(test_args ${test_args} --busy)
  endif()

  # Static client/server test
  if(${comm} STREQUAL "mpi" AND ${protocol} STREQUAL "static")
    set(static_test_args ${test_args} --mpi_static)
    add_test(NAME "mercury_${full_test_name}"
      COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} 1
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_server> ${MPIEXEC_POSTFLAGS}
      ${static_test_args} : ${MPIEXEC_NUMPROC_FLAG} ${MPIEXEC_MAX_NUMPROCS}
      ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${static_test_args}
    )
  else()
    # Dynamic client/server test
    add_test(NAME "mercury_${full_test_name}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:hg_test_server>
      --client $<TARGET_FILE:hg_test_${test_name}> ${test_args}
    )
  endif()

  # Coresident test (disable for BMI and MPI)
  if(MERCURY_TESTING_CORESIDENT AND
    (NOT ((${comm} STREQUAL "bmi") OR (${comm} STREQUAL "mpi") OR (${test_name} STREQUAL "cancel"))))
    set(cores_test_name ${full_test_name}_self)
    set(cores_test_args ${test_args} --self_send)
    if (MERCURY_ENABLE_PARALLEL_TESTING)
      add_test(NAME "mercury_${cores_test_name}"
        COMMAND ${MPIEXEC} ${MPIEXEC_NUMPROC_FLAG} ${MPIEXEC_MAX_NUMPROCS}
        ${MPIEXEC_PREFLAGS} $<TARGET_FILE:hg_test_${test_name}> ${MPIEXEC_POSTFLAGS}
        ${cores_test_args}
      )
    else()
      add_test(NAME "mercury_${cores_test_name}"
        COMMAND $<TARGET_FILE:hg_test_${test_name}> ${cores_test_args}
      )
    endif()
  endif()

  # Scalable endpoint test
  if(MERCURY_TESTING_HAS_THREAD_POOL AND ${comm} STREQUAL "ofi")
    set(cores_test_name ${full_test_name}_scalable)
    set(cores_test_args ${test_args} -C 2)
    add_test(NAME "mercury_${cores_test_name}"
      COMMAND $<TARGET_FILE:mercury_test_driver>
      --server $<TARGET_FILE:hg_test_server>
      --client $<TARGET_FILE:hg_test_${test_name}> ${cores_test_args}
    )
  endif()
endmacro()

function(add_mercury_test test_name)
  foreach(comm ${NA_PLUGINS})
    string(TOUPPER ${comm} upper_comm)
    foreach(protocol ${NA_${upper_comm}_TESTING_PROTOCOL})
      add_mercury_test_comm(${test_name} ${comm} ${protocol} false)
      add_mercury_test_comm(${test_name} ${comm} ${protocol} true)
    endforeach()
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
target_link_libraries(mercury_test mercury_hl na_test
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

set(MERCURY_tests
  rpc
  bulk
  overflow
  cancel
)
if(NOT WIN32)
  set(MERCURY_tests ${MERCURY_tests} posix)
endif()
#build_mercury_test(nested)
build_mercury_test(perf)
build_mercury_test(rpc_lat)
build_mercury_test(write_bw)
build_mercury_test(read_bw)
#build_mercury_test(init)
if(HG_TESTING_HAS_CRAY_DRC)
  build_mercury_test(drc_auth)
endif()

# Build tests and add them to ctest
foreach(MERCURY_test ${MERCURY_tests})
  build_mercury_test(${MERCURY_test})
  add_mercury_test(${MERCURY_test})
endforeach()
