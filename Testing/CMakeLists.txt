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
endif()

if(NA_USE_SM)
  set(NA_NA_TESTING_PROTOCOL "sm" CACHE STRING "Protocol(s) used for testing (e.g., sm).")
  mark_as_advanced(NA_NA_TESTING_PROTOCOL)
endif()

if(NA_USE_PSM)
  set(NA_PSM_TESTING_PROTOCOL "psm" CACHE STRING "Protocol(s) used for testing (e.g., psm).")
  mark_as_advanced(NA_PSM_TESTING_PROTOCOL)
endif()

if(NA_USE_PSM2)
  set(NA_PSM2_TESTING_PROTOCOL "psm2" CACHE STRING "Protocol(s) used for testing (e.g., psm2).")
  mark_as_advanced(NA_PSM2_TESTING_PROTOCOL)
endif()

#------------------------------------------------------------------------------
# Common libraries
#------------------------------------------------------------------------------
add_subdirectory(common)

#------------------------------------------------------------------------------
# Compile kwsys library and setup TestDriver
#------------------------------------------------------------------------------
add_subdirectory(driver)

#------------------------------------------------------------------------------
# Unit tests
#------------------------------------------------------------------------------
add_subdirectory(unit)

#------------------------------------------------------------------------------
# Perf tests
#------------------------------------------------------------------------------
add_subdirectory(perf)
