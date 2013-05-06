#------------------------------------------------------------------------------
# External dependencies
#------------------------------------------------------------------------------
# Threads
include(FindThreads)
set(MERCURY_UTIL_EXT_DEPENCIES
  ${MERCURY_UTIL_EXT_DEPENCIES}
  ${CMAKE_THREAD_LIBS_INIT}
)

if(MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_UTIL_DEP_LIBRARIES ${MERCURY_UTIL_EXT_DEPENCIES} PARENT_SCOPE)
endif(MERCURY_CREATE_SINGLE_LIB)

#------------------------------------------------------------------------------
# Set sources
#------------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

set(MERCURY_UTIL_SRCS
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_hash_table.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_list.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_thread.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_thread_mutex.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mercury_thread_condition.c
)

if(MERCURY_CREATE_SINGLE_LIB)
  set(MERCURY_UTIL_SRCS
    ${MERCURY_UTIL_SRCS}
    PARENT_SCOPE
  )
else(MERCURY_CREATE_SINGLE_LIB)
  #----------------------------------------------------------------------------
  # Libraries
  #----------------------------------------------------------------------------
  # UTIL
  add_library(mercury_util ${MERCURY_UTIL_SRCS})
  target_link_libraries(mercury_util ${MERCURY_UTIL_EXT_DEPENCIES})
  set_lib_options(mercury_util "mercury_util" ${MERCURY_LIBTYPE})

  #---------------------------------------------------------------------------
  # Add Target(s) to CMake Install
  #---------------------------------------------------------------------------
  install(
    TARGETS
      mercury_util
    EXPORT
      ${MERCURY_EXPORTED_TARGETS}
    LIBRARY DESTINATION ${MERCURY_INSTALL_LIB_DIR}
    ARCHIVE DESTINATION ${MERCURY_INSTALL_LIB_DIR}
    RUNTIME DESTINATION ${MERCURY_INSTALL_BIN_DIR}
  )
endif(MERCURY_CREATE_SINGLE_LIB)

