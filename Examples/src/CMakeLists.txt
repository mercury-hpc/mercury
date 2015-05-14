#------------------------------------------------------------------------------
# Include source and build directories
#------------------------------------------------------------------------------
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

#------------------------------------------------------------------------------
# External dependencies
#------------------------------------------------------------------------------
# mercury
find_package(MERCURY REQUIRED)
include_directories(${MERCURY_INCLUDE_DIR})

# Snappy
find_package(SNAPPY REQUIRED)
if(SNAPPY_FOUND)
  message(STATUS "Snappy include directory: ${SNAPPY_INCLUDE_DIR}")
  include_directories(${SNAPPY_INCLUDE_DIR})
  set(MercuryExamples_LIB_DEPENDENCIES
    ${MercuryExamples_LIB_DEPENDENCIES}
    ${SNAPPY_LIBRARIES}
  )
else()
  message(FATAL_ERROR "Could not find Snappy.")
endif()

# Check have snappy

#------------------------------------------------------------------------------
# Examples
#------------------------------------------------------------------------------
function(build_mercury_example example_name)
  add_executable(hg_example_${example_name} example_snappy.c example_${example_name}.c)
  target_link_libraries(hg_example_${example_name}
    mercury
    ${MercuryExamples_LIB_DEPENDENCIES}
  )
endfunction()

build_mercury_example(snappy_client)
build_mercury_example(snappy_server)