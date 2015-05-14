# - Try to find SNAPPY
# Once done this will define
#  SNAPPY_FOUND - System has Snappy
#  SNAPPY_INCLUDE_DIRS - The Snappy include directories
#  SNAPPY_LIBRARIES - The libraries needed to use Snappy

find_path(SNAPPY_INCLUDE_DIR snappy-c.h
  HINTS /usr/local/include /usr/include)

find_library(SNAPPY_LIBRARY NAMES snappy
  PATHS /usr/local/lib /usr/lib)

set(SNAPPY_INCLUDE_DIRS ${SNAPPY_INCLUDE_DIR})
set(SNAPPY_LIBRARIES ${SNAPPY_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SNAPPY_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(SNAPPY DEFAULT_MSG
                                  SNAPPY_INCLUDE_DIR SNAPPY_LIBRARY)

mark_as_advanced(SNAPPY_INCLUDE_DIR SNAPPY_LIBRARY)
