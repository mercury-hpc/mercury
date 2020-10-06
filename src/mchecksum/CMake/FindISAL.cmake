# - Try to find ISA-L
# Once done this will define
#  ISAL_FOUND - System has ISA-L
#  ISAL_INCLUDE_DIRS - The ISA-L include directories
#  ISAL_LIBRARIES - The libraries needed to use ISA-L

find_path(ISAL_INCLUDE_DIR isa-l.h
  HINTS /usr/local/include /usr/include)

find_library(ISAL_LIBRARY NAMES isal
  HINTS /usr/local/lib /usr/lib)

set(ISAL_LIBRARIES ${ISAL_LIBRARY})
set(ISAL_INCLUDE_DIRS ${ISAL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set ISAL_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(ISAL DEFAULT_MSG
                                  ISAL_LIBRARY ISAL_INCLUDE_DIR)

mark_as_advanced(ISAL_INCLUDE_DIR ISAL_LIBRARY)
