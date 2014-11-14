# - Try to find CCI
# Once done this will define
#  CCI_FOUND - System has CCI
#  CCI_INCLUDE_DIRS - The CCI include directories
#  CCI_LIBRARIES - The libraries needed to use CCI

find_path(CCI_INCLUDE_DIR cci.h
  HINTS /usr/local/include /usr/include)

find_library(CCI_LIBRARY NAMES cci
  PATHS /usr/local/lib /usr/lib)

set(CCI_INCLUDE_DIRS ${CCI_INCLUDE_DIR})
set(CCI_LIBRARIES ${CCI_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CCI_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(CCI DEFAULT_MSG
                                  CCI_INCLUDE_DIR CCI_LIBRARY)

mark_as_advanced(CCI_INCLUDE_DIR CCI_LIBRARY)
