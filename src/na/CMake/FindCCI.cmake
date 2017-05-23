# - Try to find CCI
# Once done this will define
#  CCI_FOUND - System has CCI
#  CCI_INCLUDE_DIRS - The CCI include directories
#  CCI_LIBRARIES - The libraries needed to use CCI

find_package(PkgConfig)
pkg_check_modules(PC_CCI QUIET cci)

find_path(CCI_INCLUDE_DIR cci.h
  HINTS ${PC_CCI_INCLUDEDIR} ${PC_CCI_INCLUDE_DIRS})

find_library(CCI_LIBRARY NAMES cci
  HINTS ${PC_CCI_LIBDIR} ${PC_CCI_LIBRARY_DIRS})

set(CCI_INCLUDE_DIRS ${CCI_INCLUDE_DIR})
set(CCI_LIBRARIES ${CCI_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CCI_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(CCI DEFAULT_MSG
                                  CCI_INCLUDE_DIR CCI_LIBRARY)

mark_as_advanced(CCI_INCLUDE_DIR CCI_LIBRARY)
