# - Try to find DRC
# Once done this will define
#  DRC_FOUND - System has DRC
#  DRC_INCLUDE_DIRS - The DRC include directories
#  DRC_LIBRARIES - The libraries needed to use DRC

find_package(PkgConfig)
pkg_check_modules(PC_DRC cray-drc)

find_path(DRC_INCLUDE_DIR rdmacred.h
  HINTS ${PC_DRC_INCLUDEDIR} ${PC_DRC_INCLUDE_DIRS})

find_library(DRC_LIBRARY NAMES drc
  HINTS ${PC_DRC_LIBDIR} ${PC_DRC_LIBRARY_DIRS})

set(DRC_INCLUDE_DIRS ${DRC_INCLUDE_DIR})
set(DRC_LIBRARIES ${DRC_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set DRC_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(DRC DEFAULT_MSG
                                  DRC_INCLUDE_DIR DRC_LIBRARY)

mark_as_advanced(DRC_INCLUDE_DIR DRC_LIBRARY)
