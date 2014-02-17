# - Try to find GNI
# Once done this will define
#  GNI_FOUND - System has GNI
#  GNI_INCLUDE_DIRS - The GNI include directories

find_package(PkgConfig)
pkg_check_modules(PC_GNI QUIET cray-gni-headers)

find_path(GNI_INCLUDE_DIR gni_pub.h
  HINTS ${PC_GNI_INCLUDEDIR} ${PC_GNI_INCLUDE_DIRS})

set(GNI_INCLUDE_DIRS ${GNI_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set GNI_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(GNI DEFAULT_MSG
                                  GNI_INCLUDE_DIR)

mark_as_advanced(GNI_INCLUDE_DIR)
