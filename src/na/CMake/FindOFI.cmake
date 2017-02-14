# - Try to find OFI
# Once done this will define
#  OFI_FOUND - System has OFI
#  OFI_INCLUDE_DIRS - The OFI include directories
#  OFI_LIBRARIES - The libraries needed to use OFI

find_path(OFI_INCLUDE_DIR rdma/fabric.h
  HINTS /usr/local/include /usr/include)

find_library(OFI_LIBRARY NAMES fabric
  PATHS /usr/local/lib /usr/lib)

set(OFI_INCLUDE_DIRS ${OFI_INCLUDE_DIR})
set(OFI_LIBRARIES ${OFI_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set OFI_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(OFI DEFAULT_MSG
                                  OFI_INCLUDE_DIR OFI_LIBRARY)

mark_as_advanced(OFI_INCLUDE_DIR OFI_LIBRARY)
