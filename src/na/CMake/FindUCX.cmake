# - Try to find UCX
# Once done this will define
#  UCX_FOUND - System has UCX
#  UCX_INCLUDE_DIRS - The UCX include directories
#  UCX_LIBRARIES - The libraries needed to use UCX

find_package(PkgConfig)
pkg_check_modules(PC_UCX QUIET ucx)

find_path(UCX_INCLUDE_DIR ucp/api/ucp.h
  HINTS ${PC_UCX_INCLUDEDIR} ${PC_UCX_INCLUDE_DIRS})

find_library(UCP_LIBRARY NAMES ucp
  HINTS ${PC_UCX_LIBDIR} ${PC_UCX_LIBRARY_DIRS})

find_library(UCT_LIBRARY NAMES uct
  HINTS ${PC_UCX_LIBDIR} ${PC_UCX_LIBRARY_DIRS})

find_library(UCS_LIBRARY NAMES ucs
  HINTS ${PC_UCX_LIBDIR} ${PC_UCX_LIBRARY_DIRS})

set(UCX_INCLUDE_DIRS ${UCX_INCLUDE_DIR})
set(UCX_LIBRARIES ${UCP_LIBRARY} ${UCT_LIBRARY} ${UCS_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set UCX_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(UCX DEFAULT_MSG
                                  UCX_INCLUDE_DIR
				  UCP_LIBRARY UCT_LIBRARY UCS_LIBRARY)

mark_as_advanced(UCX_INCLUDE_DIR UCP_LIBRARY UCT_LIBRARY UCS_LIBRARY)

