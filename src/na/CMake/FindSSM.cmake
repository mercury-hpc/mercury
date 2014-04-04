# - Try to find SSM
# Once done this will define
#  SSM_FOUND - System has SSM
#  SSM_INCLUDE_DIRS - The SSM include directories
#  SSM_LIBRARIES - The libraries needed to use SSM

find_path(SSM_INCLUDE_DIR ssm.h
  HINTS /usr/local/include /usr/include)

find_path(SSM_DUMB_INCLUDE_DIR dumb.h
  HINTS /usr/local/include /usr/include
  PATH_SUFFIXES ssm)

find_path(SSM_PTCP_INCLUDE_DIR ssmptcp.h
  HINTS /usr/local/include /usr/include)

find_library(SSM_PTCP_LIBRARY NAMES ssmptcp
  PATHS /usr/local/lib /usr/lib)

find_library(SSM_LIBRARY NAMES ssm
  PATHS /usr/local/lib /usr/lib)

set(SSM_INCLUDE_DIRS ${SSM_INCLUDE_DIR} ${SSM_DUMB_INCLUDE_DIR}
  ${SSM_PTCP_INCLUDE_DIR})
set(SSM_LIBRARIES ${SSM_PTCP_LIBRARY} ${SSM_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SSM_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(SSM DEFAULT_MSG
                                  SSM_INCLUDE_DIR SSM_DUMB_INCLUDE_DIR
                                  SSM_LIBRARY)

mark_as_advanced(SSM_INCLUDE_DIR SSM_DUMB_INCLUDE_DIR SSM_PTCP_INCLUDE_DIR
  SSM_PTCP_LIBRARY SSM_LIBRARY)
