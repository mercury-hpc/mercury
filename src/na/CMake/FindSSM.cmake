#  Try to find SSM library and headers.
#  This file sets the following variables:
#
#  SSM_INCLUDE_DIR, where to find ssm.h, etc.
#  SSM_LIBRARIES, the libraries to link against
#  SSM_FOUND, If false, do not try to use SSM.
#
# Also defined, but not for general use are:
#  SSM_LIBRARY, the full path to the ssm library.

FIND_PATH( SSM_INCLUDE_DIR ssm.h
  /usr/local/include
  /usr/include
)

FIND_LIBRARY( SSM_LIBRARY NAMES ssm
  /usr/lib
  /usr/local/lib
)

SET( SSM_FOUND "NO" )
IF(SSM_INCLUDE_DIR)
  IF(SSM_LIBRARY)

    SET( SSM_LIBRARIES ${SSM_LIBRARY})
    SET( SSM_FOUND "YES" )

  ELSE(SSM_LIBRARY)
    IF(SSM_FIND_REQUIRED)
      message(SEND_ERROR "Unable to find the requested SSM libraries.")
    ENDIF(SSM_FIND_REQUIRED)
  ENDIF(SSM_LIBRARY)
ENDIF(SSM_INCLUDE_DIR)

MARK_AS_ADVANCED(
  SSM_INCLUDE_DIR
  SSM_LIBRARY
)
