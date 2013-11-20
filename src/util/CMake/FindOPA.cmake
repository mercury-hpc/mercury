#  Try to find OPA library and headers.
#  This file sets the following variables:
#
#  OPA_INCLUDE_DIR, where to find opa_primitives.h, etc.
#  OPA_LIBRARIES, the libraries to link against
#  OPA_FOUND, If false, do not try to use OPA.
#
# Also defined, but not for general use are:
#  OPA_LIBRARY, the full path to the opa library.

FIND_PATH( OPA_INCLUDE_DIR opa_primitives.h
  /usr/local/include
  /usr/include
)

FIND_LIBRARY( OPA_LIBRARY NAMES opa
  /usr/lib
  /usr/local/lib
)

SET( OPA_FOUND "NO" )
IF(OPA_INCLUDE_DIR)
  IF(OPA_LIBRARY)

    SET( OPA_LIBRARIES ${OPA_LIBRARY})
    SET( OPA_FOUND "YES" )

  ELSE(OPA_LIBRARY)
    IF(OPA_FIND_REQUIRED)
      message(SEND_ERROR "Unable to find the requested OPA libraries.")
    ENDIF(OPA_FIND_REQUIRED)
  ENDIF(OPA_LIBRARY)
ENDIF(OPA_INCLUDE_DIR)

MARK_AS_ADVANCED(
  OPA_INCLUDE_DIR
  OPA_LIBRARY
)
