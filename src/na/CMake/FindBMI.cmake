#  Try to find BMI library and headers.
#  This file sets the following variables:
#
#  BMI_INCLUDE_DIR, where to find bmi.h, etc.
#  BMI_LIBRARIES, the libraries to link against
#  BMI_FOUND, If false, do not try to use BMI.
#
# Also defined, but not for general use are:
#  BMI_LIBRARY, the full path to the bmi library.

FIND_PATH( BMI_INCLUDE_DIR bmi.h
  /usr/local/include
  /usr/include
)

FIND_LIBRARY( BMI_LIBRARY NAMES bmi
  /usr/lib
  /usr/local/lib
)

SET( BMI_FOUND "NO" )
IF(BMI_INCLUDE_DIR)
  IF(BMI_LIBRARY)

    SET( BMI_LIBRARIES ${BMI_LIBRARY})
    SET( BMI_FOUND "YES" )

  ELSE(BMI_LIBRARY)
    IF(BMI_FIND_REQUIRED)
      message(SEND_ERROR "Unable to find the requested BMI libraries.")
    ENDIF(BMI_FIND_REQUIRED)
  ENDIF(BMI_LIBRARY)
ENDIF(BMI_INCLUDE_DIR)

MARK_AS_ADVANCED(
  BMI_INCLUDE_DIR
  BMI_LIBRARY
)
