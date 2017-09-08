/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_UTIL_ERROR_H
#define MERCURY_UTIL_ERROR_H

#include "mercury_util_config.h"

/* Default error macro */
#ifdef HG_UTIL_HAS_VERBOSE_ERROR
  #include <mercury_log.h>
  #define HG_UTIL_LOG_MODULE_NAME "HG Util"
  #define HG_UTIL_LOG_ERROR(...)                                \
      HG_LOG_WRITE_ERROR(HG_UTIL_LOG_MODULE_NAME, __VA_ARGS__)
  #define HG_UTIL_LOG_DEBUG(...)                                \
      HG_LOG_WRITE_DEBUG(HG_UTIL_LOG_MODULE_NAME, __VA_ARGS__)
  #define HG_UTIL_LOG_WARNING(...)                              \
      HG_LOG_WRITE_WARNING(HG_UTIL_LOG_MODULE_NAME, __VA_ARGS__)
#else
  #define HG_UTIL_LOG_ERROR(...) (void)0
  #define HG_UTIL_LOG_DEBUG(...) (void)0
  #define HG_UTIL_LOG_WARNING(...) (void)0
#endif

#endif /* MERCURY_UTIL_ERROR_H */
