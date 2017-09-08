/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_ERROR_H
#define NA_ERROR_H

#include "na_config.h"

/* Default error macro */
#ifdef NA_HAS_VERBOSE_ERROR
  #include <mercury_log.h>
  #define NA_LOG_MODULE_NAME "NA"
  #define NA_LOG_ERROR(...)                                 \
      HG_LOG_WRITE_ERROR(NA_LOG_MODULE_NAME, __VA_ARGS__)
  #define NA_LOG_DEBUG(...)                                 \
      HG_LOG_WRITE_DEBUG(NA_LOG_MODULE_NAME, __VA_ARGS__)
  #define NA_LOG_WARNING(...)                               \
      HG_LOG_WRITE_WARNING(NA_LOG_MODULE_NAME, __VA_ARGS__)
#else
  #define NA_LOG_ERROR(...) (void)0
  #define NA_LOG_DEBUG(...) (void)0
  #define NA_LOG_WARNING(...) (void)0
#endif

#endif /* NA_ERROR_H */
