/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_ERROR_H
#define NA_ERROR_H

#include "na_config.h"

/* For compatibility */
#if defined(__STDC_VERSION__) &&  (__STDC_VERSION__ < 199901L)
  #if defined(__GNUC__) && (__GNUC__ >= 2)
    #define __func__ __FUNCTION__
  #else
    #define __func__ "<unknown>"
  #endif
#elif defined(_WIN32)
  #define __func__ __FUNCTION__
#endif

/* Default error macro */
#ifdef NA_HAS_VERBOSE_ERROR
  #include <stdio.h>
  #define NA_LOG_ERROR(...) do {                                            \
      fprintf(stderr, "NA: Error in %s:%d\n", __FILE__, __LINE__);          \
      fprintf(stderr, " # %s(): ", __func__);                               \
      fprintf(stderr, __VA_ARGS__);                                         \
      fprintf(stderr, "\n");                                                \
  } while (0)
  #define NA_LOG_DEBUG(...) do {                                \
      fprintf(stdout, "NA: in %s:%d\n", __FILE__, __LINE__);    \
      fprintf(stdout, " # %s(): ", __func__);                   \
      fprintf(stdout, __VA_ARGS__);                             \
      fprintf(stdout, "\n");                                    \
  } while (0)
  #define NA_LOG_WARNING(...) do {                                      \
      fprintf(stdout, "NA: Warning in %s:%d\n", __FILE__, __LINE__);    \
      fprintf(stdout, " # %s(): ", __func__);                           \
      fprintf(stdout, __VA_ARGS__);                                     \
      fprintf(stdout, "\n");                                            \
  } while (0)
#else
  #define NA_LOG_ERROR
  #define NA_LOG_DEBUG
  #define NA_LOG_WARNING
#endif

#endif /* NA_ERROR_H */
