/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_ERROR_H
#define MERCURY_ERROR_H

#include "mercury_config.h"

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
#ifdef HG_HAS_VERBOSE_ERROR
  #include <stdio.h>
  #define HG_LOG_ERROR(...) do {                              \
      fprintf(stderr, "%s:%d: ERROR: ", __func__, __LINE__);  \
      fprintf(stderr, __VA_ARGS__);                           \
      fprintf(stderr, "\n");                                  \
  } while (0)
  #define HG_LOG_DEBUG(...) do {                       \
      fprintf(stdout, "%s:%d: ", __func__, __LINE__);  \
      fprintf(stdout, __VA_ARGS__);                    \
      fprintf(stdout, "\n");                           \
  } while (0)
  #define HG_LOG_WARNING(...) do {                              \
      fprintf(stdout, "%s:%d: WARNING: ", __func__, __LINE__);  \
      fprintf(stdout, __VA_ARGS__);                             \
      fprintf(stdout, "\n");                                    \
  } while (0)
#else
  #define HG_LOG_ERROR
  #define HG_LOG_DEBUG
  #define HG_LOG_WARNING
#endif

/* TODO remove that when switched to new macros */
#define HG_ERROR_DEFAULT   HG_LOG_ERROR
#define HG_WARNING_DEFAULT HG_LOG_DEBUG

#endif /* MERCURY_ERROR_H */
