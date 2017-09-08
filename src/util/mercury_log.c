/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_log.h"

#include <stdarg.h>

/****************/
/* Local Macros */
/****************/

#define HG_UTIL_LOG_MAX_BUF 256

/*******************/
/* Local Variables */
/*******************/

static int (*hg_log_func_g)(FILE *stream, const char *format, ...) = fprintf;
static FILE *hg_log_stream_debug_g = NULL;
static FILE *hg_log_stream_warning_g = NULL;
static FILE *hg_log_stream_error_g = NULL;

/*---------------------------------------------------------------------------*/
void
hg_log_set_func(int (*log_func)(FILE *stream, const char *format, ...))
{
    hg_log_func_g = log_func;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_debug(FILE *stream)
{
    hg_log_stream_debug_g = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_warning(FILE *stream)
{
    hg_log_stream_warning_g = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_error(FILE *stream)
{
    hg_log_stream_error_g = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_write(hg_log_type_t log_type, const char *module, const char *file,
    unsigned int line, const char *func, const char *format, ...)
{
    char buf[HG_UTIL_LOG_MAX_BUF];
    int desc_len;
    FILE *stream = NULL;
    const char *msg_type = NULL;
    va_list ap;

    switch (log_type) {
        case HG_LOG_TYPE_DEBUG:
            stream = hg_log_stream_debug_g ? hg_log_stream_debug_g : stdout;
            msg_type = "Debug";
            break;
        case HG_LOG_TYPE_WARNING:
            stream = hg_log_stream_warning_g ? hg_log_stream_warning_g : stdout;
            msg_type = "Warning";
            break;
        case HG_LOG_TYPE_ERROR:
            stream = hg_log_stream_error_g ? hg_log_stream_error_g : stderr;
            msg_type = "Error";
            break;
        default:
            return;
    };

    va_start(ap, format);
    desc_len = vsnprintf(buf, HG_UTIL_LOG_MAX_BUF, format, ap);
#ifdef HG_UTIL_HAS_VERBOSE_ERROR
    if (desc_len > HG_UTIL_LOG_MAX_BUF)
        /* Truncated */
        fprintf(stderr, "Warning, log message truncated\n");
#else
    (void) desc_len;
#endif
    va_end(ap);

    /* Print using logging function */
    hg_log_func_g(stream, "# %s -- %s -- %s:%d\n"
        " # %s(): %s\n", module, msg_type, file, line, func, buf);
}
