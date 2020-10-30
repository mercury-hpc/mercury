/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_log.h"

#include <ctype.h>
#include <stdarg.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

#define HG_LOG_MAX_BUF 256

#ifdef HG_UTIL_HAS_LOG_COLOR
#    define HG_LOG_ESC     "\033"
#    define HG_LOG_RESET   HG_LOG_ESC "[0m"
#    define HG_LOG_REG     HG_LOG_ESC "[0;"
#    define HG_LOG_BOLD    HG_LOG_ESC "[1;"
#    define HG_LOG_RED     "31m"
#    define HG_LOG_GREEN   "32m"
#    define HG_LOG_YELLOW  "33m"
#    define HG_LOG_BLUE    "34m"
#    define HG_LOG_MAGENTA "35m"
#    define HG_LOG_CYAN    "36m"
#endif

/*******************/
/* Local Variables */
/*******************/

static int (*hg_log_func_g)(FILE *stream, const char *format, ...) = fprintf;

/* Log type string table */
#define X(a, b) b,
static const char *const hg_log_type_name[] = {HG_LOG_TYPES};
#undef X

/* Standard log streams */
static FILE **const hg_log_std_streams[] = {NULL, &stderr, &stdout, &stdout};

/* Log streams */
static FILE *hg_log_streams[] = {NULL, NULL, NULL, NULL};

/* Log colors */
#ifdef HG_UTIL_HAS_LOG_COLOR
static const char *const hg_log_colors[] = {
    "", HG_LOG_RED, HG_LOG_MAGENTA, HG_LOG_BLUE};
#endif

/*---------------------------------------------------------------------------*/
enum hg_log_type
hg_log_name_to_type(const char *log_name)
{
    enum hg_log_type t = 0;
    char log_name_low[8], *q;
    const char *p;
    int i;

    if (!log_name)
        return HG_LOG_TYPE_NONE;

    /* Make sure string is lower case */
    for (i = 0, p = log_name, q = log_name_low; *p != '\0' && i < 8;
         p++, q++, i++)
        *q = (char) tolower((unsigned char) *p);
    *q = '\0';

    while (strcmp(hg_log_type_name[t], log_name) && t != HG_LOG_TYPE_MAX)
        t++;

    return ((t == HG_LOG_TYPE_MAX) ? HG_LOG_TYPE_NONE : t);
}

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
    hg_log_streams[HG_LOG_TYPE_DEBUG] = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_warning(FILE *stream)
{
    hg_log_streams[HG_LOG_TYPE_WARNING] = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_error(FILE *stream)
{
    hg_log_streams[HG_LOG_TYPE_ERROR] = stream;
}

/*---------------------------------------------------------------------------*/
void
hg_log_write(enum hg_log_type log_type, const char *module, const char *file,
    unsigned int line, const char *func, const char *format, ...)
{
    char buf[HG_LOG_MAX_BUF];
    FILE *stream = NULL;
    const char *msg_type = NULL;
#ifdef HG_UTIL_HAS_LOG_COLOR
    const char *color = "";
#endif
    va_list ap;

    if (!(log_type > HG_LOG_TYPE_NONE && log_type < HG_LOG_TYPE_MAX))
        return;

    msg_type = hg_log_type_name[log_type];
    stream = hg_log_streams[log_type] ? hg_log_streams[log_type]
                                      : *hg_log_std_streams[log_type];
#ifdef HG_UTIL_HAS_LOG_COLOR
    color = hg_log_colors[log_type];
#endif

    va_start(ap, format);
    vsnprintf(buf, HG_LOG_MAX_BUF, format, ap);
    va_end(ap);

/* Print using logging function */
#ifdef HG_UTIL_HAS_LOG_COLOR
    hg_log_func_g(stream,
        "# %s%s[%s -- %s%s%s%s%s -- %s:%d]%s\n"
        "##    %s%s%s()%s: %s\n",
        HG_LOG_REG, color, module, HG_LOG_BOLD, color, msg_type, HG_LOG_REG,
        color, file, line, HG_LOG_RESET, HG_LOG_REG, HG_LOG_YELLOW, func,
        HG_LOG_RESET, buf);
#else
    hg_log_func_g(stream,
        "# %s -- %s -- %s:%d\n"
        " # %s(): %s\n",
        module, msg_type, file, line, func, buf);
#endif
}
