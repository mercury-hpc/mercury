/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury_log.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/* Make sure it executes first */
#ifdef HG_UTIL_HAS_ATTR_CONSTRUCTOR_PRIORITY
#    define HG_UTIL_CONSTRUCTOR_1 HG_ATTR_CONSTRUCTOR_PRIORITY(101)
#else
#    define HG_UTIL_CONSTRUCTOR_1
#endif

/* Destructor (used to finalize log outlets) */
#define HG_UTIL_DESTRUCTOR HG_ATTR_DESTRUCTOR

/* Name of the root log outlet */
#define HG_LOG_STRINGIFY(x)            HG_UTIL_STRINGIFY(x)
#define HG_LOG_OUTLET_ROOT_NAME_STRING HG_LOG_STRINGIFY(HG_LOG_OUTLET_ROOT_NAME)

/* Max number of subsystems that can be tracked */
#define HG_LOG_SUBSYS_MAX (16)

/* Max length of subsystem name (without trailing \0) */
#define HG_LOG_SUBSYS_NAME_MAX (16)

/* Log buffer size */
#define HG_LOG_BUF_MAX (256)

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

#ifdef _WIN32
#    define strtok_r strtok_s
#    undef strdup
#    define strdup     _strdup
#    define strcasecmp _stricmp
#endif

/********************/
/* Local Prototypes */
/********************/

/* Init logs */
static void
hg_log_init(void) HG_UTIL_CONSTRUCTOR_1;

/* Finalize logs */
static void
hg_log_finalize(void) HG_UTIL_DESTRUCTOR;

/* Init log level */
static void
hg_log_init_level(void);

/* Init log subsys */
static void
hg_log_init_subsys(void);

/* Reset all log levels */
static void
hg_log_outlet_reset_all(void);

/* Is log active */
static int
hg_log_outlet_active(const char *name);

/* Update log level of outlet */
static void
hg_log_outlet_update_level(struct hg_log_outlet *hg_log_outlet);

/* Update level of all outlets */
static void
hg_log_outlet_update_all(void);

/*******************/
/* Local Variables */
/*******************/

/* Default log outlet */
HG_LOG_OUTLET_DECL(HG_LOG_OUTLET_ROOT_NAME) = HG_LOG_OUTLET_INITIALIZER(
    HG_LOG_OUTLET_ROOT_NAME, HG_LOG_OFF, NULL, NULL);

/* List of all registered outlets */
static STAILQ_HEAD(, hg_log_outlet) hg_log_outlets_g = STAILQ_HEAD_INITIALIZER(
    hg_log_outlets_g);

/* Default 'printf' log function */
static hg_log_func_t hg_log_func_g = fprintf;

/* Default log level */
static enum hg_log_level hg_log_level_g = HG_LOG_LEVEL_NONE;

/* Default log subsystems */
static char hg_log_subsys_g[HG_LOG_SUBSYS_MAX][HG_LOG_SUBSYS_NAME_MAX + 1] = {
    {"\0"}};

/* Log level string table */
#define X(a, b, c, d) b,
static const char *const hg_log_level_name_g[] = {HG_LOG_LEVELS};
#undef X

/* Alt log level string table */
#define X(a, b, c, d) c,
static const char *const hg_log_level_alt_name_g[] = {HG_LOG_LEVELS};
#undef X

/* Standard log streams */
#ifdef _WIN32
#    define X(a, b, c, d) NULL,
#else
#    define X(a, b, c, d) d,
#endif
static FILE **const hg_log_std_streams_g[] = {HG_LOG_LEVELS};
#undef X
static FILE *hg_log_streams_g[HG_LOG_LEVEL_MAX] = {NULL};

/* Log colors */
#ifdef HG_UTIL_HAS_LOG_COLOR
static const char *const hg_log_colors_g[] = {"", HG_LOG_RED, HG_LOG_RED,
    HG_LOG_MAGENTA, HG_LOG_BLUE, HG_LOG_BLUE, HG_LOG_BLUE, ""};
#endif

/* Init */
#ifndef HG_UTIL_HAS_ATTR_CONSTRUCTOR_PRIORITY
static bool hg_log_init_g = false;
#endif

/*---------------------------------------------------------------------------*/
static void
hg_log_init(void)
{
    hg_log_init_level();
    hg_log_init_subsys();

    /* Register top outlet */
    hg_log_outlet_register(&HG_LOG_OUTLET(HG_LOG_OUTLET_ROOT_NAME));
}

/*---------------------------------------------------------------------------*/
static void
hg_log_finalize(void)
{
    /* Deregister top outlet */
    hg_log_outlet_deregister(&HG_LOG_OUTLET(HG_LOG_OUTLET_ROOT_NAME));
}

/*---------------------------------------------------------------------------*/
static void
hg_log_init_level(void)
{
    const char *log_level = getenv("HG_LOG_LEVEL");

    /* Override default log level */
    if (log_level == NULL)
        log_level = "fatal";

    hg_log_set_level(hg_log_name_to_level(log_level));
}

/*---------------------------------------------------------------------------*/
static void
hg_log_init_subsys(void)
{
    const char *log_subsys = getenv("HG_LOG_SUBSYS");

    if (log_subsys == NULL)
        log_subsys = HG_LOG_OUTLET_ROOT_NAME_STRING;

    // fprintf(stderr, "subsys: %s\n", log_subsys);
    hg_log_set_subsys(log_subsys);
}

/*---------------------------------------------------------------------------*/
static void
hg_log_outlet_reset_all(void)
{
    struct hg_log_outlet *outlet;
    int i;

    /* Reset levels */
    STAILQ_FOREACH (outlet, &hg_log_outlets_g, entry)
        outlet->level = HG_LOG_LEVEL_NONE;

    /* Reset subsys */
    for (i = 0; i < HG_LOG_SUBSYS_MAX; i++)
        strcpy(hg_log_subsys_g[i], "\0");
}

/*---------------------------------------------------------------------------*/
static int
hg_log_outlet_active(const char *name)
{
    int i = 0;

    while (hg_log_subsys_g[i][0] != '\0' && i < HG_LOG_SUBSYS_MAX) {
        /* Force a subsystem to be inactive */
        if ((hg_log_subsys_g[i][0] == '~') &&
            (strcmp(&hg_log_subsys_g[i][1], name) == 0))
            return -1;

        if (strcmp(hg_log_subsys_g[i], name) == 0) {
            return 1;
        }
        i++;
    }
    return 0;
}

/*---------------------------------------------------------------------------*/
static void
hg_log_outlet_update_level(struct hg_log_outlet *hg_log_outlet)
{
    int active = hg_log_outlet_active(hg_log_outlet->name);

    if (active > 0 || hg_log_outlet->state == HG_LOG_ON)
        hg_log_outlet->level = hg_log_level_g;
    else if (!(active < 0) && hg_log_outlet->state == HG_LOG_PASS &&
             hg_log_outlet->parent)
        hg_log_outlet->level = hg_log_outlet->parent->level;
    else
        hg_log_outlet->level = HG_LOG_LEVEL_NONE;
}

/*---------------------------------------------------------------------------*/
static void
hg_log_outlet_update_all(void)
{
    struct hg_log_outlet *hg_log_outlet;

    STAILQ_FOREACH (hg_log_outlet, &hg_log_outlets_g, entry)
        hg_log_outlet_update_level(hg_log_outlet);
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_level(enum hg_log_level log_level)
{
    hg_log_level_g = log_level;

    hg_log_outlet_update_all();
}

/*---------------------------------------------------------------------------*/
enum hg_log_level
hg_log_get_level(void)
{
    return hg_log_level_g;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_subsys(const char *log_subsys)
{
    char *subsys, *current, *next;
    int i = 0;

    subsys = strdup(log_subsys);
    if (!subsys)
        return;

    current = subsys;

    /* Reset all */
    hg_log_outlet_reset_all();

    /* Enable each of the subsys */
    while (strtok_r(current, ",", &next) && i < HG_LOG_SUBSYS_MAX) {
        int j, exist = 0;

        /* Skip duplicates */
        for (j = 0; j < i; j++) {
            if (strcmp(current, hg_log_subsys_g[j]) == 0) {
                exist = 1;
                break;
            }
        }

        if (!exist) {
            strncpy(hg_log_subsys_g[i], current, HG_LOG_SUBSYS_NAME_MAX);
            i++;
        }
        current = next;
    }

    /* Update outlets */
    hg_log_outlet_update_all();

    free(subsys);
}

/*---------------------------------------------------------------------------*/
const char *
hg_log_get_subsys(void)
{
    static char log_subsys[HG_LOG_SUBSYS_MAX * (HG_LOG_SUBSYS_NAME_MAX + 2)] =
        "\0";
    char *p = log_subsys;
    int i = 0;

    while (hg_log_subsys_g[i][0] != '\0' && i < HG_LOG_SUBSYS_MAX) {
        strcpy(p, hg_log_subsys_g[i]);
        p += strlen(hg_log_subsys_g[i]);
        *p = ',';
        p++;
        i++;
    }
    if (i > 0)
        *(p - 1) = '\0';

    return (const char *) log_subsys;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_subsys_level(const char *subsys, enum hg_log_level log_level)
{
    const char *log_subsys = hg_log_get_subsys();
    char *new_subsys = NULL;
    const char *new_subsys_ptr;

    if (strcmp(log_subsys, "") != 0) {
        new_subsys = malloc(strlen(log_subsys) + strlen(subsys) + 2);
        if (!new_subsys)
            return;
        strcpy(new_subsys, log_subsys);
        strcat(new_subsys, ",");
        strcat(new_subsys, subsys);
        new_subsys_ptr = new_subsys;
    } else
        new_subsys_ptr = subsys;

    hg_log_set_level(log_level);
    hg_log_set_subsys(new_subsys_ptr);

    free(new_subsys);
}

/*---------------------------------------------------------------------------*/
enum hg_log_level
hg_log_name_to_level(const char *log_level)
{
    enum hg_log_level l;

    if (!log_level || strcasecmp("none", log_level) == 0)
        return HG_LOG_LEVEL_NONE;

    for (l = HG_LOG_LEVEL_NONE; l != HG_LOG_LEVEL_MAX; l++)
        if ((strcasecmp(hg_log_level_name_g[l], log_level) == 0) ||
            (strcasecmp(hg_log_level_alt_name_g[l], log_level) == 0))
            break;

    if (l == HG_LOG_LEVEL_MAX) {
        fprintf(stderr,
            "Warning: invalid log level was passed, defaulting to none\n");
        return HG_LOG_LEVEL_NONE;
    }

    return l;
}

/*---------------------------------------------------------------------------*/
const char *
hg_log_level_to_string(enum hg_log_level level)
{
    return hg_log_level_name_g[level];
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_func(hg_log_func_t log_func)
{
    hg_log_func_g = log_func;
}

/*---------------------------------------------------------------------------*/
hg_log_func_t
hg_log_get_func(void)
{
    return hg_log_func_g;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_debug(FILE *stream)
{
    hg_log_streams_g[HG_LOG_LEVEL_DEBUG] = stream;
}

/*---------------------------------------------------------------------------*/
FILE *
hg_log_get_stream_debug(void)
{
    if (hg_log_streams_g[HG_LOG_LEVEL_DEBUG])
        return hg_log_streams_g[HG_LOG_LEVEL_DEBUG];
    else if (hg_log_std_streams_g[HG_LOG_LEVEL_DEBUG])
        return *hg_log_std_streams_g[HG_LOG_LEVEL_DEBUG];
    else
        return stdout;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_warning(FILE *stream)
{
    hg_log_streams_g[HG_LOG_LEVEL_WARNING] = stream;
}

/*---------------------------------------------------------------------------*/
FILE *
hg_log_get_stream_warning(void)
{
    if (hg_log_streams_g[HG_LOG_LEVEL_WARNING])
        return hg_log_streams_g[HG_LOG_LEVEL_WARNING];
    else if (hg_log_std_streams_g[HG_LOG_LEVEL_WARNING])
        return *hg_log_std_streams_g[HG_LOG_LEVEL_WARNING];
    else
        return stderr;
}

/*---------------------------------------------------------------------------*/
void
hg_log_set_stream_error(FILE *stream)
{
    hg_log_streams_g[HG_LOG_LEVEL_ERROR] = stream;
}

/*---------------------------------------------------------------------------*/
FILE *
hg_log_get_stream_error(void)
{
    if (hg_log_streams_g[HG_LOG_LEVEL_ERROR])
        return hg_log_streams_g[HG_LOG_LEVEL_ERROR];
    else if (hg_log_std_streams_g[HG_LOG_LEVEL_ERROR])
        return *hg_log_std_streams_g[HG_LOG_LEVEL_ERROR];
    else
        return stderr;
}

/*---------------------------------------------------------------------------*/
void
hg_log_outlet_register(struct hg_log_outlet *hg_log_outlet)
{
#ifndef HG_UTIL_HAS_ATTR_CONSTRUCTOR_PRIORITY
    if (!hg_log_init_g) {
        /* Set here to prevent infinite loop */
        hg_log_init_g = true;
        hg_log_init();
    }
#endif
    hg_log_outlet_update_level(hg_log_outlet);

    /* Inherit debug log if not set and parent has one */
    if (!hg_log_outlet->debug_log && hg_log_outlet->parent &&
        hg_log_outlet->parent->debug_log)
        hg_log_outlet->debug_log = hg_log_outlet->parent->debug_log;

    STAILQ_INSERT_TAIL(&hg_log_outlets_g, hg_log_outlet, entry);
    hg_log_outlet->registered = true;
}

/*---------------------------------------------------------------------------*/
void
hg_log_outlet_deregister(struct hg_log_outlet *hg_log_outlet)
{
    if (hg_log_outlet->debug_log &&
        !(hg_log_outlet->parent &&
            hg_log_outlet->parent->debug_log == hg_log_outlet->debug_log)) {
        if (hg_log_outlet->level >= HG_LOG_LEVEL_MIN_DEBUG) {
            FILE *stream = hg_log_streams_g[hg_log_outlet->level]
                               ? hg_log_streams_g[hg_log_outlet->level]
                               : *hg_log_std_streams_g[hg_log_outlet->level];
            hg_dlog_dump_counters(
                hg_log_outlet->debug_log, hg_log_func_g, stream, 0);
        }
        hg_dlog_free(hg_log_outlet->debug_log);
    }
    STAILQ_REMOVE(&hg_log_outlets_g, hg_log_outlet, hg_log_outlet, entry);
    hg_log_outlet->registered = false;
}

/*---------------------------------------------------------------------------*/
void
hg_log_dump_counters(struct hg_log_outlet *hg_log_outlet)
{
    if (hg_log_outlet->debug_log &&
        hg_log_outlet->level >= HG_LOG_LEVEL_MIN_DEBUG) {
        FILE *stream = hg_log_streams_g[hg_log_outlet->level]
                           ? hg_log_streams_g[hg_log_outlet->level]
                           : *hg_log_std_streams_g[hg_log_outlet->level];
        hg_dlog_dump_counters(
            hg_log_outlet->debug_log, hg_log_func_g, stream, 0);
    }
}

/*---------------------------------------------------------------------------*/
void
hg_log_write(struct hg_log_outlet *hg_log_outlet, enum hg_log_level log_level,
    const char *module, const char *file, unsigned int line, const char *func,
    bool no_return, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    hg_log_vwrite(hg_log_outlet, log_level, module, file, line, func, no_return,
        format, ap);
    va_end(ap);
}

/*---------------------------------------------------------------------------*/
void
hg_log_vwrite(struct hg_log_outlet *hg_log_outlet, enum hg_log_level log_level,
    const char *module, const char *file, unsigned int line, const char *func,
    bool no_return, const char *format, va_list ap)
{
    char buf[HG_LOG_BUF_MAX];
    FILE *stream = NULL;
    const char *level_name = NULL;
#ifdef HG_UTIL_HAS_LOG_COLOR
    const char *color = hg_log_colors_g[log_level];
#endif
    hg_time_t tv;

    if (!(log_level > HG_LOG_LEVEL_NONE && log_level < HG_LOG_LEVEL_MAX))
        return;

    hg_time_get_current(&tv);
    level_name = hg_log_level_name_g[log_level];
    if (hg_log_streams_g[log_level])
        stream = hg_log_streams_g[log_level];
    else if (hg_log_std_streams_g[log_level])
        stream = *hg_log_std_streams_g[log_level];
    else
        stream = (log_level > HG_LOG_LEVEL_ERROR) ? stdout : stderr;
#ifdef HG_UTIL_HAS_LOG_COLOR
    color = hg_log_colors_g[log_level];
#endif

    vsnprintf(buf, HG_LOG_BUF_MAX, format, ap);

#ifdef HG_UTIL_HAS_LOG_COLOR
    /* Print using logging function */
    hg_log_func_g(stream,
        "# %s%s[%lf] %s%s%s->%s%s: %s%s[%s]%s%s %s%s%s:%d %s\n"
        "## %s%s%s()%s: %s%s%s%s%s",
        HG_LOG_REG, HG_LOG_GREEN, hg_time_to_double(tv), HG_LOG_REG,
        HG_LOG_YELLOW, "mercury", hg_log_outlet->name, HG_LOG_RESET,
        HG_LOG_BOLD, color, level_name, HG_LOG_REG, color, module ? module : "",
        module ? ":" : "", file, line, HG_LOG_RESET, HG_LOG_REG, HG_LOG_YELLOW,
        func, HG_LOG_RESET, HG_LOG_REG,
        log_level != HG_LOG_LEVEL_DEBUG ? color : HG_LOG_RESET, buf,
        no_return ? "" : "\n", HG_LOG_RESET);
#else
    /* Print using logging function */
    hg_log_func_g(stream, "# [%lf] %s->%s [%s] %s%s%s:%d %s() %s%s",
        hg_time_to_double(tv), "mercury", hg_log_outlet->name, level_name,
        module ? module : "", module ? ":" : "", file, line, func, buf,
        no_return ? "" : "\n");
#endif

    if (log_level == HG_LOG_LEVEL_ERROR && hg_log_outlet->debug_log &&
        hg_log_outlet->level >= HG_LOG_LEVEL_MIN_DEBUG) {
        hg_dlog_dump(hg_log_outlet->debug_log, hg_log_func_g, stream, 0);
        hg_dlog_resetlog(hg_log_outlet->debug_log);
    }
}
