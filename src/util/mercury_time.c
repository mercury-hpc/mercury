/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_time.h"
#include "mercury_util_error.h"

#if defined(_WIN32)
#    include <windows.h>
#elif defined(__APPLE__)
#    include <sys/time.h>
#    include <mach/mach_time.h>
#else
#    include <time.h>
#endif

#ifdef _WIN32
static LARGE_INTEGER
get_FILETIME_offset(void)
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;

    return t;
}
#endif

/*---------------------------------------------------------------------------*/
int
hg_time_get_current(hg_time_t *tv)
{
    int ret = HG_UTIL_SUCCESS;

#if defined(_WIN32)
    LARGE_INTEGER t;
    FILETIME f;
    double t_usec;
    static LARGE_INTEGER offset;
    static double freq_to_usec;
    static int initialized = 0;
    static BOOL use_perf_counter = 0;
#elif defined(__APPLE__)
    static uint64_t monotonic_timebase_factor = 0;
    uint64_t monotonic_nsec;
#else
    struct timespec tp;
#endif

    if (!tv) {
        HG_UTIL_ERROR_DEFAULT("NULL pointer to hg_time_t");
        ret = HG_UTIL_FAIL;
        return ret;
    }

#if defined(_WIN32)
    if (!initialized) {
        LARGE_INTEGER perf_freq;
        initialized = 1;
        use_perf_counter = QueryPerformanceFrequency(&perf_freq);
        if (use_perf_counter) {
            QueryPerformanceCounter(&offset);
            freq_to_usec = (double) perf_freq.QuadPart / 1000000.;
        } else {
            offset = get_FILETIME_offset();
            freq_to_usec = 10.;
        }
    }
    if (use_perf_counter) {
        QueryPerformanceCounter(&t);
    } else {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    t_usec = (double) t.QuadPart / freq_to_usec;
    t.QuadPart = t_usec;
    tv->tv_sec = t.QuadPart / 1000000;
    tv->tv_usec = t.QuadPart % 1000000;
#elif defined(__APPLE__)
    if (monotonic_timebase_factor == 0) {
        mach_timebase_info_data_t timebase_info;

        (void) mach_timebase_info(&timebase_info);
        monotonic_timebase_factor = timebase_info.numer / timebase_info.denom;
    }
    monotonic_nsec = (mach_absolute_time() * monotonic_timebase_factor);
    tv->tv_sec  = monotonic_nsec / 1000000000;
    tv->tv_usec = (monotonic_nsec - tv->tv_sec) / 1000;
#else
    if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
        HG_UTIL_ERROR_DEFAULT("clock_gettime failed");
        ret = HG_UTIL_FAIL;
        return ret;
    }
    tv->tv_sec = tp.tv_sec;
    tv->tv_usec = tp.tv_nsec / 1000;
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
double
hg_time_to_double(hg_time_t tv)
{
    return (double) tv.tv_sec + (double) (tv.tv_usec) * 0.000001;
}

/*---------------------------------------------------------------------------*/
hg_time_t
hg_time_from_double(double d)
{
    hg_time_t tv;

    tv.tv_sec = (long) d;
    tv.tv_usec = (long) ((d - (double) (tv.tv_sec)) * 1000000);

    return tv;
}

/*---------------------------------------------------------------------------*/
int
hg_time_less(hg_time_t in1, hg_time_t in2)
{
    return ((in1.tv_sec < in2.tv_sec) ||
            ((in1.tv_sec == in2.tv_sec) && (in1.tv_usec < in2.tv_usec)));
}

/*---------------------------------------------------------------------------*/
hg_time_t
hg_time_add(hg_time_t in1, hg_time_t in2)
{
    hg_time_t out;

    out.tv_sec = in1.tv_sec + in2.tv_sec;
    out.tv_usec = in1.tv_usec + in2.tv_usec;
    if(out.tv_usec > 1000000) {
        out.tv_usec -= 1000000;
        out.tv_sec += 1;
    }

    return out;
}

/*---------------------------------------------------------------------------*/
hg_time_t
hg_time_subtract(hg_time_t in1, hg_time_t in2)
{
    hg_time_t out;

    out.tv_sec = in1.tv_sec - in2.tv_sec;
    out.tv_usec = in1.tv_usec - in2.tv_usec;
    if(out.tv_usec < 0) {
        out.tv_usec += 1000000;
        out.tv_sec -= 1;
    }

    return out;
}

/*---------------------------------------------------------------------------*/
int
hg_time_sleep(const hg_time_t rqt, hg_time_t *rmt)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    DWORD dwMilliseconds = (DWORD) (hg_time_to_double(rqt) / 1000);

    Sleep(dwMilliseconds);
#else
    struct timespec rqtp;
    struct timespec rmtp;

    rqtp.tv_sec = rqt.tv_sec;
    rqtp.tv_nsec = rqt.tv_usec * 1000;

    if (nanosleep(&rqtp, &rmtp)) {
        HG_UTIL_ERROR_DEFAULT("nanosleep failed");
        ret = HG_UTIL_FAIL;
        return ret;
    }

    if (rmt) {
        rmt->tv_sec = rmtp.tv_sec;
        rmt->tv_usec = rmtp.tv_nsec / 1000;
    }
#endif

    return ret;
}

/*---------------------------------------------------------------------------*/
#define HG_UTIL_STAMP_MAX 128
char *
hg_time_stamp(void)
{
    char *ret = NULL;
    static char buf[HG_UTIL_STAMP_MAX];

#ifdef _WIN32
    /* TODO not implemented */
#else
    const char *time_format = "%a, %d %b %y %T %Z";
    struct tm *local_time;
    time_t t;

    t = time(NULL);
    local_time = localtime(&t);
    if (local_time == NULL) {
        HG_UTIL_ERROR_DEFAULT("Could not get local time");
        ret = NULL;
        return ret;
    }

    if (strftime(buf, HG_UTIL_STAMP_MAX, time_format, local_time) == 0) {
        HG_UTIL_ERROR_DEFAULT("Could not format time");
        ret = NULL;
        return ret;
    }

    ret = buf;
#endif

    return ret;
}
