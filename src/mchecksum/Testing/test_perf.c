/*
 * Copyright (C) 2013-2019 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mchecksum.h"
#include "mchecksum_error.h"

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Maximum size of buffer used */
#define MAX_BUF_SIZE (1<<24)

/* Width of field used to report numbers */
#define FIELD_WIDTH 20

/* Precision of reported numbers */
#define FLOAT_PRECISION 2

#define BENCHMARK "MChecksum Perf Test"

#define MAX_LOOP 20

/* #define USE_MEMSET */

typedef struct my_time
{
    long tv_sec;
    long tv_usec;
} my_time_t;

/*---------------------------------------------------------------------------*/
static int
my_time_get_current(my_time_t *tv)
{
    int ret = 0;
    struct timespec tp;

    if (!tv) {
        ret = -1;
        return ret;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &tp)) {
        ret = -1;
        return ret;
    }
    tv->tv_sec = tp.tv_sec;
    tv->tv_usec = tp.tv_nsec / 1000;

    return ret;
}

/*---------------------------------------------------------------------------*/
static double
my_time_to_double(my_time_t tv)
{
    return (double) tv.tv_sec + (double) (tv.tv_usec) * 0.000001;
}

/*---------------------------------------------------------------------------*/
static my_time_t
my_time_add(my_time_t in1, my_time_t in2)
{
    my_time_t out;

    out.tv_sec = in1.tv_sec + in2.tv_sec;
    out.tv_usec = in1.tv_usec + in2.tv_usec;
    if(out.tv_usec > 1000000) {
        out.tv_usec -= 1000000;
        out.tv_sec += 1;
    }

    return out;
}

/*---------------------------------------------------------------------------*/
static my_time_t
my_time_subtract(my_time_t in1, my_time_t in2)
{
    my_time_t out;

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
main(int argc, char *argv[])
{
    mchecksum_object_t checksum;
    char *buf = NULL, *hash = NULL;
    size_t hash_size;
    const char *hash_method;
    unsigned int size;
    int ret = EXIT_SUCCESS;
    int i;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n%s [method]\n", argv[0]);
        ret = EXIT_FAILURE;
        goto done;
    }

    hash_method = argv[1];

    /* Initialize buf */
    buf = malloc(MAX_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "Could not allocate buffer\n");
        ret = EXIT_FAILURE;
        goto done;
    }
    for (i = 0; i < MAX_BUF_SIZE; i++) {
        buf[i] = (char) i;
    }

    fprintf(stdout, "# %s\n", BENCHMARK);
    fprintf(stdout, "%-*s%*s%*s\n", 10, "# Size", FIELD_WIDTH,
            "Bandwidth (MB/s)", FIELD_WIDTH, "Average Time (ms)");
    fflush(stdout);

    if (mchecksum_init(hash_method, &checksum) != MCHECKSUM_SUCCESS)
    {
       fprintf (stderr, "Error in mchecksum_init!\n");
       ret = EXIT_FAILURE;
       goto done;
    }

    hash_size = mchecksum_get_size(checksum);
    hash = malloc(hash_size);
    if (!hash) {
        fprintf(stderr, "Could not allocate hash\n");
        ret = EXIT_FAILURE;
        goto done;
    }

    /* Initialize the buffers */
    for (size = 1; size <= MAX_BUF_SIZE; size *= 2) {
        my_time_t t = {0, 0};

        for (i = 0; i < MAX_LOOP; i++) {
            my_time_t t_start = {0, 0}, t_end = {0, 0};

            mchecksum_reset(checksum);

            my_time_get_current(&t_start);
#ifdef USE_MEMSET
            memset(buf, 'B', size);
#else
            mchecksum_update(checksum, buf, size);
#endif
            my_time_get_current(&t_end);

            /* t = t + (t_end - t_start) */
            t = my_time_add(t, my_time_subtract(t_end, t_start));
        }

        fprintf(stdout, "%-*d%*.*f%*.*f\n", 10, size, FIELD_WIDTH,
                FLOAT_PRECISION, (size * MAX_LOOP) / (my_time_to_double(t) * 1e6),
                FIELD_WIDTH, FLOAT_PRECISION, my_time_to_double(t) * 1e3 / MAX_LOOP);
        fflush(stdout);
        mchecksum_get(checksum, hash, hash_size, MCHECKSUM_FINALIZE);
    }

    mchecksum_destroy(checksum);

done:
    free(hash);
    free(buf);

    return ret;
}
