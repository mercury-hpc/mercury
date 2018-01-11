/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_TEST_H
#define NA_TEST_H

#include "mercury_test_config.h"
#include "na.h"
#include "na_error.h"

#ifdef MERCURY_HAS_PARALLEL_TESTING
# include <mpi.h>
#endif

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

struct na_test_info {
    na_class_t *na_class;       /* NA class */
    char *target_name;          /* Target name */
    char *comm;                 /* Comm/Plugin name */
    char *protocol;             /* Protocol name */
    char *hostname;             /* Hostname */
    na_bool_t listen;           /* Listen */
    na_bool_t mpi_static;       /* MPI static comm */
    na_bool_t self_send;        /* Self send */
    na_bool_t auth;             /* Auth service */
    char *key;                  /* Auth key */
    int loop;                   /* Number of loops */
    na_bool_t busy_wait;        /* Busy wait */
    na_bool_t verbose;          /* Verbose mode */
    int max_number_of_peers;    /* Max number of peers */
#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Comm mpi_comm;          /* MPI comm */
    na_bool_t mpi_no_finalize;  /* Prevent from finalizing MPI */
#endif
    int mpi_comm_rank;          /* MPI comm rank */
    int mpi_comm_size;          /* MPI comm size */
    na_bool_t extern_init;      /* Extern init */
};

/*****************/
/* Public Macros */
/*****************/

#define NA_TEST_MAX_ADDR_NAME 256

/*********************/
/* Public Prototypes */
/*********************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Usage
 */
void
na_test_usage(const char *execname);

/**
 * Initialize
 */
na_return_t
NA_Test_init(int argc, char *argv[], struct na_test_info *na_test_info);

/**
 * Finalize
 */
na_return_t
NA_Test_finalize(struct na_test_info *na_test_info);

/**
 * Call MPI_Barrier if available
 */
void
NA_Test_barrier(struct na_test_info *na_test_info);

#ifdef __cplusplus
}
#endif

#endif /* NA_TEST_H */
