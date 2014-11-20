/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_TEST_H
#define NA_TEST_H

#include "na.h"
#include "mercury_test_config.h"

#define NA_TEST_MAX_ADDR_NAME 256

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize client
 */
na_class_t *
NA_Test_client_init(int argc, char *argv[], char *addr_name,
        na_size_t max_addr_name, int *rank);

/**
 * Initialize server
 */
na_class_t *
NA_Test_server_init(int argc, char *argv[], na_bool_t print_ready,
        char ***addr_table, unsigned int *addr_table_size,
        unsigned int *max_number_of_peers);

/**
 * Finalize client/server
 */
na_return_t
NA_Test_finalize(na_class_t *na_class);

/**
 * Call MPI_Barrier if available
 */
void
NA_Test_barrier(void);

#ifdef __cplusplus
}
#endif

#endif /* NA_TEST_H */
