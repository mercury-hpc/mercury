/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_TEST_H
#define MERCURY_TEST_H

#include "na.h"
#include "mercury_test_config.h"
#include "mercury_config.h"
#include "mercury_bulk.h"

#include "test_rpc.h"
#include "test_bulk.h"
#include "test_posix.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize client
 */
hg_return_t
HG_Test_client_init(int argc, char *argv[], na_addr_t *addr, int *rank);

/**
 * Initialize server
 */
hg_return_t
HG_Test_server_init(int argc, char *argv[], char ***addr_table,
        unsigned int *addr_table_size, unsigned int *max_number_of_peers);

/**
 * Finalize client/server
 */
hg_return_t
HG_Test_finalize(void);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_TEST_H */
