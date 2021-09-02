/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "example_rpc.h"
#include "example_rpc_engine.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

/* example server program.  Starts HG engine, registers the example RPC type,
 * and then executes indefinitely.
 */

int
main(void)
{
    hg_engine_init(NA_TRUE, "tcp://12345");

    hg_engine_print_self_addr();

    /* register RPC */
    my_rpc_register();

    /* this would really be something waiting for shutdown notification */
    while (1)
        sleep(1);

    hg_engine_finalize();

    return (0);
}
