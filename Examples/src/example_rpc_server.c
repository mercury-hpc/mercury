/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "example_rpc_engine.h"
#include "example_rpc.h"

/* example server program.  Starts HG engine, registers the example RPC type,
 * and then executes indefinitely.
 */

int main(void)
{
    hg_engine_init(NA_TRUE, "tcp://1234");

    /* register RPC */
    my_rpc_register();

    /* this would really be something waiting for shutdown notification */
    while(1)
        sleep(1);

    hg_engine_finalize();

    return(0);
}

