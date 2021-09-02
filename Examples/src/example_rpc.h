/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "example_rpc_engine.h"

#ifndef EXAMPLE_RPC_H
#    define EXAMPLE_RPC_H

/* visible API for example RPC operation */

MERCURY_GEN_PROC(my_rpc_out_t, ((int32_t)(ret)))
MERCURY_GEN_PROC(my_rpc_in_t, ((int32_t)(input_val))((hg_bulk_t)(bulk_handle)))

hg_id_t
my_rpc_register(void);

#endif /* EXAMPLE_RPC_H */
