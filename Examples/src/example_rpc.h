/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
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
