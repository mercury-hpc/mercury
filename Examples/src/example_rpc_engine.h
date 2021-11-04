/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mercury.h>
#include <mercury_bulk.h>
#include <mercury_macros.h>

/* example_rpc_engine: API of generic utilities and progress engine hooks that
 * are reused across many RPC functions.  init and finalize() manage a
 * dedicated thread that will drive all HG progress
 */

#ifndef EXAMPLE_RPC_ENGINE_H
#    define EXAMPLE_RPC_ENGINE_H

void
hg_engine_init(hg_bool_t listen, const char *local_addr);
void
hg_engine_finalize(void);
hg_class_t *
hg_engine_get_class(void);
void
hg_engine_print_self_addr(void);
void
hg_engine_addr_lookup(const char *name, hg_addr_t *addr);
void
hg_engine_addr_free(hg_addr_t addr);
void
hg_engine_create_handle(hg_addr_t addr, hg_id_t id, hg_handle_t *handle);

#endif /* EXAMPLE_RPC_ENGINE_H */
