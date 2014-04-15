/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_RPC_CB_H
#define MERCURY_RPC_CB_H

hg_return_t
rpc_open_cb(hg_handle_t handle);

hg_return_t
bulk_write_cb(hg_handle_t handle);

hg_return_t
bulk_seg_write(hg_handle_t handle);

#endif /* MERCURY_RPC_CB_H */
