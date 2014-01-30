/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NA_MPI_H
#define NA_MPI_H

#include "na.h"

#include <mpi.h>

/* MPI initialization flags */
#define MPI_INIT_SERVER 0x01 /* set up to listen for unexpected messages */
#define MPI_INIT_STATIC 0x10 /* set up static inter-communicator */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the MPI plugin.
 *
 * \param intra_comm [IN]       (Optional) MPI communicator used for
 *                              intra-communication within a local set of
 *                              processes.
 * \param flags [IN]            (Optional) supported flags:
 *                                - MPI_INIT_SERVER
 *                                - MPI_INIT_STATIC
 *
 * \return Pointer to network class
 */
NA_EXPORT na_class_t *
NA_MPI_Init(MPI_Comm *intra_comm, int flags);

/**
 * Get port name used by server (only valid if plugin initialized with
 * MPI_INIT_SERVER).
 *
 * \return Pointer to string
 */
NA_EXPORT const char *
NA_MPI_Get_port_name(na_class_t *network_class);

#ifdef __cplusplus
}
#endif

#endif /* NA_MPI_H */
