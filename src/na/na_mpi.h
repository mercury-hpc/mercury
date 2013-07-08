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

/* MPI initialization flags */
enum {
    MPI_INIT_SERVER = 1,    /* set up to listen for unexpected messages */
    MPI_INIT_SERVER_STATIC, /* set up static inter-communicator */
    MPI_INIT_STATIC         /* set up static inter-communicator */
};

#include <mpi.h>

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
 *                                - MPI_INIT_SERVER_STATIC
 *                                - MPI_INIT_STATIC
 *
 * \return Pointer to network class
 */
NA_EXPORT na_class_t *
NA_MPI_Init(MPI_Comm *intra_comm, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NA_MPI_H */
