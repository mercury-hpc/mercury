/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    and UChicago Argonne, LLC.
 * Copyright (C) 2013 The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef NETWORK_MPI_H
#define NETWORK_MPI_H

#include "network_abstraction.h"

/* MPI initialization flags */
enum {
    MPI_INIT_SERVER = 1 /* set up to listen for unexpected messages */
};

#include <mpi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the MPI plugin */
na_network_class_t *na_mpi_init(MPI_Comm *intra_comm, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_MPI_H */
