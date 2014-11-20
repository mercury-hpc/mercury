/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set MPI intra_comm used when initializing the MPI plugin.
 *
 * \param intra_comm [IN]       MPI communicator used for
 *                              intra-communication within a local set of
 *                              processes.
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
NA_EXPORT na_return_t
NA_MPI_Set_init_intra_comm(MPI_Comm intra_comm);

/**
 * Get port name used by server (only valid if plugin initialized with
 * MPI_INIT_SERVER).
 *
 * \param na_class [IN]         pointer to NA class
 *
 * \return Pointer to string
 */
NA_EXPORT const char *
NA_MPI_Get_port_name(
        na_class_t *na_class
        );

/**
 * Setup the Aries NIC resources for the job when NA MPI is used with
 * Cray MPI without ALPS support.
 *
 * \return NA_SUCCESS or corresponding NA error code
 */
#ifdef NA_MPI_HAS_GNI_SETUP
NA_EXPORT na_return_t
NA_MPI_Gni_job_setup(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NA_MPI_H */
