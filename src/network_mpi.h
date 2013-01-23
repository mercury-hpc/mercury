/*
 * network_mpi.h
 *
 *  Created on: Nov 5, 2012
 *      Author: soumagne
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

void na_mpi_init(MPI_Comm *intra_comm, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_MPI_H */
