/*
 * generic_client.h
 *
 *  Created on: Nov 6, 2012
 *      Author: soumagne
 */

#ifndef GENERIC_CLIENT_H
#define GENERIC_CLIENT_H

#include <stdint.h>

/* Op id describes the various generic operations (setattr, getattr etc.) */
typedef uint32_t generic_op_id_t;

/*
 * generic_op_status_t is used by the server to inform the client of the status
 * of the operation.
 */
typedef int32_t generic_op_status_t;

/* client request object */
typedef void *generic_request_id_t;

typedef enum {
    NA_BMI,
    NA_MPI
} generic_na_id_t;

#ifdef __cplusplus
extern "C" {
#endif

int generic_client_init(generic_na_id_t na_id);
int generic_client_finalize(void);

/*
 * int generic_client_register(const char *name, void (*in)(...),
 *   void (*out)(...), void (*encode)(...), void (*decode)(...));
 */

int generic_client_register();

int generic_client_forward(generic_op_id_t generic_op_id, generic_op_status_t *generic_op_status,
        generic_request_id_t *generic_request_id);
int generic_client_wait(generic_request_id_t generic_request_id);

#ifdef __cplusplus
}
#endif

#endif /* GENERIC_CLIENT_H */
