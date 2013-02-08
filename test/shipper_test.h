/*
 * shipper_test.h
 */

#ifndef SHIPPER_TEST_H
#define SHIPPER_TEST_H

#include "network_abstraction.h"

#define ION_ENV "ZOIDFS_ION_NAME"

#ifdef __cplusplus
extern "C" {
#endif

na_network_class_t *shipper_test_client_init(int argc, char *argv[]);

na_network_class_t *shipper_test_server_init(int argc, char *argv[], unsigned int *max_number_of_peers);

#ifdef __cplusplus
}
#endif

#endif /* SHIPPER_TEST_H */
