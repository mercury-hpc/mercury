/*
 * client_bds.c
 */

#include "function_shipper.h"
#include "bulk_data_shipper.h"
#include "bulk_data_proc.h"
#include "generic_macros.h"
#include "shipper_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Dummy function that needs to be shipped:
 * size_t bla_write(int fildes, const void *buf, size_t nbyte);
 */

/*****************************************************************************/
/* Generate processor for input/output structs
 * IOFSL_SHIPPER_GEN_PROC( struct type name, members )
 *****************************************************************************/
IOFSL_SHIPPER_GEN_PROC( bla_write_in_t, ((int32_t)(fildes)) ((bds_handle_t)(bds_handle)) )
IOFSL_SHIPPER_GEN_PROC( bla_write_out_t, ((uint64_t)(ret)) )

/******************************************************************************/
int main(int argc, char *argv[])
{
    char *ion_name;
    na_addr_t addr;
    na_network_class_t *network_class = NULL;

    /* dummy function parameters */
    int fildes = 12345;
    int *bulk_buf = NULL;
    int bulk_size = 1024*1024;

    fs_id_t bla_write_id;
    bla_write_in_t bla_write_in_struct;
    bla_write_out_t bla_write_out_struct;
    fs_request_t bla_write_request;
    int bla_write_ret = 0;

    bds_handle_t bla_bulk_handle = NULL;

    int i;

    /* Prepare bulk_buf */
    bulk_buf = malloc(sizeof(int) * bulk_size);
    for (i = 0; i < bulk_size; i++) {
        bulk_buf[i] = i;
    }

    /* Initialize the interface */
    network_class = shipper_test_client_init(argc, argv);
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
    }

    fs_init(network_class);
    bds_init(network_class);

    /* Look up addr id */
    na_addr_lookup(network_class, ion_name, &addr);

    /* Register function and encoding/decoding functions */
    bla_write_id = fs_register("bla_write", fs_proc_bla_write_in_t, fs_proc_bla_write_out_t);

    /* Register memory */
    bds_handle_create(bulk_buf, sizeof(int) * bulk_size, BDS_READ_ONLY,
            &bla_bulk_handle);

    /* Fill input structure */
    bla_write_in_struct.fildes = fildes;
    bla_write_in_struct.bds_handle = bla_bulk_handle;

    /* Forward call to addr */
    fs_forward(addr, bla_write_id, &bla_write_in_struct, &bla_write_out_struct, &bla_write_request);

    /* Wait for call to be executed and return value to be sent back */
    fs_wait(bla_write_request, FS_MAX_IDLE_TIME, FS_STATUS_IGNORE);

    /* Get output parameter */
    bla_write_ret = bla_write_out_struct.ret;

    printf("bla_write returned: %d\n", bla_write_ret);

    /* Free memory handle */
    bds_handle_free(bla_bulk_handle);

    /* Free bulk data */
    free(bulk_buf);

    /* Free addr id */
    na_addr_free(network_class, addr);

    /* Finalize interface */
    fs_finalize();
    bds_finalize();
    return EXIT_SUCCESS;
}
