/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "test_posix.h"
#include "mercury_test.h"
#include "mercury.h"
#include "mercury_bulk.h"

#ifndef MERCURY_HAS_ADVANCED_MACROS
na_addr_t addr;
na_class_t *network_class = NULL;
hg_id_t open_id, write_id, read_id, close_id, finalize_id;

int init_rpc(int argc, char *argv[], int *rank)
{
    int hg_ret, na_ret;
    int ret = HG_SUCCESS;
    char *ion_name;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = HG_Test_client_init(argc, argv, rank);

    ion_name = getenv(MERCURY_PORT_NAME);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", MERCURY_PORT_NAME);
    }

    hg_ret = HG_Init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper\n");
        ret = HG_FAIL;
        return ret;
    }

    hg_ret = HG_Bulk_init(network_class);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        ret = HG_FAIL;
        return ret;
    }

    /* Look up addr id */
    na_ret = NA_Addr_lookup(network_class, ion_name, &addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        ret = HG_FAIL;
        return ret;
    }

    /* Register function and encoding/decoding functions */
    open_id = MERCURY_REGISTER("open", open_in_t, open_out_t);
    write_id = MERCURY_REGISTER("write", write_in_t, write_out_t);
    read_id = MERCURY_REGISTER("read", read_in_t, read_out_t);
    close_id = MERCURY_REGISTER("close", close_in_t, close_out_t);
    finalize_id = MERCURY_REGISTER_FINALIZE();

    return ret;
}

int finalize_rpc()
{
    int hg_ret, na_ret;
    int ret = HG_SUCCESS;
    hg_request_t request;
    hg_status_t status;
    int finalize_ret;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(addr, finalize_id, NULL, NULL, &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        finalize_ret = HG_FAIL;
        return finalize_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        finalize_ret = HG_FAIL;
        return finalize_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        finalize_ret = HG_FAIL;
        return finalize_ret;
    }

    /* Free addr id */
    na_ret = NA_Addr_free(network_class, addr);
    if (na_ret != NA_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        ret = HG_FAIL;
        return ret;
    }

    /* Finalize interface */
    hg_ret = HG_Finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper\n");
        ret = HG_FAIL;
        return ret;
    }

    hg_ret = HG_Bulk_finalize();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        ret = HG_FAIL;
        return ret;
    }

    return ret;
}

int open_rpc(const char *pathname, int flags, mode_t mode)
{
    open_in_t  open_in_struct;
    open_out_t open_out_struct;
    hg_request_t request;
    hg_status_t status;
    int hg_ret;
    int open_ret;

    /* Fill input structure */
    open_in_struct.path = pathname;
    open_in_struct.flags = flags;
    open_in_struct.mode = mode;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(addr, open_id, &open_in_struct,
            &open_out_struct, &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        open_ret = HG_FAIL;
        return open_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        open_ret = HG_FAIL;
        return open_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        open_ret = HG_FAIL;
        return open_ret;
    }

    /* Get output parameters */
    open_ret = open_out_struct.ret;

    return open_ret;
}

int close_rpc(int fd)
{
    close_in_t  close_in_struct;
    close_out_t close_out_struct;
    hg_request_t request;
    hg_status_t status;
    int hg_ret;
    int close_ret;

    /* Fill input structure */
    close_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(addr, close_id, &close_in_struct,
            &close_out_struct, &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        close_ret = HG_FAIL;
        return close_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        close_ret = HG_FAIL;
        return close_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        close_ret = HG_FAIL;
        return close_ret;
    }

    /* Get output parameters */
    close_ret = close_out_struct.ret;

    return close_ret;
}

ssize_t write_rpc(int fd, const void *buf, size_t count)
{
    write_in_t  write_in_struct;
    write_out_t write_out_struct;

    hg_bulk_t bulk_handle;
    hg_request_t request;
    hg_status_t status;
    int hg_ret;
    int write_ret;

    /* Register memory */
    hg_ret = HG_Bulk_handle_create((void*)buf, count, HG_BULK_READ_ONLY, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        write_ret = HG_FAIL;
        return write_ret;
    }

    /* Fill input structure */
    write_in_struct.bulk_handle = bulk_handle;
    write_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(addr, write_id, &write_in_struct, &write_out_struct, &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        write_ret = HG_FAIL;
        return write_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        write_ret = HG_FAIL;
        return write_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        write_ret = HG_FAIL;
        return write_ret;
    }

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        write_ret = HG_FAIL;
        return write_ret;
    }

    /* Get output parameters */
    write_ret = write_out_struct.ret;

    return write_ret;
}

ssize_t read_rpc(int fd, void *buf, size_t count)
{
    read_in_t  read_in_struct;
    read_out_t read_out_struct;

    hg_bulk_t bulk_handle;
    hg_request_t request;
    hg_status_t status;
    int hg_ret;
    int read_ret;

    /* Register memory */
    hg_ret = HG_Bulk_handle_create(buf, count, HG_BULK_READWRITE, &bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        read_ret = HG_FAIL;
        return read_ret;
    }

    /* Fill input structure */
    read_in_struct.bulk_handle = bulk_handle;
    read_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    hg_ret = HG_Forward(addr, read_id, &read_in_struct, &read_out_struct, &request);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        read_ret = HG_FAIL;
        return read_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    hg_ret = HG_Wait(request, HG_MAX_IDLE_TIME, &status);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        read_ret = HG_FAIL;
        return read_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        read_ret = HG_FAIL;
        return read_ret;
    }

    /* Free memory handle */
    hg_ret = HG_Bulk_handle_free(bulk_handle);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        read_ret = HG_FAIL;
        return read_ret;
    }

    /* Get output parameters */
    read_ret = read_out_struct.ret;

    return read_ret;
}

#endif

#undef open
#define open open_rpc
#undef read
#define read read_rpc
#undef write
#define write write_rpc
#undef close
#define close close_rpc

/******************************************************************************/
int main(int argc, char *argv[])
{
    int ret;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    char filename[256];
    int fd = 0;
    int *read_buf = NULL;
    int *write_buf = NULL;
    size_t n_ints = 1024*1024;
    unsigned int i;
    int error = 0;
    int rank;
    ssize_t nbyte;

#ifndef MERCURY_HAS_ADVANCED_MACROS
    int hg_ret;

    printf("Initializing...\n");
    hg_ret = init_rpc(argc, argv, &rank);
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error in client_posix_init\n");
        return EXIT_FAILURE;
    }
#endif
    sprintf(filename, "posix_test%d", rank);

    /* Prepare buffers */
    write_buf = malloc(sizeof(int) * n_ints);
    read_buf =  malloc(sizeof(int) * n_ints);
    for (i = 0; i < n_ints; i++) {
        write_buf[i] = i;
        read_buf[i] = 0;
    }

    printf("(%d) Creating file...\n", rank);

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "Error in fs_open\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Writing data...\n", rank);

    nbyte = write(fd, write_buf, sizeof(int) * n_ints);
    if (nbyte <= 0) {
        fprintf(stderr, "Error detected in client_posix_write\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Closing file...\n", rank);

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "Error detected in client_posix_close\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Opening file...\n", rank);

    fd = open(filename, O_RDONLY, mode);
    if (fd < 0) {
        fprintf(stderr, "Error in fs_open\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Reading data...\n", rank);

    nbyte = read(fd, read_buf, sizeof(int) * n_ints);
    if (nbyte < 0) {
        fprintf(stderr, "Error detected in client_posix_read\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Closing file...\n", rank);

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "Error detected in client_posix_close\n");
        return EXIT_FAILURE;
    }

    printf("(%d) Checking data...\n", rank);

    /* Check bulk buf */
    for (i = 0; i < n_ints; i++) {
        if (read_buf[i] != write_buf[i]) {
            printf("(%d) Error detected in bulk transfer, read_buf[%d] = %d, was expecting %d!\n",
                    rank, i, read_buf[i], write_buf[i]);
            error = 1;
            break;
        }
    }
    if (!error) printf("(%d) Successfully transferred %lu bytes!\n", rank, nbyte);

    /* Free bulk data */
    free(write_buf);
    free(read_buf);

#ifndef MERCURY_HAS_ADVANCED_MACROS
    printf("(%d) Finalizing...\n", rank);

    hg_ret = finalize_rpc();
    if (hg_ret != HG_SUCCESS) {
        fprintf(stderr, "Error in client_posix_finalize\n");
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}
