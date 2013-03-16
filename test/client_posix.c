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

#include "test_posix.h"
#include "shipper_test.h"
#include "function_shipper.h"
#include "bulk_data_shipper.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

na_addr_t addr;
na_network_class_t *network_class = NULL;
fs_id_t open_id, write_id, read_id, close_id;

int client_posix_init(int argc, char *argv[])
{
    int fs_ret;
    int ret = S_SUCCESS;
    char *ion_name;

    /* Initialize the interface (for convenience, shipper_test_client_init
     * initializes the network interface with the selected plugin)
     */
    network_class = shipper_test_client_init(argc, argv);

    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
        ret = S_FAIL;
        return ret;
    }

    fs_ret = fs_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper\n");
        ret = S_FAIL;
        return ret;
    }

    fs_ret = bds_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        ret = S_FAIL;
        return ret;
    }

    /* Look up addr id */
    fs_ret = na_addr_lookup(network_class, ion_name, &addr);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not find addr %s\n", ion_name);
        ret = S_FAIL;
        return ret;
    }

    /* Register function and encoding/decoding functions */
    open_id = IOFSL_SHIPPER_REGISTER("open", open_in_t, open_out_t);
    write_id = IOFSL_SHIPPER_REGISTER("write", write_in_t, write_out_t);
    read_id = IOFSL_SHIPPER_REGISTER("read", read_in_t, read_out_t);
    close_id = IOFSL_SHIPPER_REGISTER("close", close_in_t, close_out_t);

    return ret;
}

int client_posix_finalize()
{
    int fs_ret;
    int ret = S_SUCCESS;

    /* Free addr id */
    fs_ret = na_addr_free(network_class, addr);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free addr\n");
        ret = S_FAIL;
        return ret;
    }

    /* Finalize interface */
    fs_ret = fs_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper\n");
        ret = S_FAIL;
        return ret;
    }

    fs_ret = bds_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        ret = S_FAIL;
        return ret;
    }

    return ret;
}

int client_posix_open(const char *pathname, int flags, mode_t mode)
{
    open_in_t  open_in_struct;
    open_out_t open_out_struct;
    fs_request_t request;
    fs_status_t status;
    int fs_ret;
    int open_ret;

    /* Fill input structure */
    open_in_struct.path = pathname;
    open_in_struct.flags = flags;
    open_in_struct.mode = mode;

    /* Forward call to remote addr and get a new request */
    fs_ret = fs_forward(addr, open_id, &open_in_struct,
            &open_out_struct, &request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        open_ret = S_FAIL;
        return open_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(request, FS_MAX_IDLE_TIME, &status);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        open_ret = S_FAIL;
        return open_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        open_ret = S_FAIL;
        return open_ret;
    }

    /* Get output parameters */
    open_ret = open_out_struct.ret;

    return open_ret;
}

int client_posix_close(int fd)
{
    close_in_t  close_in_struct;
    close_out_t close_out_struct;
    fs_request_t request;
    fs_status_t status;
    int fs_ret;
    int close_ret;

    /* Fill input structure */
    close_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    fs_ret = fs_forward(addr, close_id, &close_in_struct,
            &close_out_struct, &request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        close_ret = S_FAIL;
        return close_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(request, FS_MAX_IDLE_TIME, &status);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        close_ret = S_FAIL;
        return close_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        close_ret = S_FAIL;
        return close_ret;
    }

    /* Get output parameters */
    close_ret = close_out_struct.ret;

    return close_ret;
}

ssize_t client_posix_write(int fd, const void *buf, size_t count)
{
    write_in_t  write_in_struct;
    write_out_t write_out_struct;

    bds_handle_t bds_handle;
    fs_request_t request;
    fs_status_t status;
    int fs_ret;
    int write_ret;

    /* Register memory */
    fs_ret = bds_handle_create((void*)buf, count, BDS_READ_ONLY, &bds_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        write_ret = S_FAIL;
        return write_ret;
    }

    /* Fill input structure */
    write_in_struct.bds_handle = bds_handle;
    write_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    fs_ret = fs_forward(addr, write_id, &write_in_struct, &write_out_struct, &request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        write_ret = S_FAIL;
        return write_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(request, FS_MAX_IDLE_TIME, &status);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        write_ret = S_FAIL;
        return write_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        write_ret = S_FAIL;
        return write_ret;
    }

    /* Free memory handle */
    fs_ret = bds_handle_free(bds_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        write_ret = S_FAIL;
        return write_ret;
    }

    /* Get output parameters */
    write_ret = write_out_struct.ret;

    return write_ret;
}

ssize_t client_posix_read(int fd, void *buf, size_t count)
{
    read_in_t  read_in_struct;
    read_out_t read_out_struct;

    bds_handle_t bds_handle;
    fs_request_t request;
    fs_status_t status;
    int fs_ret;
    int read_ret;

    /* Register memory */
    fs_ret = bds_handle_create(buf, count, BDS_READWRITE, &bds_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not create bulk data handle\n");
        read_ret = S_FAIL;
        return read_ret;
    }

    /* Fill input structure */
    read_in_struct.bds_handle = bds_handle;
    read_in_struct.fd = fd;

    /* Forward call to remote addr and get a new request */
    fs_ret = fs_forward(addr, read_id, &read_in_struct, &read_out_struct, &request);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not forward call\n");
        read_ret = S_FAIL;
        return read_ret;
    }

    /* Wait for call to be executed and return value to be sent back
     * (Request is freed when the call completes)
     */
    fs_ret = fs_wait(request, FS_MAX_IDLE_TIME, &status);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error during wait\n");
        read_ret = S_FAIL;
        return read_ret;
    }
    if (!status) {
        fprintf(stderr, "Operation did not complete\n");
        read_ret = S_FAIL;
        return read_ret;
    }

    /* Free memory handle */
    fs_ret = bds_handle_free(bds_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free bulk data handle\n");
        read_ret = S_FAIL;
        return read_ret;
    }

    /* Get output parameters */
    read_ret = read_out_struct.ret;

    return read_ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    int fs_ret, ret;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    const char *filename = "/tmp/posix_test";
    int fd = 0;
    int *read_buf = NULL;
    int *write_buf = NULL;
    size_t n_ints = 1024*1024;
    int i, error = 0;
    size_t nbyte;

    printf("Initializing...\n");

    fs_ret = client_posix_init(argc, argv);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error in client_posix_init\n");
        return EXIT_FAILURE;
    }

    /* Prepare buffers */
    write_buf = malloc(sizeof(int) * n_ints);
    read_buf =  malloc(sizeof(int) * n_ints);
    for (i = 0; i < n_ints; i++) {
        write_buf[i] = i;
        read_buf[i] = 0;
    }

    printf("Creating file...\n");

    fd = client_posix_open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "Error in fs_open\n");
        return EXIT_FAILURE;
    }

    printf("Writing data...\n");

    nbyte = client_posix_write(fd, write_buf, sizeof(int) * n_ints);
    if (nbyte <= 0) {
        fprintf(stderr, "Error detected in client_posix_write\n");
        return EXIT_FAILURE;
    }

    printf("Closing file...\n");

    ret = client_posix_close(fd);
    if (ret < 0) {
        fprintf(stderr, "Error detected in client_posix_close\n");
        return EXIT_FAILURE;
    }

    printf("Opening file...\n");

    fd = client_posix_open(filename, O_RDONLY, mode);
    if (fd < 0) {
        fprintf(stderr, "Error in fs_open\n");
        return EXIT_FAILURE;
    }

    printf("Reading data...\n");

    nbyte = client_posix_read(fd, read_buf, sizeof(int) * n_ints);
    if (nbyte < 0) {
        fprintf(stderr, "Error detected in client_posix_read\n");
        return EXIT_FAILURE;
    }

    printf("Closing file...\n");

    ret = client_posix_close(fd);
    if (ret < 0) {
        fprintf(stderr, "Error detected in client_posix_close\n");
        return EXIT_FAILURE;
    }

    printf("Checking data...\n");

    /* Check bulk buf */
    for (i = 0; i < n_ints; i++) {
        if (read_buf[i] != write_buf[i]) {
            printf("Error detected in bulk transfer, read_buf[%d] = %d, was expecting %d!\n", i, read_buf[i], write_buf[i]);
            error = 1;
            break;
        }
    }
    if (!error) printf("Successfully transferred %lu bytes!\n", nbyte);

    /* Free bulk data */
    free(write_buf);
    free(read_buf);

    printf("Finalizing...\n");

    fs_ret = client_posix_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Error in client_posix_finalize\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
