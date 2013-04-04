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
#include "function_shipper_handler.h"
#include "bulk_data_shipper.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

unsigned int finalizing = 0;

int server_finalize(fs_handle_t handle)
{
    int ret = S_SUCCESS;

    finalizing++;

    /* Free handle and send response back */
    ret = fs_handler_start_response(handle, NULL, 0);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    return ret;
}

int server_posix_open(fs_handle_t handle)
{
    int fs_ret = S_SUCCESS;

    void          *open_in_buf;
    size_t         open_in_buf_size;
    open_in_t      open_in_struct;

    void          *open_out_buf;
    size_t         open_out_buf_size;
    open_out_t     open_out_struct;

    fs_proc_t proc;

    const char *path;
    int flags;
    mode_t mode;
    int ret;

    /* Get input buffer */
    ret = fs_handler_get_input(handle, &open_in_buf, &open_in_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    fs_proc_create(open_in_buf, open_in_buf_size, FS_DECODE, &proc);
    fs_proc_open_in_t(proc, &open_in_struct);
    fs_proc_free(proc);

    path = open_in_struct.path;
    flags = open_in_struct.flags;
    mode = open_in_struct.mode;

    /* Call open */
    printf("Calling open with path: %s\n", path);
    ret = open(path, flags, mode);

    /* Fill output structure */
    open_out_struct.ret = ret;

    /* Create a new encoding proc */
    ret = fs_handler_get_output(handle, &open_out_buf, &open_out_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get output buffer\n");
        return ret;
    }

    fs_proc_create(open_out_buf, open_out_buf_size, FS_ENCODE, &proc);
    fs_proc_open_out_t(proc, &open_out_struct);
    fs_proc_free(proc);

    /* Free handle and send response back */
    ret = fs_handler_start_response(handle, NULL, 0);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Also free memory allocated during decoding */
    fs_proc_create(NULL, 0, FS_FREE, &proc);
    fs_proc_open_in_t(proc, &open_in_struct);
    fs_proc_free(proc);

    return fs_ret;
}

int server_posix_close(fs_handle_t handle)
{
    int fs_ret = S_SUCCESS;

    void          *close_in_buf;
    size_t         close_in_buf_size;
    close_in_t     close_in_struct;

    void          *close_out_buf;
    size_t         close_out_buf_size;
    close_out_t    close_out_struct;

    fs_proc_t proc;

    int fd;
    int ret;

    /* Get input buffer */
    ret = fs_handler_get_input(handle, &close_in_buf, &close_in_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    fs_proc_create(close_in_buf, close_in_buf_size, FS_DECODE, &proc);
    fs_proc_close_in_t(proc, &close_in_struct);
    fs_proc_free(proc);

    fd = close_in_struct.fd;

    /* Call close */
    printf("Calling close with fd: %d\n", fd);
    ret = close(fd);

    /* Fill output structure */
    close_out_struct.ret = ret;

    /* Create a new encoding proc */
    ret = fs_handler_get_output(handle, &close_out_buf, &close_out_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get output buffer\n");
        return ret;
    }

    fs_proc_create(close_out_buf, close_out_buf_size, FS_ENCODE, &proc);
    fs_proc_close_out_t(proc, &close_out_struct);
    fs_proc_free(proc);

    /* Free handle and send response back */
    ret = fs_handler_start_response(handle, NULL, 0);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Also free memory allocated during decoding */
    fs_proc_create(NULL, 0, FS_FREE, &proc);
    fs_proc_close_in_t(proc, &close_in_struct);
    fs_proc_free(proc);

    return fs_ret;
}

int server_posix_write(fs_handle_t handle)
{
    int fs_ret = S_SUCCESS;

    void          *write_in_buf;
    size_t         write_in_buf_size;
    write_in_t     write_in_struct;

    void          *write_out_buf;
    size_t         write_out_buf_size;
    write_out_t    write_out_struct;

    fs_proc_t proc;

    na_addr_t source = fs_handler_get_addr(handle);
    bds_handle_t bds_handle = NULL;
    bds_block_handle_t bds_block_handle = NULL;

    int fd;
    void *buf;
    size_t count;
    ssize_t ret;

    /* for debug */
    int i;
    const int *buf_ptr;

    /* Get input buffer */
    ret = fs_handler_get_input(handle, &write_in_buf, &write_in_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    fs_proc_create(write_in_buf, write_in_buf_size, FS_DECODE, &proc);
    fs_proc_write_in_t(proc, &write_in_struct);
    fs_proc_free(proc);

    bds_handle = write_in_struct.bds_handle;
    fd = write_in_struct.fd;

    /* Read bulk data here and wait for the data to be here  */
    count = bds_handle_get_size(bds_handle);
    buf = malloc(count);

    bds_block_handle_create(buf, count, BDS_READWRITE, &bds_block_handle);

    fs_ret = bds_read(bds_handle, source, bds_block_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not read bulk data\n");
        return fs_ret;
    }

    fs_ret = bds_wait(bds_block_handle, BDS_MAX_IDLE_TIME);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data read\n");
        return fs_ret;
    }

    /* Check bulk buf */
    buf_ptr = buf;
    for (i = 0; i < (count / sizeof(int)); i++) {
        if (buf_ptr[i] != i) {
            printf("Error detected in bulk transfer, buf[%d] = %d, was expecting %d!\n", i, buf_ptr[i], i);
            break;
        }
    }

    printf("Calling write with fd: %d\n", fd);
    ret = write(fd, buf, count);

    /* Fill output structure */
    write_out_struct.ret = ret;

    /* Create a new encoding proc */
    ret = fs_handler_get_output(handle, &write_out_buf, &write_out_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get output buffer\n");
        return ret;
    }

    fs_proc_create(write_out_buf, write_out_buf_size, FS_ENCODE, &proc);
    fs_proc_write_out_t(proc, &write_out_struct);
    fs_proc_free(proc);

    /* Free handle and send response back */
    ret = fs_handler_start_response(handle, NULL, 0);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Also free memory allocated during decoding */
    fs_proc_create(NULL, 0, FS_FREE, &proc);
    fs_proc_write_in_t(proc, &write_in_struct);
    fs_proc_free(proc);

    /* Free block handle */
    fs_ret = bds_block_handle_free(bds_block_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return fs_ret;
    }

    free(buf);

    return fs_ret;
}

int server_posix_read(fs_handle_t handle)
{
    int fs_ret = S_SUCCESS;

    void         *read_in_buf;
    size_t        read_in_buf_size;
    read_in_t     read_in_struct;

    void         *read_out_buf;
    size_t        read_out_buf_size;
    read_out_t    read_out_struct;

    fs_proc_t proc;

    na_addr_t dest = fs_handler_get_addr(handle);
    bds_handle_t bds_handle = NULL;
    bds_block_handle_t bds_block_handle = NULL;

    int fd;
    void *buf;
    size_t count;
    ssize_t ret;

    /* for debug */
    int i;
    const int *buf_ptr;

    /* Get input buffer */
    ret = fs_handler_get_input(handle, &read_in_buf, &read_in_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get input buffer\n");
        return ret;
    }

    /* Create a new decoding proc */
    fs_proc_create(read_in_buf, read_in_buf_size, FS_DECODE, &proc);
    fs_proc_read_in_t(proc, &read_in_struct);
    fs_proc_free(proc);

    bds_handle = read_in_struct.bds_handle;
    fd = read_in_struct.fd;

    /* Call read */
    count = bds_handle_get_size(bds_handle);
    buf = malloc(count);

    printf("Calling read with fd: %d\n", fd);
    ret = read(fd, buf, count);

    /* Check bulk buf */
    buf_ptr = buf;
    for (i = 0; i < (count / sizeof(int)); i++) {
        if (buf_ptr[i] != i) {
            printf("Error detected after read, buf[%d] = %d, was expecting %d!\n", i, buf_ptr[i], i);
            break;
        }
    }

    /* Create a new block handle to write the data */
    bds_block_handle_create(buf, ret, BDS_READ_ONLY, &bds_block_handle);

    /* Write bulk data here and wait for the data to be there  */
    fs_ret = bds_write(bds_handle, dest, bds_block_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not write bulk data\n");
        return fs_ret;
    }

    fs_ret = bds_wait(bds_block_handle, BDS_MAX_IDLE_TIME);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not complete bulk data write\n");
        return fs_ret;
    }

    /* Fill output structure */
    read_out_struct.ret = ret;

    /* Create a new encoding proc */
    ret = fs_handler_get_output(handle, &read_out_buf, &read_out_buf_size);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not get output buffer\n");
        return ret;
    }

    fs_proc_create(read_out_buf, read_out_buf_size, FS_ENCODE, &proc);
    fs_proc_read_out_t(proc, &read_out_struct);
    fs_proc_free(proc);

    /* Free handle and send response back */
    ret = fs_handler_start_response(handle, NULL, 0);
    if (ret != S_SUCCESS) {
        fprintf(stderr, "Could not respond\n");
        return ret;
    }

    /* Also free memory allocated during decoding */
    fs_proc_create(NULL, 0, FS_FREE, &proc);
    fs_proc_read_in_t(proc, &read_in_struct);
    fs_proc_free(proc);

    /* Free block handle */
    fs_ret = bds_block_handle_free(bds_block_handle);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not free block call\n");
        return fs_ret;
    }

    free(buf);

    return fs_ret;
}

/******************************************************************************/
int main(int argc, char *argv[])
{
    na_network_class_t *network_class = NULL;
    unsigned int number_of_peers;
    int fs_ret;

    /* Used by Test Driver */
    printf("Waiting for client...\n");
    fflush(stdout);

    /* Initialize the interface */
    network_class = shipper_test_server_init(argc, argv, &number_of_peers);

    fs_ret = fs_handler_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize function shipper handler\n");
        return EXIT_FAILURE;
    }

    fs_ret = bds_init(network_class);
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not initialize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    /* Register routine */
    IOFSL_SHIPPER_HANDLER_REGISTER("open", server_posix_open);
    IOFSL_SHIPPER_HANDLER_REGISTER("write", server_posix_write);
    IOFSL_SHIPPER_HANDLER_REGISTER("read", server_posix_read);
    IOFSL_SHIPPER_HANDLER_REGISTER("close", server_posix_close);
    IOFSL_SHIPPER_HANDLER_REGISTER_FINALIZE(server_finalize);

    while (finalizing != number_of_peers) {
        /* Receive new function calls */
        fs_ret = fs_handler_process(FS_HANDLER_MAX_IDLE_TIME);
        if (fs_ret != S_SUCCESS) {
            fprintf(stderr, "Could not receive function call\n");
            return EXIT_FAILURE;
        }
    }

    printf("Finalizing...\n");

    /* Finalize the interface */
    fs_ret = bds_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize bulk data shipper\n");
        return EXIT_FAILURE;
    }

    fs_ret = fs_handler_finalize();
    if (fs_ret != S_SUCCESS) {
        fprintf(stderr, "Could not finalize function shipper handler\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
