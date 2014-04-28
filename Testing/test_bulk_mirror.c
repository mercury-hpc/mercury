/*
 * test_bulk_ptr.c
 *
 *  Created on: Mar 24, 2014
 *      Author: jsoumagne
 */

#include "mercury_test.h"

#include "mercury_bulk.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 64

static void
write_data(hg_bulk_t bulk_handle)
{
    size_t size;
    void *buf;
    size_t buf_size;

    size = HG_Bulk_handle_get_size(bulk_handle);

    HG_Bulk_handle_access(bulk_handle, 3, size, HG_BULK_READ_ONLY, 1,
            &buf, &buf_size, NULL);

    printf("Data from mirror is: %s\n", (const char *) buf);
    /* write(filedes, segment.address, size); */
}

static void
read_data(hg_bulk_t bulk_handle)
{
    size_t size;
    void *buf;
    size_t buf_size;

    size = HG_Bulk_handle_get_size(bulk_handle);

    HG_Bulk_handle_access(bulk_handle, 0, size, HG_BULK_READWRITE, 1,
            &buf, &buf_size, NULL);

    printf("Data from mirror is: %s\n", (const char *) buf);

    /* read(filedes, segment.address, size); */
    strcpy((char *) buf, "We do not copy bulk data");
}

int
main(int argc, char *argv[])
{
    hg_bulk_t bulk_handle;
    na_addr_t addr = NA_ADDR_NULL;

    char src[BUFFER_SIZE];
    size_t size = BUFFER_SIZE;
    void *src_ptr[1];

    memset(src, '\0', BUFFER_SIZE);
    strcpy(src, "Nothing");

    /* Initialize interface */
    HG_Test_client_init(argc, argv, &addr, NULL);

    /* This is created remotely or locally */
    *src_ptr = src;
    HG_Bulk_handle_create(1, src_ptr, &size, HG_BULK_READ_ONLY,
            &bulk_handle);

    printf("Data from origin is: %s\n", (const char *) src);

    /* Read data */
    read_data(bulk_handle);

    printf("Data from origin is now: %s\n", (const char *) src);

    /* Write data */
    write_data(bulk_handle);

    /* Free handle */
    HG_Bulk_handle_free(bulk_handle);

    /* Finalize interface */
    HG_Test_finalize();

    return EXIT_SUCCESS;
}
