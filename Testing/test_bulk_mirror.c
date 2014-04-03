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
write_data(na_addr_t addr, hg_bulk_t bulk_handle)
{
    hg_bulk_t mirror_handle;
    hg_bulk_request_t request;
    hg_bulk_segment_t segment;
    size_t size;

    size = HG_Bulk_handle_get_size(bulk_handle);

    HG_Bulk_mirror(addr, bulk_handle, 2, size, &mirror_handle);
    HG_Bulk_sync(mirror_handle, HG_BULK_READ, &request);
    HG_Bulk_wait(request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

    HG_Bulk_handle_access(mirror_handle, 4, size, HG_BULK_READ_ONLY, 1,
            &segment, NULL);

    printf("Data from mirror is: %s\n", (const char *) segment.address);
    /* write(filedes, segment.address, size); */

    HG_Bulk_handle_free(mirror_handle);
}

static void
read_data(na_addr_t addr, hg_bulk_t bulk_handle)
{
    hg_bulk_t mirror_handle;
    hg_bulk_request_t request;
    hg_bulk_segment_t segment;
    size_t size;

    size = HG_Bulk_handle_get_size(bulk_handle);
    HG_Bulk_mirror(addr, bulk_handle, 0, size, &mirror_handle);

    HG_Bulk_handle_access(mirror_handle, 0, size, HG_BULK_READWRITE, 1,
            &segment, NULL);

    printf("Data from mirror is: %s\n", (const char *) segment.address);

    /* read(filedes, segment.address, size); */
    strcpy((char *) segment.address, "We do not copy bulk data");

    HG_Bulk_sync(mirror_handle, HG_BULK_WRITE, &request);
    HG_Bulk_wait(request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

    HG_Bulk_handle_free(mirror_handle);
}

int
main(int argc, char *argv[])
{
    na_class_t *na_class = NULL;
    hg_bulk_t bulk_handle;
    na_addr_t addr = NA_ADDR_NULL;

    char src[BUFFER_SIZE];
    size_t size = BUFFER_SIZE;

    memset(src, '\0', BUFFER_SIZE);
    strcpy(src, "Nothing");

    /* Initialize interface */
    na_class = HG_Test_client_init(argc, argv, NULL, NULL);
    NA_Addr_self(na_class, &addr);

    HG_Bulk_init(na_class);

    /* This is created remotely or locally */
    HG_Bulk_handle_create(src, size, HG_BULK_READ_ONLY, &bulk_handle);

    printf("Data from origin is: %s\n", (const char *) src);

    /* Read data */
    read_data(addr, bulk_handle);

    printf("Data from origin is now: %s\n", (const char *) src);

    /* Write data */
    write_data(addr, bulk_handle);

    /* Free handle */
    HG_Bulk_handle_free(bulk_handle);

    /* Finalize interface */
    HG_Bulk_finalize();

    NA_Addr_free(na_class, addr);
    HG_Test_finalize(na_class);

    return EXIT_SUCCESS;
}
