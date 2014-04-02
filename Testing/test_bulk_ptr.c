/*
 * test_bulk_ptr.c
 *
 *  Created on: Mar 24, 2014
 *      Author: jsoumagne
 */

#include "mercury_bulk.h"

#include <stdlib.h>

static void
write_data(na_addr_t addr, hg_bulk_t bulk_handle)
{
    hg_bulk_t mirror_handle;
    hg_bulk_request_t request;
    hg_bulk_segment_t segment;
    size_t total_size, segment_count;

    total_size = HG_Bulk_handle_get_size(bulk_handle);
    segment_count = HG_Bulk_handle_get_segment_count(bulk_handle);

    HG_Bulk_mirror(bulk_handle, 0, total_size, &mirror_handle);
    HG_Bulk_sync(addr, mirror_handle, HG_BULK_READ, &request);
    HG_Bulk_wait(request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

    HG_Bulk_handle_access(mirror_handle, 0, 0, HG_BULK_READ_ONLY, 1,
            &segment, NULL);

    /* write(filedes, buffer, size); */

    printf("Data: %s\n", (const char *) segment.address);

    HG_Bulk_handle_free(mirror_handle);
}

static void
read_data(na_addr_t addr, hg_bulk_t bulk_handle)
{
    hg_bulk_t mirror_handle;
    hg_bulk_request_t request;
    void *buffer;
    size_t size;

    size = HG_Bulk_handle_get_size(bulk_handle);
    HG_Bulk_mirror(addr, bulk_handle, 0, size, &mirror_handle);

    HG_Bulk_handle_access(mirror_handle, 0, 0, HG_BULK_READWRITE, 1,
            &buffer, &size, NULL);

    /* read(filedes, buffer, size); */

    printf("Data: %s\n", buffer);

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
    hg_bulk_request_t bulk_request;
    char *src = "We do not copy bulk data";
    size_t size = strlen(src) + 1;

    /* Initialize interface */
    na_class = HG_Test_client_init(argc, argv, NULL, NULL);
    NA_Addr_self(na_class, &addr);

    HG_Bulk_init(na_class);

    /* This is created remotely or locally */
    HG_Bulk_handle_create(src, size, HG_BULK_READ_ONLY, &bulk_handle);

    /* Write data */
    write_data(addr, bulk_handle);

    /* Read data */
    read_data(addr, bulk_handle);

    /* Free handle */
    HG_Bulk_handle_free(bulk_handle);

    /* Finalize interface */
    HG_Bulk_finalize();

    HG_Test_finalize(na_class);

    return EXIT_SUCCESS;
}
