/*
 * test_bulk_ptr.c
 *
 *  Created on: Mar 24, 2014
 *      Author: jsoumagne
 */

#include "mercury_bulk.h"

#include <stdlib.h>

int
main(int argc, char *argv[])
{
    hg_bulk_t bulk_handle;
    na_addr_t addr = NA_ADDR_NULL;
    hg_bulk_request_t bulk_request;
    char *src = "We do not copy bulk data";
    size_t size = strlen(src) + 1;

    // This is created remotely or locally
    HG_Bulk_handle_create(src, size, HG_BULK_READ_ONLY, &bulk_handle);

    {
        void *data = HG_Bulk_handle_get_ptr(bulk_handle, 0);
        // if non local we used to do data = malloc(size)

//        HG_Bulk_ptr_read_all(addr, bulk_handle, data, &bulk_request);
        // equivalent to
        // HG_Bulk_ptr_read(addr, src_handle, 0, &dest, 0, size, &bulk_request);
        HG_Bulk_wait(bulk_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

        // write(fd, data, size);

        printf("Data: %s\n", data);

        // free(data); ??
        // HG_Bulk_handle_release_ptr ??
    }

    {
        void *data = HG_Bulk_handle_get_ptr(bulk_handle, 0);
        // if non local we used to do data = malloc(size)

        // read(fd, data, size)

        printf("Data: %s\n", data);

//        HG_Bulk_ptr_write_all(addr, bulk_handle, data, &bulk_request);
        HG_Bulk_wait(bulk_request, HG_MAX_IDLE_TIME, HG_STATUS_IGNORE);

        // free(data); ??
        // HG_Bulk_handle_release_ptr ??
    }

    HG_Bulk_handle_free(bulk_handle);

    return EXIT_SUCCESS;
}
