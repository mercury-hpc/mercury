/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_checksum.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE 512
#define BUF_SIZE_X 32
#define BUF_SIZE_Y 16

int
main(int argc, char *argv[])
{
    int buf1[BUF_SIZE];
    int buf2[BUF_SIZE_X][BUF_SIZE_Y];
    int i, j;
    hg_checksum_t checksum1, checksum2;
    void *hash1 = NULL, *hash2 = NULL;
    size_t hash_size;
    const char *hash_method;
    int ret = EXIT_SUCCESS;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n%s [method]\n", argv[0]);
        ret = EXIT_FAILURE;
        return ret;
    }

    if (strcmp(argv[1], "crc16") && strcmp(argv[1], "crc64")) {
        fprintf(stderr, "%s is not a valid parameter\n", argv[1]);
        ret = EXIT_FAILURE;
        return ret;
    }

    hash_method = argv[1];

    /* Initialize buf1 */
    for (i = 0; i < BUF_SIZE; i++) {
        buf1[i] = i;
    }

    /* Initialize buf2 */
    for (i = 0; i < BUF_SIZE_X; i++) {
        for (j = 0; j < BUF_SIZE_Y; j++) {
            buf2[i][j] = i * BUF_SIZE_Y + j;
        }
    }

    /* Initialize checksums */
    hg_checksum_init(hash_method, &checksum1);
    hg_checksum_init(hash_method, &checksum2);

    /* Update checksums */
    hg_checksum_update(checksum1, buf1, BUF_SIZE * sizeof(int));

    for (i = 0; i < BUF_SIZE_X; i++) {
        hg_checksum_update(checksum2, buf2[i], BUF_SIZE_Y * sizeof(int));
    }

    /* Get size of checksums */
    hash_size = hg_checksum_get_size(checksum1);

    hash1 = malloc(hash_size);
    hash2 = malloc(hash_size);

    hg_checksum_get(checksum1, hash1, hash_size, 0);
    hg_checksum_get(checksum2, hash2, hash_size, 0);

    /*
    printf("Checksum of buf1 is: %016lX\n",
            *(hg_util_uint64_t*)hash1);

    printf("Checksum of buf2 is: %016lX\n",
            *(hg_util_uint64_t*)hash2);

    printf("Checksum of buf1 is: %04X\n",
            *(hg_util_uint16_t*)hash1);

    printf("Checksum of buf2 is: %04X\n",
            *(hg_util_uint16_t*)hash2);
    */

    if (strncmp(hash1, hash2, hash_size) != 0) {
        fprintf(stderr, "Checksums do not match\n");
        ret = EXIT_FAILURE;
    }

    /* Corrupting buf2 and recomputing checksum */
    buf2[0][0] = 1;

    hg_checksum_reset(checksum2);
    for (i = 0; i < BUF_SIZE_X; i++) {
        hg_checksum_update(checksum2, buf2[i], BUF_SIZE_Y * sizeof(int));
    }
    hg_checksum_get(checksum2, hash2, hash_size, 0);

    if (strncmp(hash1, hash2, hash_size) == 0) {
        fprintf(stderr, "Checksums should not match\n");
        ret = EXIT_FAILURE;
    }

    /* Destroy checksums and free hash buffers */
    hg_checksum_destroy(checksum1);
    hg_checksum_destroy(checksum2);
    free(hash1);
    free(hash2);

    return ret;
}
