/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include <mercury_macros.h>

#ifndef EXAMPLE_SNAPPY_H
#    define EXAMPLE_SNAPPY_H

#    define TEMP_DIRECTORY   "."
#    define CONFIG_FILE_NAME "/port.cfg"

extern hg_bool_t snappy_compress_done_target_g;

/**
 * If this is the snappy interface we wish to ship:
 *
 *   snappy_status snappy_compress(const char* input,
 *                                 size_t input_length,
 *                                 char* compressed,
 *                                 size_t* compressed_length);
 */

/* The MERCURY_GEN_PROC macro creates a new compound type consisting of
 * the members listed.
 *
 * snappy_compress_in_t will contain input/output members:
 * - input_bulk_handle: describes input/intput_length
 * - compressed_bulk_handle: describes compressed/compressed_length
 */
MERCURY_GEN_PROC(snappy_compress_in_t,
    ((hg_bulk_t)(input_bulk_handle))((hg_bulk_t)(compressed_bulk_handle)))

/* snappy_compress_out_t will contain output members:
 * - ret: snappy_status enum, the return type uses hg_int32_t as a base type
 */
MERCURY_GEN_PROC(
    snappy_compress_out_t, ((hg_int32_t)(ret))((hg_size_t)(compressed_length)))

/**
 * Convenient to have both origin and target call a "register" routine
 * that sets up all forwarded functions.
 */
hg_id_t
snappy_compress_register(hg_class_t *hg_class);

void
print_buf(int n, int *buf);

#endif /* EXAMPLE_SNAPPY_H */
