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

#include "mem_handle_map.h"
#include "hash-table.h"
#include "shipper_error.h"

#include <stdlib.h>

static inline int pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}

static inline unsigned int pointer_hash(void *location)
{
    return (unsigned int) (unsigned long) location;
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_new
 *
 * Purpose:     Create a new map
 *
 * Returns:     Pointer to table
 *
 *---------------------------------------------------------------------------
 */
mh_map_t *mh_map_new()
{
    mh_map_t *map;

    map = hash_table_new(pointer_hash, pointer_equal);

    /* Automatically free all the values with the hash map */
    hash_table_register_free_functions(map, NULL, NULL);

    return map;
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_free
 *
 * Purpose:     Free the map
 *
 *---------------------------------------------------------------------------
 */
void mh_map_free(mh_map_t *map)
{
    /* Free the hash map */
    hash_table_free(map);
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_insert
 *
 * Purpose:     Insert a new entry into the map
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int mh_map_insert(mh_map_t *map, mh_key_t key, mh_value_t value)
{
    int ret = S_SUCCESS;

    if (!hash_table_insert(map, key, value)) {
        S_ERROR_DEFAULT("hash_table_insert failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_remove
 *
 * Purpose:     Remove the entry from the map
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int mh_map_remove(mh_map_t *map, mh_key_t key)
{
    int ret = S_SUCCESS;

    if (!hash_table_remove(map, key)) {
        S_ERROR_DEFAULT("hash_table_remove failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_lookup
 *
 * Purpose:     Look up entry
 *
 * Returns:     Value that corresponds to the key
 *
 *---------------------------------------------------------------------------
 */
mh_value_t mh_map_lookup(mh_map_t *map, mh_key_t key)
{
    return hash_table_lookup(map, key);
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_get_size
 *
 * Purpose:     Get number of entries
 *
 * Returns:     Size of the table
 *
 *---------------------------------------------------------------------------
 */
int mh_map_get_size(mh_map_t *map)
{
    return hash_table_num_entries(map);
}
