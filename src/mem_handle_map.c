/*
 * mem_handle_map.c
 */

#include "mem_handle_map.h"

#include "hash-table.h"

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
 * Returns:
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
 * Returns:
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
   // TODO return right return value
   return hash_table_insert(map, key, value);
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
    // TODO return right return value
    /* Remove an entry */
    return hash_table_remove(map, key);
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_lookup
 *
 * Purpose:     Look up entry
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
mh_value_t mh_map_lookup(mh_map_t *map, mh_key_t key)
{
    /* Lookup value */
    return hash_table_lookup(map, key);
}

/*---------------------------------------------------------------------------
 * Function:    mh_map_get_size
 *
 * Purpose:     Get number of entries
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
int mh_map_get_size(mh_map_t *map)
{
    return hash_table_num_entries(map);
}
