/*
 * function_map.c
 */

#include "function_map.h"
#include "hash-table.h"
#include "shipper_error.h"

#include <stdlib.h>

int int_equal(void *vlocation1, void *vlocation2)
{
    int *location1;
    int *location2;

    location1 = (int *) vlocation1;
    location2 = (int *) vlocation2;

    return *location1 == *location2;
}

unsigned int int_hash(void *vlocation)
{
    int *location;

    location = (int *) vlocation;

    return (unsigned int) *location;
}

/*---------------------------------------------------------------------------
 * Function:    func_map_new
 *
 * Purpose:     Create a new map
 *
 * Returns:     Pointer to table
 *
 *---------------------------------------------------------------------------
 */
func_map_t *func_map_new()
{
    func_map_t *map;

    map = hash_table_new(int_hash, int_equal);

    /* Automatically free all the values with the hash map */
    hash_table_register_free_functions(map, free, free);

    return map;
}

/*---------------------------------------------------------------------------
 * Function:    func_map_free
 *
 * Purpose:     Free the map
 *
 *---------------------------------------------------------------------------
 */
void func_map_free(func_map_t *map)
{
    /* Free the hash map */
    hash_table_free(map);
}

/*---------------------------------------------------------------------------
 * Function:    func_map_insert
 *
 * Purpose:     Insert a new entry into the map
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int func_map_insert(func_map_t *map, func_key_t key, func_value_t value)
{
    int ret = S_SUCCESS;

    if (!hash_table_insert(map, key, value)) {
        S_ERROR_DEFAULT("hash_table_insert failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    func_map_remove
 *
 * Purpose:     Remove the entry from the map
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int func_map_remove(func_map_t *map, func_key_t key)
{
    int ret = S_SUCCESS;

    if (!hash_table_remove(map, key)) {
        S_ERROR_DEFAULT("hash_table_remove failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    func_map_lookup
 *
 * Purpose:     Look up entry
 *
 * Returns:     Value that corresponds to the key
 *
 *---------------------------------------------------------------------------
 */
func_value_t func_map_lookup(func_map_t *map, func_key_t key)
{
    return hash_table_lookup(map, key);
}

/*---------------------------------------------------------------------------
 * Function:    func_map_get_size
 *
 * Purpose:     Get number of entries
 *
 * Returns:     Size of the table
 *
 *---------------------------------------------------------------------------
 */
int func_map_get_size(func_map_t *map)
{
    return hash_table_num_entries(map);
}
