/*
 * hash_table.c
 */

#include "hash_table.h"

#include <stdlib.h>
#include <map>

/* Default error macro */
#define HT_ERROR_DEFAULT(x) {             \
  fprintf(stderr, "Error "                \
        "in %s:%d (%s): "                 \
        "%s.\n",                          \
        __FILE__, __LINE__, __func__, x); \
}

static std::map<void*,void*> ht_map;

extern "C" {

/*---------------------------------------------------------------------------
 * Function:    ht_new
 *
 * Purpose:     Create a new table
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
ht_table_t *ht_new()
{
// nothing here
    ht_map.clear();
}

/*---------------------------------------------------------------------------
 * Function:    ht_free
 *
 * Purpose:     Free the table
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
void ht_free(ht_table_t *table)
{
// nothing here
    ht_map.clear();
}

/*---------------------------------------------------------------------------
 * Function:    ht_insert
 *
 * Purpose:     Insert a new entry into the table
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int ht_insert(ht_table_t *table, ht_key_t key, ht_value_t value)
{
    ht_map[key] = value;
}

/*---------------------------------------------------------------------------
 * Function:    ht_remove
 *
 * Purpose:     Remove the entry from the table
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int ht_remove(ht_table_t *table, ht_key_t key)
{
    ht_map.erase(key);
}

/*---------------------------------------------------------------------------
 * Function:    ht_lookup
 *
 * Purpose:     Look up entry
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
ht_value_t ht_lookup(ht_table_t *table, ht_key_t key)
{
    return ht_map.find(key)->second;
}

/*---------------------------------------------------------------------------
 * Function:    ht_get_size
 *
 * Purpose:     Get number of entries
 *
 * Returns:
 *
 *---------------------------------------------------------------------------
 */
int ht_get_size(ht_table_t *table)
{

}

}
