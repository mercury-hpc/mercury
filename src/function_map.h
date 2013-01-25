/*
 * function_map.h
 */

#ifndef FUNCTION_MAP_H
#define FUNCTION_MAP_H

typedef void *func_key_t;
typedef void *func_value_t;

typedef struct _HashTable func_map_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new table */
func_map_t *func_map_new();

/* Free the table */
void func_map_free(func_map_t *table);

/* Insert a new entry into the table */
int func_map_insert(func_map_t *table, func_key_t key, func_value_t value);

/* Remove the entry from the table */
int func_map_remove(func_map_t *table, func_key_t key);

/* Look up entry */
func_value_t func_map_lookup(func_map_t *table, func_key_t key);

/* Get number of entries */
int func_map_get_size(func_map_t *table);

#ifdef __cplusplus
}
#endif

#endif /* FUNCTION_MAP_H */
