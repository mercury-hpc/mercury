/*
 * mem_handle_map.h
 */

#ifndef MEM_HANDLE_MAP_H
#define MEM_HANDLE_MAP_H

typedef void *mh_key_t;
typedef void *mh_value_t;

typedef struct _HashTable mh_map_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new table */
mh_map_t *mh_map_new();

/* Free the table */
void mh_map_free(mh_map_t *table);

/* Insert a new entry into the table */
int mh_map_insert(mh_map_t *table, mh_key_t key, mh_value_t value);

/* Remove the entry from the table */
int mh_map_remove(mh_map_t *table, mh_key_t key);

/* Look up entry */
mh_value_t mh_map_lookup(mh_map_t *table, mh_key_t key);

/* Get number of entries */
int mh_map_get_size(mh_map_t *table);

#ifdef __cplusplus
}
#endif

#endif /* MEM_HANDLE_MAP_H */
