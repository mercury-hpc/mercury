/*
 * hash_table.h
 */

#ifndef HASH_TABLE_H_
#define HASH_TABLE_H_

typedef void *ht_key_t;
typedef void *ht_value_t;

typedef struct ht_entry ht_entry_t;
typedef struct ht_table ht_table_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new table */
ht_table_t *ht_new();

/* Free the table */
void ht_free(ht_table_t *table);

/* Insert a new entry into the table */
int ht_insert(ht_table_t *table, ht_key_t key, ht_value_t value);

/* Remove the entry from the table */
int ht_remove(ht_table_t *table, ht_key_t key);

/* Look up entry */
ht_value_t ht_lookup(ht_table_t *table, ht_key_t key);

/* Get number of entries */
int ht_get_size(ht_table_t *table);

#ifdef __cplusplus
}
#endif

#endif /* HASH_TABLE_H_ */
