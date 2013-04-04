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

#ifndef HANDLE_LIST_H
#define HANDLE_LIST_H

typedef void *handle_value_t;

typedef struct _ListEntry handle_entry_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Free the list */
void handle_list_free(handle_entry_t *list);

/* Append a new entry to the list */
int handle_list_append(handle_entry_t **list, handle_value_t value);

/* Remove the entry from the list */
int handle_list_remove_entry(handle_entry_t **list, handle_entry_t *entry);

/* Remove the entry from the list */
int handle_list_remove_data(handle_entry_t **list, handle_value_t value);

/* Retrieve next entry */
handle_entry_t *handle_list_next(handle_entry_t *entry);

/* Retrieve value at a list entry */
handle_value_t handle_list_value(handle_entry_t *entry);

/* Get number of entries */
unsigned int handle_list_get_size(handle_entry_t *list);

#ifdef __cplusplus
}
#endif

#endif /* HANDLE_LIST_H */
