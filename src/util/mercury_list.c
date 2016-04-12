/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

/*
 * Copyright (c) 2005-2008, Simon Howard
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "mercury_list.h"

#include <stdlib.h>

#ifdef HG_UTIL_HAS_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "mercury_sys_queue.h"
#endif

/* A doubly-linked list */
LIST_HEAD(hg_list, hg_list_entry);

struct hg_list_entry {
    hg_list_value_t data;
    LIST_ENTRY(hg_list_entry) entry;
};

/*---------------------------------------------------------------------------*/
hg_list_t *
hg_list_new(void)
{
    hg_list_t *list;

    list = (hg_list_t *) malloc(sizeof(hg_list_t));
    if (!list)
        return NULL;

    LIST_INIT(list);

    return list;
}

/*---------------------------------------------------------------------------*/
void
hg_list_free(hg_list_t *list)
{
    hg_list_entry_t *current;

    if (!list)
        return;

    /* Iterate over each entry, freeing each list entry, until the
     * end is reached */
    for (current = LIST_FIRST(list); current;) {
        hg_list_entry_t *next = LIST_NEXT(current, entry);
        free(current);
        current = next;
    }
    free(list);

    return;
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_insert_head(hg_list_t *list, hg_list_value_t data)
{
    hg_list_entry_t *new_entry;

    if (!list)
        return NULL;

    /* Create new list entry */
    new_entry = (hg_list_entry_t *) malloc(sizeof(hg_list_entry_t));
    if (!new_entry)
        return NULL;

    new_entry->data = data;
    LIST_INSERT_HEAD(list, new_entry, entry);

    return new_entry;
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_insert_before(hg_list_entry_t *entry, hg_list_value_t data)
{
    hg_list_entry_t *new_entry;

    if (!entry)
        return NULL;

    /* Create new list entry */
    new_entry = (hg_list_entry_t *) malloc(sizeof(hg_list_entry_t));
    if (!new_entry)
        return NULL;

    new_entry->data = data;
    LIST_INSERT_BEFORE(entry, new_entry, entry);

    return new_entry;
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_insert_after(hg_list_entry_t *entry, hg_list_value_t data)
{
    hg_list_entry_t *new_entry;

    if (!entry)
        return NULL;

    /* Create new list entry */
    new_entry = (hg_list_entry_t *) malloc(sizeof(hg_list_entry_t));
    if (!new_entry)
        return NULL;

    new_entry->data = data;
    LIST_INSERT_AFTER(entry, new_entry, entry);

    return new_entry;
}

/*---------------------------------------------------------------------------*/
hg_util_bool_t
hg_list_is_empty(hg_list_t *list)
{
    if (!list)
        return HG_UTIL_TRUE;

    return LIST_EMPTY(list);
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_first(hg_list_t *list)
{
    if (!list)
        return NULL;

    return LIST_FIRST(list);
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_next(hg_list_entry_t *entry)
{
    if (!entry)
        return NULL;

    return LIST_NEXT(entry, entry);
}

/*---------------------------------------------------------------------------*/
hg_list_value_t
hg_list_data(hg_list_entry_t *entry)
{
    if (!entry)
        return NULL;

    return entry->data;
}

/*---------------------------------------------------------------------------*/
int
hg_list_remove_entry(hg_list_entry_t *entry)
{
    if (!entry)
        return HG_UTIL_FAIL;

    LIST_REMOVE(entry, entry);
    free(entry);

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
unsigned int
hg_list_remove_data(hg_list_t *list, hg_list_equal_func_t callback,
        hg_list_value_t data)
{
    unsigned int entries_removed;
    hg_list_entry_t *entry;

    entries_removed = 0;

    /* Iterate over the entries in the list */
    for (entry = LIST_FIRST(list); entry;) {
        hg_list_entry_t *next = LIST_NEXT(entry, entry);
        if (callback(entry->data, data)) {
            hg_list_remove_entry(entry);
            entries_removed++;
        }
        entry = next;
    }

    return entries_removed;
}

/*---------------------------------------------------------------------------*/
hg_list_entry_t *
hg_list_find_data(hg_list_t *list, hg_list_equal_func_t callback,
        hg_list_value_t data)
{
    hg_list_entry_t *entry;

    /* Iterate over entries in the list until the data is found */
    LIST_FOREACH(entry, list, entry)
        if (callback(entry->data, data))
            return entry;

    /* Not found */
    return NULL;
}
