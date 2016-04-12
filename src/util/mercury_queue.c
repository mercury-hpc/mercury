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

#include "mercury_queue.h"

#include <stdlib.h>

#ifdef HG_UTIL_HAS_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "mercury_sys_queue.h"
#endif

/* A double-ended queue */
TAILQ_HEAD(hg_queue, hg_queue_entry);

struct hg_queue_entry {
    hg_queue_value_t data;
    TAILQ_ENTRY(hg_queue_entry) entry;
};

/*---------------------------------------------------------------------------*/
hg_queue_t *
hg_queue_new(void)
{
    hg_queue_t *queue;

    queue = (hg_queue_t *) malloc(sizeof(hg_queue_t));
    if (!queue)
        return NULL;

    TAILQ_INIT(queue);

    return queue;
}

/*---------------------------------------------------------------------------*/
void
hg_queue_free(hg_queue_t *queue)
{
    struct hg_queue_entry *current;

    if (!queue)
        return;

    /* Iterate over each entry, freeing each queue entry, until the
     * end is reached */
    for (current = TAILQ_FIRST(queue); current;) {
        struct hg_queue_entry *next = TAILQ_NEXT(current, entry);
        free(current);
        current = next;
    }
    free(queue);

    return;
}

/*---------------------------------------------------------------------------*/
int
hg_queue_push_head(hg_queue_t *queue, hg_queue_value_t data)
{
    struct hg_queue_entry *new_entry;

    if (!queue)
        return HG_UTIL_FAIL;

    /* Create the new entry and fill in the fields in the structure */
    new_entry = (struct hg_queue_entry *) malloc(sizeof(struct hg_queue_entry));
    if (!new_entry)
        return HG_UTIL_FAIL;

    new_entry->data = data;
    TAILQ_INSERT_HEAD(queue, new_entry, entry);

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_queue_value_t
hg_queue_pop_head(hg_queue_t *queue)
{
    struct hg_queue_entry *entry;
    hg_queue_value_t result;

    /* Check the queue is not empty */
    if (!queue || hg_queue_is_empty(queue))
        return HG_QUEUE_NULL;

    /* Unlink the first entry from the head of the queue */
    entry = TAILQ_FIRST(queue);
    TAILQ_REMOVE(queue, entry, entry);
    result = entry->data;

    /* Free back the queue entry structure */
    free(entry);

    return result;
}

/*---------------------------------------------------------------------------*/
hg_queue_value_t
hg_queue_peek_head(hg_queue_t *queue)
{
    if (!queue || hg_queue_is_empty(queue))
        return HG_QUEUE_NULL;
    else
        return TAILQ_FIRST(queue)->data;
}

/*---------------------------------------------------------------------------*/
int
hg_queue_push_tail(hg_queue_t *queue, hg_queue_value_t data)
{
    struct hg_queue_entry *new_entry;

    if (!queue)
        return HG_UTIL_FAIL;

    /* Create the new entry and fill in the fields in the structure */
    new_entry = (struct hg_queue_entry *) malloc(sizeof(struct hg_queue_entry));
    if (!new_entry)
        return HG_UTIL_FAIL;

    new_entry->data = data;
    TAILQ_INSERT_TAIL(queue, new_entry, entry);

    return HG_UTIL_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_queue_value_t
hg_queue_pop_tail(hg_queue_t *queue)
{
    struct hg_queue_entry *entry;
    hg_queue_value_t result;

    /* Check the queue is not empty */
    if (!queue || hg_queue_is_empty(queue))
        return HG_QUEUE_NULL;

    /* Unlink the last entry from the tail of the queue */
    entry = TAILQ_LAST(queue, hg_queue);
    TAILQ_REMOVE(queue, entry, entry);
    result = entry->data;

    /* Free back the queue entry structure */
    free(entry);

    return result;
}

/*---------------------------------------------------------------------------*/
hg_queue_value_t
hg_queue_peek_tail(hg_queue_t *queue)
{
    if (!queue || hg_queue_is_empty(queue))
        return HG_QUEUE_NULL;
    else
        return TAILQ_LAST(queue, hg_queue)->data;
}

/*---------------------------------------------------------------------------*/
hg_util_bool_t
hg_queue_is_empty(hg_queue_t *queue)
{
    if (!queue)
        return HG_UTIL_TRUE;

    return TAILQ_EMPTY(queue);
}
