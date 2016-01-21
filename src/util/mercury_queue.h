/*
 * Copyright (C) 2013-2015 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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

#ifndef MERCURY_QUEUE_H
#define MERCURY_QUEUE_H

#include "mercury_util_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A double-ended queue.
 */

typedef struct hg_queue hg_queue_t;

/**
 * A value stored in a \ref hg_queue_t.
 */

typedef void *hg_queue_value_t;

/**
 * A null \ref hg_queue_value_t.
 */

#define HG_QUEUE_NULL ((void *) 0)

/**
 * Create a new double-ended queue.
 *
 * \return           A new queue, or NULL if it was not possible to allocate
 *                   the memory.
 */
HG_UTIL_EXPORT hg_queue_t *
hg_queue_new(void);

/**
 * Destroy a queue. User is responsible for freeing allocated data that was
 * pushed to the queue.
 *
 * \param queue      The queue to destroy.
 */
HG_UTIL_EXPORT void
hg_queue_free(hg_queue_t *queue);

/**
 * Add a value to the head of a queue.
 *
 * \param queue      The queue.
 * \param data       The value to add.
 *
 * \return           Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_queue_push_head(hg_queue_t *queue, hg_queue_value_t data);

/**
 * Remove a value from the head of a queue.
 *
 * \param queue      The queue.
 *
 * \return           Value that was at the head of the queue, or
 *                   \ref QUEUE_NULL if the queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_pop_head(hg_queue_t *queue);

/**
 * Read value from the head of a queue, without removing it from
 * the queue.
 *
 * \param queue      The queue.
 *
 * \return           Value at the head of the queue, or \ref QUEUE_NULL if the
 *                   queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_peek_head(hg_queue_t *queue);

/**
 * Add a value to the tail of a queue.
 *
 * \param queue      The queue.
 * \param data       The value to add.
 *
 * \return           Non-negative on success or negative on failure
 */
HG_UTIL_EXPORT int
hg_queue_push_tail(hg_queue_t *queue, hg_queue_value_t data);

/**
 * Remove a value from the tail of a queue.
 *
 * \param queue      The queue.
 *
 * \return           Value that was at the tail of the queue, or
 *                   \ref QUEUE_NULL if the queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_pop_tail(hg_queue_t *queue);

/**
 * Read a value from the tail of a queue, without removing it from
 * the queue.
 *
 * \param queue      The queue.
 *
 * \return           Value at the tail of the queue, or \ref QUEUE_NULL if the
 *                   queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_peek_tail(hg_queue_t *queue);

/**
 * Query if any values are currently in a queue.
 *
 * \param queue      The queue.
 *
 * \return           Zero if the queue is not empty, non-zero if the queue
 *                   is empty.
 */
HG_UTIL_EXPORT hg_util_bool_t
hg_queue_is_empty(hg_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_QUEUE_H */
