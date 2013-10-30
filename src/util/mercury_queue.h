/*

Copyright (c) 2005-2008, Simon Howard

Permission to use, copy, modify, and/or distribute this software 
for any purpose with or without fee is hereby granted, provided 
that the above copyright notice and this permission notice appear 
in all copies. 

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL 
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE 
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR 
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, 
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN      
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 

 */

/**
 * \file queue.h
 *
 * \brief Double-ended queue.
 *
 * A double ended queue stores a list of values in order.  New values
 * can be added and removed from either end of the queue.
 *
 * To create a new queue, use \ref queue_new.  To destroy a queue, use
 * \ref queue_free.
 *
 * To add values to a queue, use \ref queue_push_head and
 * \ref queue_push_tail.
 *
 * To read values from the ends of a queue, use \ref queue_pop_head
 * and \ref queue_pop_tail.  To examine the ends without removing values
 * from the queue, use \ref queue_peek_head and \ref queue_peek_tail.
 *
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

typedef void * hg_queue_value_t;

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
 * Destroy a queue.
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
 * \return           Non-zero if the value was added successfully, or zero
 *                   if it was not possible to allocate the memory for the
 *                   new entry. 
 */
HG_UTIL_EXPORT int
hg_queue_push_head(hg_queue_t *queue, hg_queue_value_t data);

/**
 * Remove a value from the head of a queue.
 *
 * \param queue      The queue.
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
 * \return           Non-zero if the value was added successfully, or zero
 *                   if it was not possible to allocate the memory for the
 *                   new entry. 
 */
HG_UTIL_EXPORT int
hg_queue_push_tail(hg_queue_t *queue, hg_queue_value_t data);

/**
 * Remove a value from the tail of a queue.
 *
 * \param queue      The queue.
 * \return           Value that was at the head of the queue, or
 *                   \ref QUEUE_NULL if the queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_pop_tail(hg_queue_t *queue);

/**
 * Read a value from the tail of a queue, without removing it from
 * the queue.
 *
 * \param queue      The queue.
 * \return           Value at the tail of the queue, or QUEUE_NULL if the
 *                   queue is empty.
 */
HG_UTIL_EXPORT hg_queue_value_t
hg_queue_peek_tail(hg_queue_t *queue);

/**
 * Query if any values are currently in a queue.
 *
 * \param queue      The queue.
 * \return           Zero if the queue is not empty, non-zero if the queue
 *                   is empty.
 */
HG_UTIL_EXPORT int
hg_queue_is_empty(hg_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_QUEUE_H */

