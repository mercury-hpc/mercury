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
 * @file mercury_list.h
 *
 * @brief Doubly-linked list.
 *
 * A doubly-linked list stores a collection of values.  Each entry in
 * the list (represented by a pointer a @ref hg_list_entry_t structure)
 * contains a link to the next entry and the previous entry.
 * It is therefore possible to iterate over entries in the list in either 
 * direction.
 *
 * To create an empty list, create a new variable which is a pointer to
 * a @ref hg_list_entry_t structure, and initialize it to NULL.
 * To destroy an entire list, use @ref list_free.
 *
 * To add a value to a list, use @ref list_append or @ref list_prepend.
 *
 * To remove a value from a list, use @ref list_remove_entry or 
 * @ref list_remove_data.
 *
 * To iterate over entries in a list, use @ref list_iterate to initialize
 * a @ref hg_list_iter_t structure, with @ref list_iter_next and
 * @ref list_iter_has_more to retrieve each value in turn. 
 * @ref list_iter_remove can be used to remove the current entry.
 *
 * To access an entry in the list by index, use @ref list_nth_entry or
 * @ref list_nth_data.
 *
 * To sort a list, use @ref list_sort.
 *
 */

#ifndef MERCURY_LIST_H
#define MERCURY_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represents an entry in a doubly-linked list.  The empty list is
 * represented by a NULL pointer. To initialize a new doubly linked
 * list, simply create a variable of this type 
 * containing a pointer to NULL.
 */

typedef struct hg_list_entry hg_list_entry_t;

/** 
 * Structure used to iterate over a list.
 */

typedef struct hg_list_iter hg_list_iter_t;

/**
 * A value stored in a list.
 */

typedef void *hg_list_value_t;

/**
 * Definition of a @ref hg_list_iter_t.
 */

struct hg_list_iter {
    hg_list_entry_t **prev_next;
    hg_list_entry_t *current;
};

/**
 * A null @ref hg_list_value_t.
 */

#define HG_LIST_NULL ((void *) 0)

/**
 * Callback function used to compare values in a list when sorting.
 *
 * @param value1      The first value to compare.
 * @param value2      The second value to compare.
 * @return            A negative value if value1 should be sorted before 
 *                    value2, a positive value if value1 should be sorted 
 *                    after value2, zero if value1 and value2 are equal.
 */

typedef int (*hg_list_compare_func_t)(hg_list_value_t value1, hg_list_value_t value2);

/**
 * Callback function used to determine of two values in a list are
 * equal.
 *
 * @param value1      The first value to compare.
 * @param value2      The second value to compare.
 * @return            A non-zero value if value1 and value2 are equal, zero
 *                    if they are not equal.
 */

typedef int (*hg_list_equal_func_t)(hg_list_value_t value1, hg_list_value_t value2);

/**
 * Free an entire list.
 *
 * @param list         The list to free.
 */

void list_free(hg_list_entry_t *list);

/**
 * Prepend a value to the start of a list.
 *
 * @param list         Pointer to the list to prepend to.
 * @param data         The value to prepend.
 * @return             The new entry in the list, or NULL if it was not
 *                     possible to allocate the memory for the new entry.
 */

hg_list_entry_t *hg_list_prepend(hg_list_entry_t **list, hg_list_value_t data);

/**
 * Append a value to the end of a list.
 *
 * @param list         Pointer to the list to append to.
 * @param data         The value to append.
 * @return             The new entry in the list, or NULL if it was not
 *                     possible to allocate the memory for the new entry.
 */

hg_list_entry_t *hg_list_append(hg_list_entry_t **list, hg_list_value_t data);

/** 
 * Retrieve the previous entry in a list.
 *
 * @param listentry    Pointer to the list entry.
 * @return             The previous entry in the list, or NULL if this 
 *                     was the first entry in the list.
 */

hg_list_entry_t *hg_list_prev(hg_list_entry_t *listentry);

/** 
 * Retrieve the next entry in a list.
 *
 * @param listentry    Pointer to the list entry.
 * @return             The next entry in the list, or NULL if this was the
 *                     last entry in the list.
 */

hg_list_entry_t *hg_list_next(hg_list_entry_t *listentry);

/**
 * Retrieve the value at a list entry.
 *
 * @param listentry    Pointer to the list entry.
 * @return             The value stored at the list entry.
 */

hg_list_value_t hg_list_data(hg_list_entry_t *listentry);

/** 
 * Retrieve the entry at a specified index in a list.
 *
 * @param list       The list.
 * @param n          The index into the list .
 * @return           The entry at the specified index, or NULL if out of range.
 */

hg_list_entry_t *hg_list_nth_entry(hg_list_entry_t *list, unsigned int n);

/** 
 * Retrieve the value at a specified index in the list.
 *
 * @param list       The list.
 * @param n          The index into the list.
 * @return           The value at the specified index, or @ref HG_LIST_NULL if
 *                   unsuccessful.
 */

hg_list_value_t hg_list_nth_data(hg_list_entry_t *list, unsigned int n);

/** 
 * Find the length of a list.
 *
 * @param list       The list.
 * @return           The number of entries in the list.
 */

unsigned int hg_list_length(hg_list_entry_t *list);

/**
 * Create a C array containing the contents of a list.
 *
 * @param list       The list.
 * @return           A newly-allocated C array containing all values in the
 *                   list, or NULL if it was not possible to allocate the
 *                   memory.  The length of the array is equal to the length
 *                   of the list (see @ref list_length).
 */

hg_list_value_t *hg_list_to_array(hg_list_entry_t *list);

/**
 * Remove an entry from a list.
 *
 * @param list       Pointer to the list.
 * @param entry      The list entry to remove .
 * @return           If the entry is not found in the list, returns zero,
 *                   else returns non-zero.
 */

int hg_list_remove_entry(hg_list_entry_t **list, hg_list_entry_t *entry);

/**
 * Remove all occurrences of a particular value from a list.
 *
 * @param list       Pointer to the list.
 * @param callback   Function to invoke to compare values in the list
 *                   with the value to be removed.
 * @param data       The value to remove from the list.
 * @return           The number of entries removed from the list.
 */

unsigned int hg_list_remove_data(hg_list_entry_t **list, hg_list_equal_func_t callback,
                              hg_list_value_t data);

/**
 * Sort a list.
 *
 * @param list          Pointer to the list to sort.
 * @param compare_func  Function used to compare values in the list.
 */

void hg_list_sort(hg_list_entry_t **list, hg_list_compare_func_t compare_func);

/**
 * Find the entry for a particular value in a list.
 *
 * @param list           The list to search.
 * @param callback       Function to invoke to compare values in the list
 *                       with the value to be searched for.
 * @param data           The value to search for.
 * @return               The list entry of the item being searched for, or
 *                       NULL if not found.
 */

hg_list_entry_t *hg_list_find_data(hg_list_entry_t *list,
                          hg_list_equal_func_t callback,
                          hg_list_value_t data);

/** 
 * Initialize a @ref hg_list_iter_t structure to iterate over a list.
 *
 * @param list           A pointer to the list to iterate over.
 * @param iter           A pointer to an iterator structure to initialize.
 */

void hg_list_iterate(hg_list_entry_t **list, hg_list_iter_t *iter);

/**
 * Determine if there are more values in the list to iterate over.
 *
 * @param iterator       The list iterator.
 * @return               Zero if there are no more values in the list to
 *                       iterate over, non-zero if there are more values to
 *                       read.
 */

int hg_list_iter_has_more(hg_list_iter_t *iterator);

/**
 * Using a list iterator, retrieve the next value from the list. 
 *
 * @param iterator       The list iterator.
 * @return               The next value from the list, or @ref HG_LIST_NULL if
 *                       there are no more values in the list.
 */
	
hg_list_value_t hg_list_iter_next(hg_list_iter_t *iterator);

/** 
 * Delete the current entry in the list (the value last returned from
 * list_iter_next)
 *
 * @param iterator       The list iterator.
 */

void hg_list_iter_remove(hg_list_iter_t *iterator);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_LIST_H */

