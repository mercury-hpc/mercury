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

#include "handle_list.h"
#include "list.h"
#include "shipper_error.h"

static inline int pointer_equal(void *location1, void *location2)
{
    return location1 == location2;
}

//static inline unsigned int pointer_hash(void *location)
//{
//    return (unsigned int) (unsigned long) location;
//}

/*---------------------------------------------------------------------------
 * Function:    handle_list_free
 *
 * Purpose:     Free the list
 *
 *---------------------------------------------------------------------------
 */
void handle_list_free(handle_entry_t *list)
{
    list_free(list);
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_append
 *
 * Purpose:     Append a new entry to the list
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int handle_list_append(handle_entry_t **list, handle_value_t value)
{
    int ret = S_SUCCESS;

    if (!list_append(list, value)) {
        S_ERROR_DEFAULT("list_append failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_remove_entry
 *
 * Purpose:     Remove the entry from the list
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int handle_list_remove_entry(handle_entry_t **list, handle_entry_t *entry)
{
    int ret = S_SUCCESS;

    if (!list_remove_entry(list, entry)) {
        S_ERROR_DEFAULT("list_remove_entry failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_remove_data
 *
 * Purpose:     Remove the entry from the list
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int handle_list_remove_data(handle_entry_t **list, handle_value_t value)
{
    int ret = S_SUCCESS;

    if (!list_remove_data(list, pointer_equal, value)) {
        S_ERROR_DEFAULT("list_remove_data failed");
        ret = S_FAIL;
    }

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_next
 *
 * Purpose:     Retrieve next entry
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
handle_entry_t *handle_list_next(handle_entry_t *entry)
{
    return list_next(entry);
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_value
 *
 * Purpose:     Retrieve value at a list entry
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
handle_value_t handle_list_value(handle_entry_t *entry)
{
    return list_data(entry);
}

/*---------------------------------------------------------------------------
 * Function:    handle_list_get_size
 *
 * Purpose:     Get number of entries
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
unsigned int handle_list_get_size(handle_entry_t *list)
{
    return list_length(list);
}
