/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_string_object.h"
#include "mercury_error.h"

#include <stdlib.h>
#include <string.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
hg_return_t
hg_string_object_init(hg_string_object_t *string)
{
    hg_return_t ret = HG_SUCCESS;

    string->data = NULL;
    string->is_owned = 0;
    string->is_const = 0;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_string_object_init_char(
    hg_string_object_t *string, char *s, hg_bool_t is_owned)
{
    hg_return_t ret = HG_SUCCESS;

    string->data = s;
    string->is_owned = is_owned;
    string->is_const = 0;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_string_object_init_const_char(
    hg_string_object_t *string, const char *s, hg_bool_t is_owned)
{
    union {
        char *p;
        const char *const_p;
    } safe_string = {.const_p = s};
    hg_return_t ret = HG_SUCCESS;

    string->data = safe_string.p;
    string->is_owned = is_owned;
    string->is_const = 1;

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_string_object_free(hg_string_object_t *string)
{
    hg_return_t ret = HG_SUCCESS;

    if (string->is_owned) {
        free(string->data);
        string->data = NULL;
    }

    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_string_object_dup(hg_string_object_t string, hg_string_object_t *new_string)
{
    hg_return_t ret = HG_SUCCESS;

    new_string->data = strdup(string.data);
    HG_CHECK_ERROR(new_string->data == NULL, done, ret, HG_NOMEM,
        "Could not dup string data");
    new_string->is_owned = 1;
    new_string->is_const = 0;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
char *
hg_string_object_swap(hg_string_object_t *string, char *s)
{
    char *old = string->data;

    string->data = s;
    string->is_const = 0;
    string->is_owned = 0;

    return old;
}
