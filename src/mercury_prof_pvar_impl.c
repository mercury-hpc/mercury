/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_bulk.h"
#include "mercury_core.h"
#include "mercury_private.h"
#include "mercury_error.h"

#include "mercury_atomic.h"
#include "mercury_prof_interface.h"
#include "mercury_prof_pvar_impl.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*******************/
/* Local Variables */
/*******************/

static hg_hash_table_t *pvar_table; /* Internal hash table containing PVAR info */

HG_PROF_PVAR_UINT_COUNTER_DECL(hg_pvar_hg_forward_count); /* Declaring a PVAR */

/* Internal routines for the pvar_hash_table data structure */
static HG_INLINE int
hg_prof_uint_equal(void *vlocation1, void *vlocation2)
{
    return *((unsigned int *) vlocation1) == *((unsigned int *) vlocation2);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE unsigned int
hg_prof_uint_hash(void *vlocation)
{
    return *((unsigned int *) vlocation);
}

/*---------------------------------------------------------------------------*/

hg_prof_pvar_data_t *
hg_prof_pvar_table_lookup(unsigned int key)
{
    return hg_hash_table_lookup(pvar_table, (hg_hash_table_key_t)(&key));
}
/*---------------------------------------------------------------------------*/

void 
HG_PROF_PVAR_REGISTER_impl(hg_prof_class_t varclass, hg_prof_datatype_t dtype, const char* name, void *addr, int count,
    hg_prof_bind_t bind, int continuous, const char * desc) {

    unsigned int * key = NULL;
    key = (unsigned int *)malloc(sizeof(unsigned int));
    *key = hg_hash_table_num_entries(pvar_table);
    hg_prof_pvar_data_t * pvar_info = NULL;
    pvar_info = (hg_prof_pvar_data_t *)malloc(sizeof(hg_prof_pvar_data_t));
    (*pvar_info).pvar_class = varclass;
    (*pvar_info).pvar_datatype = dtype;
    (*pvar_info).pvar_bind = bind;
    (*pvar_info).count = count;
    (*pvar_info).addr = addr;
    strcpy((*pvar_info).name, name);
    strcpy((*pvar_info).description, desc);
    (*pvar_info).continuous = continuous;
    hg_hash_table_insert(pvar_table, (hg_hash_table_key_t)key, (hg_hash_table_value_t)(pvar_info));
}

/*---------------------------------------------------------------------------*/
hg_return_t 
hg_prof_pvar_init() {

    /*Initialize internal PVAR data structures*/
    pvar_table = hg_hash_table_new(hg_prof_uint_hash, hg_prof_uint_equal);
    /* Register available PVARs */
    HG_PROF_PVAR_UINT_COUNTER_REGISTER(HG_UINT, HG_PROF_BIND_NO_OBJECT, hg_pvar_hg_forward_count, "Number of times HG_Forward has been invoked");
    HG_PROF_PVAR_UINT_COUNTER_REGISTER(HG_UINT, HG_PROF_BIND_NO_OBJECT, hg_pvar_dummy, "Dummy");

return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
