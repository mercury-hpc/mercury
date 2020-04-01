/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROF_PVAR_IMPL_H
#define MERCURY_PROF_PVAR_IMPL_H

#include "mercury_prof_types.h"
#include "mercury_hash_table.h"
#include "mercury_atomic.h"

/*************************************/
/* Public Type and Struct Definition */

/*************************************/

/* Internal PVAR data structure used to store PVAR data */
struct hg_prof_pvar_data_t {
   hg_prof_class_t pvar_class; /* PVAR class */
   hg_prof_datatype_t pvar_datatype; /* PVAR datatype */
   hg_prof_bind_t pvar_bind; /* PVAR binding */
   int continuous; /* Is PVAR continuous or not */
   void *addr; /* PVAR address */
   int count; /* count of PVAR values */
   char name[128]; /* PVAR name */
   char description[128]; /* PVAR description */
};

typedef struct hg_prof_pvar_data_t hg_prof_pvar_data_t;

/*****************/
/* Public Macros */
/*****************/

#define NUM_PVARS 1 /* Number of PVARs currently exported. PVAR indices go from 0......(NUM_PVARS - 1). */

/* PVAR handle declaration and registration macros */
#define HG_PROF_PVAR_UINT_COUNTER(name) \
    static hg_atomic_int32_t * addr_##name = NULL;

#define HG_PROF_PVAR_UINT_COUNTER_REGISTER(dtype, bind,\
            name, desc) \
        hg_atomic_int32_t *addr_##name = (hg_atomic_int32_t *)malloc(sizeof(hg_atomic_int32_t)); \
        /* Set initial value */ \
        hg_atomic_init32(addr_##name, 0); \
        HG_PROF_PVAR_REGISTER_impl(HG_PVAR_CLASS_COUNTER, dtype, #name, \
            (void *)addr_##name, 1, bind, 1, desc); 

/* Increment the value of a PVAR */
#define HG_PROF_PVAR_COUNTER_INC(name, val) \
    addr_##name = (addr_##name == NULL ? hg_prof_get_pvar_addr_from_name(#name): addr_##name); \
    for(int i=0; i < val; i++) \
        hg_atomic_incr32(addr_##name);

/**
 * Internal routine that gets invoked during Mercury's own initialization routine.
 * General routine for initializing the PVAR data structures and registering any PVARs that are not bound to a specific module.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
hg_return_t 
hg_prof_pvar_init();

/**
 * Internal routine that gets invoked during Mercury's own finalization routine.
 * General routine for finalizing and freeing the internal PVAR data structures.
 *
 * \return HG_SUCCESS or corresponding HG error code
 */
hg_return_t 
hg_prof_pvar_finalize();

/**
 * Internal routine that returns the PVAR address associated with the name.
 *
 * \param name [IN]	  PVAR name
 * \return hg_atomic_int32_t* that represents the PVAR addr
 */
hg_atomic_int32_t *
hg_prof_get_pvar_addr_from_name(const char* name);

/**
 * Internal routine that returns the PVAR data associated with a key representing index.
 *
 * \param key [IN]	  PVAR index key
 * \return hg_prof_pvar_data_t that represents the PVAR data
 */
hg_prof_pvar_data_t * 
hg_prof_pvar_table_lookup(unsigned int key);


/**
 * PVAR registration function. Used by internal Mercury modules to register any PVARs that they export.
 * \param varclass [IN]	  PVAR class
 * \param dtype [IN]	  PVAR datatype
 * \param name [IN] 	  PVAR name
 * \param addr [IN]	  PVAR address
 * \param count [IN]	  PVAR count
 * \param bind [IN]	  PVAR binding
 * \param continuous [IN] Is PVAR continuous or not
 * \param desc [IN]	  PVAR description
 */
extern void 
HG_PROF_PVAR_REGISTER_impl(
    hg_prof_class_t varclass, hg_prof_datatype_t dtype, const char* name, void *addr, int count,
    hg_prof_bind_t bind, int continuous, const char * desc);

#endif /* MERCURY_PROF_PVAR_IMPL_H */
