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

/* Number of PVARs currently exported
 * PVAR indices go from 0......(NUM_PVARS - 1) */
#define NUM_PVARS 1

/* Internal PVAR data structure used to store PVAR data, addr, etc */
struct hg_prof_pvar_data_t {
   hg_prof_class_t pvar_class;
   hg_prof_datatype_t pvar_datatype;
   hg_prof_bind_t pvar_bind;
   int continuous;
   void *addr;
   int count;
   char name[128];
   char description[128];
};

typedef struct hg_prof_pvar_data_t hg_prof_pvar_data_t;

extern hg_hash_table_t *pvar_table;

/* PVAR registration function. Used by internal mercury modules to register any PVARs that they export */
extern void HG_PROF_PVAR_REGISTER_impl(
    hg_prof_class_t varclass, hg_prof_datatype_t dtype, const char* name, void *addr, int count,
    hg_prof_bind_t bind, int continuous, const char * desc);

/* PVAR declaration and registration macros */
#define HG_PROF_PVAR_UINT_COUNTER_DECL(name) \
    unsigned int PVAR_COUNTER_##name;

#define HG_PROF_PVAR_UINT_COUNTER_DECL_EXTERN(name) \
    extern unsigned int PVAR_COUNTER_##name;

#define HG_PROF_PVAR_UINT_COUNTER_REGISTER(dtype, bind,\
            name, desc) \
        void *addr; \
        /* Set initial value */ \
        PVAR_COUNTER_##name = 0; \
        addr = &PVAR_COUNTER_##name; \
        HG_PROF_PVAR_REGISTER_impl(HG_PVAR_CLASS_COUNTER, dtype, #name, \
            addr, 1, bind, 1, desc); 

/* Macro to increment the value of a PVAR */
#define HG_PROF_PVAR_COUNTER_INC(name, val) \
    *(&PVAR_COUNTER_##name) += val;

hg_return_t hg_prof_pvar_init();
#endif /* MERCURY_PROF_PVAR_IMPL_H */
