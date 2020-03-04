/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROF_TYPES_H
#define MERCURY_PROF_TYPES_H

/* Public macros and definitions */
typedef struct hg_prof_pvar_handle * hg_prof_pvar_handle_t;
typedef struct hg_prof_pvar_session * hg_prof_pvar_session_t;

/* Enumerate the type of PVAR bindings available */
typedef enum {
   HG_PROF_BIND_NO_OBJECT,
   HG_PROF_BIND_HANDLE
} hg_prof_bind_t;

/* Enumerate the various types of PVAR classes */
typedef enum {
   HG_PVAR_CLASS_STATE,
   HG_PVAR_CLASS_COUNTER,
   HG_PVAR_CLASS_LEVEL,
   HG_PVAR_CLASS_SIZE,
   HG_PVAR_CLASS_HIGHWATERMARK,
   HG_PVAR_CLASS_LOWWATERMARK
} hg_prof_class_t;

/* Datatypes allowable with the PVAR interface */
typedef enum {
   HG_UINT,
   HG_DOUBLE
} hg_prof_datatype_t;

#endif /* MERCURY_PROF_TYPES_H */
