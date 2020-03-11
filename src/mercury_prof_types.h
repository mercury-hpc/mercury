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

/*************************************/
/* Public Type and Struct Definition */
/*************************************/
typedef struct hg_prof_pvar_handle * hg_prof_pvar_handle_t;
typedef struct hg_prof_pvar_session * hg_prof_pvar_session_t;

/* Enumerate the type of PVAR bindings available */
typedef enum {
   HG_PROF_BIND_NO_OBJECT, /* PVARs that are not bound to any object */
   HG_PROF_BIND_HANDLE /* PVARs that are bound to Mercury handles */
} hg_prof_bind_t;

/* Enumerate the various types of PVAR classes */
typedef enum {
   HG_PVAR_CLASS_STATE, /* PVAR that represents any one of a set of discrete states */
   HG_PVAR_CLASS_COUNTER, /* PVAR that represents a regular monotonic counter */
   HG_PVAR_CLASS_LEVEL, /* PVAR that represents a utilization level (in percentage) of a given resource */
   HG_PVAR_CLASS_SIZE, /* PVAR that represents the size of a given resource at any given point in time */
   HG_PVAR_CLASS_HIGHWATERMARK, /* PVAR that represents a high watermark value */
   HG_PVAR_CLASS_LOWWATERMARK /* PVAR that represents a low watermark value */
} hg_prof_class_t;

/* Datatypes allowable with the PVAR interface */
typedef enum {
   HG_UINT, /* PVAR of type unsigned integer */
   HG_DOUBLE /* PVAR of type double */
} hg_prof_datatype_t;

#endif /* MERCURY_PROF_TYPES_H */
