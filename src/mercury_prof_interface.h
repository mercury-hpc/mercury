/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_PROF_INTERFACE_H
#define MERCURY_PROF_INTERFACE_H

#include "mercury_prof_types.h"

/*Initialize and finalize routines */
HG_PUBLIC hg_return_t HG_Prof_init();
HG_PUBLIC hg_return_t HG_Prof_finalize();

/*Create a session */
HG_PUBLIC hg_return_t HG_Prof_pvar_session_create(hg_prof_pvar_session_t *session);

/* Gather information about PVARs */
HG_PUBLIC int HG_Prof_pvar_get_num();
HG_PUBLIC hg_return_t HG_Prof_pvar_get_info(int pvar_index, char *name, int *name_len, 
			hg_prof_class_t *var_class, hg_prof_datatype_t *datatype, 
			char *desc, int *desc_len, hg_prof_bind_t *bind, int *continuous);

/* Allocate handles */
HG_PUBLIC hg_return_t HG_Prof_pvar_handle_alloc(hg_prof_pvar_session_t session, 
			int pvar_index, void *obj_handle, hg_prof_pvar_handle_t *handle, int *count);

/* Start and read PVARs */
HG_PUBLIC hg_return_t HG_Prof_pvar_start(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle);
HG_PUBLIC hg_return_t HG_Prof_pvar_read(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle, void *buf);

#endif /* MERCURY_PROF_INTERFACE_H */
