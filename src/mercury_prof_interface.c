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

/* Variable denoting whether or not the profiling interface has been initialized */
static int hg_prof_is_initialized = 0;

/* Client-side PVAR handle that contains all information about the PVAR. Data structure is opaque to the client. 
 * Handle exists to make PVAR reads quicker */
struct hg_prof_pvar_handle {
   hg_prof_class_t pvar_class;
   hg_prof_datatype_t pvar_datatype;
   hg_prof_bind_t pvar_bind;
   int continuous;
   void * addr;
   int is_started;
   int count;
   char name[128];
   char description[128];
};

/* Client-side PVAR session. PVARs are associated with a session. As of now, we only support one default session */
struct hg_prof_pvar_session {
   hg_prof_pvar_handle_t * pvar_handle_array;
   int num_pvars;
   int reference_counter;
};

struct hg_prof_pvar_session default_session;

/* Setter and getter functions for profiling interface initialization */
static void hg_prof_set_is_initialized(int val)
{
  hg_prof_is_initialized = val;
}

static int hg_prof_get_is_initialized() {
   return hg_prof_is_initialized;
}

/* Client-side API to initialize the PVAR profiling interface */
hg_return_t HG_Prof_init() {

  default_session.reference_counter = 0;
  default_session.num_pvars = NUM_PVARS;
  default_session.pvar_handle_array = (hg_prof_pvar_handle_t *)malloc(sizeof(hg_prof_pvar_handle_t)*NUM_PVARS);
  hg_prof_set_is_initialized(1);

  return HG_SUCCESS;
}

/* Client-side API to finalize the PVAR profiling interface */
hg_return_t HG_Prof_finalize() {

  if(hg_prof_get_is_initialized()) {
    hg_prof_set_is_initialized(0);
  }

  fprintf(stderr, "[MERCURY_PROF_INTERFACE] Successfully shutting down profiling interface\n");
  return HG_SUCCESS;
}

/* Client-side API to retrieve the number of PVARs currently exported */
int HG_Prof_pvar_get_num() {
  if(hg_prof_get_is_initialized()) {
    return NUM_PVARS;
  } else {
    return 0;
  }
}

/* Gather information about every PVAR exported. This API is necessary in order for the client to discover the types, bindings, etc.
 * The client can then allocate the necessary data structures using this information */
hg_return_t HG_Prof_pvar_get_info(int pvar_index, char *name, int *name_len, hg_prof_class_t *var_class, hg_prof_datatype_t *datatype, char *desc, int *desc_len, hg_prof_bind_t *bind, int *continuous) {
  
  if(!hg_prof_get_is_initialized())
    return HG_NA_ERROR;
 
  assert(pvar_index < NUM_PVARS);
 
  unsigned int key = pvar_index;
  hg_prof_pvar_data_t * val;

  /* Lookup the internal PVAR hash table to gather information about this PVAR */
  val = hg_hash_table_lookup(pvar_table, (hg_hash_table_key_t)(&key));
  strcpy(name, (*val).name);
  *name_len = strlen(name);
  strcpy(desc, (*val).description);
  *desc_len = strlen(desc);
  *var_class = (*val).pvar_class;
  *datatype = (*val).pvar_datatype;
  *bind = (*val).pvar_bind;
  *continuous = (*val).continuous;

  return HG_SUCCESS;
}

/* Create a session. In this case, return a reference to the default session that is currently supported */
hg_return_t HG_Prof_pvar_session_create(hg_prof_pvar_session_t *session) {
  if(!hg_prof_get_is_initialized())
    return HG_NA_ERROR;

  default_session.reference_counter += 1;

  /* Only support one tool at the moment */
  assert(default_session.reference_counter == 1);

  *session = &default_session;

  return HG_SUCCESS;
}

/* Allocate a handle for a PVAR at a given index.
 * This handle will later be used by the client to query the value for the PVAR
 * This handle is an opaque object */
hg_return_t HG_Prof_pvar_handle_alloc(hg_prof_pvar_session_t session, int pvar_index, void *obj_handle, hg_prof_pvar_handle_t *handle, int *count) {

  if(!hg_prof_get_is_initialized())
    return HG_NA_ERROR;

  /* Only supporting a default session and null bind type at the moment */
  assert(session == &default_session);
  assert(obj_handle == NULL);

  struct hg_prof_pvar_session s = *session;
  unsigned int key = pvar_index;
  hg_prof_pvar_data_t * val;

  s.pvar_handle_array[pvar_index] = (hg_prof_pvar_handle_t)malloc(sizeof(struct hg_prof_pvar_handle));
  val = hg_hash_table_lookup(pvar_table, (hg_hash_table_key_t)(&key)); 

  /* Copy out information from the internal PVAR hash table */
  (*s.pvar_handle_array[pvar_index]).pvar_class = (*val).pvar_class;
  (*s.pvar_handle_array[pvar_index]).pvar_datatype = (*val).pvar_datatype;
  (*s.pvar_handle_array[pvar_index]).pvar_bind = (*val).pvar_bind;
  (*s.pvar_handle_array[pvar_index]).continuous = (*val).continuous;
  (*s.pvar_handle_array[pvar_index]).is_started = 0;
  (*s.pvar_handle_array[pvar_index]).addr = (*val).addr;
  if((*val).continuous)
    (*s.pvar_handle_array[pvar_index]).is_started = 1;
  strcpy((*s.pvar_handle_array[pvar_index]).name, (*val).name);
  strcpy((*s.pvar_handle_array[pvar_index]).description, (*val).description);
  *count = (*val).count;

  /* Return handle */
  *handle = s.pvar_handle_array[pvar_index];

  fprintf(stderr, "[MERCURY_PROF_INTERFACE] Successfully allocated handle for PVAR: %s\n", (*s.pvar_handle_array[pvar_index]).name);

  return HG_SUCCESS;
}

/* Start the PVAR is it is not continuous and has not been started yet */
hg_return_t HG_Prof_pvar_start(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle) {
  if(!hg_prof_get_is_initialized())
    return HG_NA_ERROR;
  if (!(*handle).continuous && !((*handle).is_started))
     (*handle).is_started = 1;
  return HG_SUCCESS;
}

/* Read the value of the PVAR when the client supplies the handle.
 * Note that the handle is necessary as the input (instead of the pvar_index) because there may be multiple PVAR sessions in flight */
hg_return_t HG_Prof_pvar_read(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle, void *buf) {
  if(!hg_prof_get_is_initialized())
    return HG_NA_ERROR;


  /* Assert first that handle belongs to the session provided. NOT DOING THIS HERE FOR NOW */

  struct hg_prof_pvar_handle h = (*handle);
  switch(h.pvar_datatype) {
    case HG_UINT:
      /*for(int i = 0; i < h.count; h++)*/ /* Need to support PVAR arrays, just a placeholder that assumes PVAR count is 1 */
      *((unsigned int *)buf) = *((unsigned int *)h.addr);
      break;
  }
  return HG_SUCCESS;
}
