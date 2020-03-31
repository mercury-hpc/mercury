/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury.h"
#include "mercury_bulk.h"
#include "mercury_core.h"
#include "mercury_private.h"
#include "mercury_error.h"

#include "mercury_atomic.h"
#include "mercury_types.h"
#include "mercury_prof_interface.h"
#include "mercury_prof_pvar_impl.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* HG profiling PVAR handle object concrete definition */
struct hg_prof_pvar_handle {
   hg_prof_class_t pvar_class; /* PVAR class */
   hg_prof_datatype_t pvar_datatype; /* PVAR datatype */
   hg_prof_bind_t pvar_bind; /* PVAR binding */
   int continuous; /* is PVAR continuous or not */
   void * addr; /* actual address of PVAR */
   int is_started; /* if continuous, has PVAR been started? */
   int count; /* number of values associated with PVAR */
   char name[128]; /* PVAR name */
   char description[128]; /* PVAR description */
};

/* HG profiling session object concrete definition */
struct hg_prof_pvar_session {
   hg_prof_pvar_handle_t * pvar_handle_array; /* PVAR handle array */
   int is_initialized;     /* Is profiling initialized */
};

/* HG class */
struct hg_private_class {
    struct hg_class hg_class;       /* Must remain as first field */
    int hg_prof_is_initialized;     /* Is profiling initialized */
    int num_pvars;          /* No of PVARs currently supported */
    hg_prof_pvar_session_t session; /* Is profiling initialized on the session */
};

/*******************/
/* Local Variables */
/*******************/

/*---------------------------------------------------------------------------*/
static void 
hg_prof_set_is_initialized(struct hg_private_class * hg_private_class)
{
  hg_private_class->hg_prof_is_initialized = 1;
}

/*---------------------------------------------------------------------------*/
static int 
hg_prof_get_is_initialized(struct hg_private_class * hg_private_class) {
   return hg_private_class->hg_prof_is_initialized;
}

/*---------------------------------------------------------------------------*/
static void 
hg_prof_set_session_is_initialized(struct hg_prof_pvar_session * session)
{
  session->is_initialized = 1;
}

/*---------------------------------------------------------------------------*/
static int 
hg_prof_get_session_is_initialized(struct hg_prof_pvar_session * session) {
   return session->is_initialized;
}

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_init(hg_class_t *hg_class) {

  struct hg_private_class *hg_private_class = (struct hg_private_class *)(hg_class);

  hg_prof_set_is_initialized(hg_private_class);
  hg_private_class->num_pvars = NUM_PVARS;

  return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_finalize(hg_class_t *hg_class) {

  struct hg_private_class *hg_private_class = (struct hg_private_class *)(hg_class);

  if(hg_prof_get_is_initialized(hg_private_class)) {
    hg_prof_set_is_initialized(hg_private_class);
  }

  fprintf(stderr, "[MERCURY_PROF_INTERFACE] Successfully shutting down profiling interface\n");
  return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int 
HG_Prof_pvar_get_num(hg_class_t *hg_class) {
  struct hg_private_class *hg_private_class = (struct hg_private_class *)(hg_class);

  if(hg_prof_get_is_initialized(hg_private_class)) {
    return hg_private_class->num_pvars;
  } else {
    return 0;
  }
}

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_pvar_get_info(hg_class_t *hg_class, int pvar_index, char *name, int *name_len, hg_prof_class_t *var_class, hg_prof_datatype_t *datatype, char *desc, int *desc_len, hg_prof_bind_t *bind, int *continuous) {
  
  struct hg_private_class *hg_private_class = (struct hg_private_class *)(hg_class);

  if(!hg_prof_get_is_initialized(hg_private_class))
    return HG_NA_ERROR;
 
  assert(pvar_index < NUM_PVARS);
 
  unsigned int key = pvar_index;
  hg_prof_pvar_data_t * val;

  /* Lookup the internal PVAR hash table to gather information about this PVAR */
  val = hg_prof_pvar_table_lookup(key);
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

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_pvar_session_create(hg_class_t *hg_class, hg_prof_pvar_session_t *session) {

  struct hg_private_class *hg_private_class = (struct hg_private_class *)(hg_class);

  if(!hg_prof_get_is_initialized(hg_private_class))
    return HG_NA_ERROR;

  (*session) = (hg_prof_pvar_session_t)malloc(sizeof(struct hg_prof_pvar_session));
  (*session)->pvar_handle_array = (hg_prof_pvar_handle_t *)malloc(sizeof(hg_prof_pvar_handle_t)*NUM_PVARS);
  hg_private_class->session = (*session);

  hg_prof_set_session_is_initialized((*session));

  return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_pvar_handle_alloc(hg_prof_pvar_session_t session, int pvar_index, void *obj_handle, hg_prof_pvar_handle_t *handle, int *count) {

  if(!hg_prof_get_session_is_initialized(session))
    return HG_NA_ERROR;

  /* Only supporting a null bind type at the moment */
  assert(obj_handle == NULL);

  struct hg_prof_pvar_session s = *session;
  unsigned int key = pvar_index;
  hg_prof_pvar_data_t * val;

  s.pvar_handle_array[pvar_index] = (hg_prof_pvar_handle_t)malloc(sizeof(struct hg_prof_pvar_handle));
  val = hg_prof_pvar_table_lookup(key);

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

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_pvar_start(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle) {
  if(!hg_prof_get_session_is_initialized(session))
    return HG_NA_ERROR;

  if (!(*handle).continuous && !((*handle).is_started))
     (*handle).is_started = 1;
  return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
hg_return_t 
HG_Prof_pvar_read(hg_prof_pvar_session_t session, hg_prof_pvar_handle_t handle, void *buf) {
  if(!hg_prof_get_session_is_initialized(session))
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
/*---------------------------------------------------------------------------*/
