/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_THREAD_H
#define MERCURY_THREAD_H

#ifdef _WIN32
  #include <windows.h>
  typedef HANDLE hg_thread_t;
  typedef LPTHREAD_START_ROUTINE hg_thread_func_t;
  typedef DWORD hg_thread_ret_t;
  #define MERCURY_THREAD_RETURN_TYPE hg_thread_ret_t WINAPI
  typedef DWORD hg_thread_key_t;
#else
  #include <pthread.h>
  typedef pthread_t hg_thread_t;
  typedef void *(*hg_thread_func_t)(void *);
  typedef void *hg_thread_ret_t;
  #define MERCURY_THREAD_RETURN_TYPE hg_thread_ret_t
  typedef pthread_key_t hg_thread_key_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Init thread IDs */
void hg_thread_init(hg_thread_t *thread);

/* Create a new thread for the given function */
int hg_thread_create(hg_thread_t *thread, hg_thread_func_t f, void *data);

/* Wait for thread completion */
int hg_thread_join(hg_thread_t thread);

/* Terminate the thread */
int hg_thread_cancel(hg_thread_t thread);

/* Create a thread-specific data key visible to all threads in the process */
int hg_thread_key_create(hg_thread_key_t *key);

/* Delete a thread-specific data key previously returned by hg_thread_key_create() */
int hg_thread_key_delete(hg_thread_key_t key);

/* Get value from specified key */
void *hg_thread_getspecific(hg_thread_key_t key);

/* Set value to specified key */
int hg_thread_setspecific(hg_thread_key_t key, const void *value);

#ifdef __cplusplus
}
#endif

#endif /* MERCURY_THREAD_H */
