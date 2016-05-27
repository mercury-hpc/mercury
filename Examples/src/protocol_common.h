#include <stdio.h>
#include <assert.h>

#include <mercury.h>
#include "mercury_atomic.h"


hg_return_t my_in_proc_cb01(hg_proc_t proc, void *data);
hg_return_t my_in_proc_cb02(hg_proc_t proc, void *data);
hg_return_t my_in_proc_cb03(hg_proc_t proc, void *data);
hg_return_t my_out_proc_cb01(hg_proc_t proc, void *data);
hg_return_t my_out_proc_cb02(hg_proc_t proc, void *data);
hg_return_t my_out_proc_cb03(hg_proc_t proc, void *data);
hg_return_t my_rpc_handler01(hg_handle_t handle);
hg_return_t my_rpc_handler02(hg_handle_t handle);
hg_return_t my_rpc_handler03(hg_handle_t handle);

typedef struct {
	int32_t aa;
} my_rpc_test_in_t;

typedef struct {
	int32_t bb;
} my_rpc_test_out_t;

na_return_t
my_na_addr_lookup_wait(na_class_t *na_class, const char *name, na_addr_t *addr);

hg_atomic_int32_t example_protocol_finalizing_g;
