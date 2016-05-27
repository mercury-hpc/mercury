#include <stdlib.h>
#include <stdio.h>

#include "protocol_common.h"
#include <mercury_proc_string.h>

hg_return_t my_in_proc_cb01(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_in_t *in_data;

	in_data = (my_rpc_test_in_t *) data;
	ret = hg_proc_hg_int32_t(proc, &in_data->aa);

	return ret;
}

hg_return_t my_in_proc_cb02(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_in_t *in_data;

	in_data = (my_rpc_test_in_t *) data;
	ret = hg_proc_hg_int32_t(proc, &in_data->aa);

	return ret;
}

hg_return_t my_in_proc_cb03(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_in_t *in_data;

	in_data = (my_rpc_test_in_t *) data;
	ret = hg_proc_hg_int32_t(proc, &in_data->aa);

	return ret;
}

hg_return_t my_out_proc_cb01(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_out_t *out_data;

	fprintf(stderr, "proc_cb01 starting to work\n");
	out_data = (my_rpc_test_out_t *) data;
	ret = hg_proc_hg_int32_t(proc, &out_data->bb);

	fprintf(stderr, "proc_cb01 responded\n");
	return ret;
}

hg_return_t my_out_proc_cb02(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_out_t *out_data;

	out_data = (my_rpc_test_out_t *) data;
	ret = hg_proc_hg_int32_t(proc, &out_data->bb);

	return ret;
}

hg_return_t my_out_proc_cb03(hg_proc_t proc, void *data)
{
	hg_return_t ret;

	my_rpc_test_out_t *out_data;

	out_data = (my_rpc_test_out_t *) data;
	ret = hg_proc_hg_int32_t(proc, &out_data->bb);

	return ret;
}

hg_return_t my_rpc_handler01(hg_handle_t handle)
{
	my_rpc_test_in_t in_struct;
	my_rpc_test_out_t out_struct;

	HG_Get_input(handle, &in_struct);
	fprintf(stdout, "rpc_handler 1 ");
	fprintf(stdout, "input argument: %d\n", in_struct.aa);
	out_struct.bb = in_struct.aa + 1;
	HG_Respond(handle, NULL, NULL, &out_struct);

	return 0;
}

hg_return_t my_rpc_handler02(hg_handle_t handle)
{
	my_rpc_test_in_t in_struct;
	my_rpc_test_out_t out_struct;

	HG_Get_input(handle, &in_struct);
	fprintf(stdout, "rpc_handler 2 ");
	fprintf(stdout, "input argument: %d\n", in_struct.aa);
	out_struct.bb = in_struct.aa + 2;
	HG_Respond(handle, NULL, NULL, &out_struct);

	return 0;
}

hg_return_t my_rpc_handler03(hg_handle_t handle)
{
	my_rpc_test_in_t in_struct;
	my_rpc_test_out_t out_struct;

	HG_Get_input(handle, &in_struct);
	fprintf(stdout, "rpc_handler 3 ");
	fprintf(stdout, "input argument: %d\n", in_struct.aa);
	out_struct.bb = in_struct.aa + 3;
	HG_Respond(handle, NULL, NULL, &out_struct);
	hg_atomic_set32(&example_protocol_finalizing_g, 1);

	return 0;
}


/**
 * this function is a copy paste from the Mercury tester.
 */
static na_return_t
my_na_addr_lookup_cb(const struct na_cb_info *callback_info)
{
	na_addr_t *addr_ptr = (na_addr_t *) callback_info->arg;
	na_return_t ret = NA_SUCCESS;

	if (callback_info->ret != NA_SUCCESS) {
		fprintf(stderr, "Return from callback with %s error code\n",
				NA_Error_to_string(callback_info->ret));
		return ret;
	}

	*addr_ptr = callback_info->info.lookup.addr;

	return ret;
}

/**
 * this function is a copy paste from the Mercury tester.
 */
na_return_t
my_na_addr_lookup_wait(na_class_t *na_class, const char *name, na_addr_t *addr)
{
	na_addr_t new_addr = NULL;
	na_bool_t lookup_completed = NA_FALSE;
	na_context_t *context = NULL;
	na_return_t ret = NA_SUCCESS;

	context = NA_Context_create(na_class);
	if (!context) {
		fprintf(stderr, "Could not create context\n");
		goto done;
	}

	ret = NA_Addr_lookup(na_class, context, &my_na_addr_lookup_cb,
			     &new_addr, name, NA_OP_ID_IGNORE);
	if (ret != NA_SUCCESS) {
		fprintf(stderr, "Could not start NA_Addr_lookup\n");
		goto done;
	}

	while (!lookup_completed) {
		na_return_t trigger_ret;
		unsigned int actual_count = 0;

		do {
			trigger_ret = NA_Trigger(context, 0, 1, &actual_count);
		} while ((trigger_ret == NA_SUCCESS) && actual_count);

		if (new_addr) {
			lookup_completed = NA_TRUE;
			*addr = new_addr;
		}

		if (lookup_completed)
			break;

		ret = NA_Progress(na_class, context, NA_MAX_IDLE_TIME);
		if (ret != NA_SUCCESS) {
			fprintf(stderr, "Could not make progress\n");
			goto done;
		}
	}

	ret = NA_Context_destroy(na_class, context);
	if (ret != NA_SUCCESS) {
		fprintf(stderr, "Could not destroy context\n");
		goto done;
	}

done:
	return ret;
}
