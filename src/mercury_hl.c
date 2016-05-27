/*
 * Copyright (C) 2013-2016 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_hl.h"
#include "mercury_hash_string.h"
#include "mercury_proc_header.h"
#include "mercury_proc.h"
#include "mercury_error.h"
#include "mercury_proc_string.h"
#include <string.h>

#include <stdlib.h>

/****************/
/* Local Macros */
/****************/

/************************************/
/* Local Type and Struct Definition */
/************************************/
struct hg_lookup_request_arg {
    hg_addr_t *addr_ptr;
    hg_request_t *request;
};

/********************/
/* Local Prototypes */
/********************/

static int
hg_hl_request_progress(
        unsigned int timeout,
        void *arg
        );

static int
hg_hl_request_trigger(
        unsigned int timeout,
        unsigned int *flag,
        void *arg
        );

static hg_return_t
hg_hl_addr_lookup_cb(
        const struct hg_cb_info *callback_info
        );

static hg_return_t
hg_hl_forward_cb(
        const struct hg_cb_info *callback_info
        );

static hg_return_t
hg_hl_bulk_transfer_cb(
        const struct hg_cb_info *callback_info
        );

static void
hg_hl_finalize(
        void
        );

/*******************/
/* Local Variables */
/*******************/

/* HG default */
hg_class_t *HG_CLASS_DEFAULT = NULL;
hg_context_t *HG_CONTEXT_DEFAULT = NULL;
hg_request_class_t *HG_REQUEST_CLASS_DEFAULT = NULL;

/* For convenience, register HG_Hl_finalize() */
static hg_bool_t hg_atexit_g = HG_FALSE;

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_progress(unsigned int timeout, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Progress(context, timeout) != HG_SUCCESS)
        ret = HG_UTIL_FAIL;

    return ret;
}

/*---------------------------------------------------------------------------*/
static int
hg_hl_request_trigger(unsigned int timeout, unsigned int *flag, void *arg)
{
    hg_context_t *context = (hg_context_t *) arg;
    unsigned int actual_count = 0;
    int ret = HG_UTIL_SUCCESS;

    if (HG_Trigger(context, timeout, 1, &actual_count)
            != HG_SUCCESS) ret = HG_UTIL_FAIL;
    *flag = (actual_count) ? HG_UTIL_TRUE : HG_UTIL_FALSE;

    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_addr_lookup_cb(const struct hg_cb_info *callback_info)
{
    struct hg_lookup_request_arg *request_args =
            (struct hg_lookup_request_arg *) callback_info->arg;

    *request_args->addr_ptr = callback_info->info.lookup.addr;

    hg_request_complete(request_args->request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_forward_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;

    hg_request_complete(request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_hl_bulk_transfer_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;

    hg_request_complete(request);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static void
hg_hl_finalize(void)
{
    HG_Hl_finalize();
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_init(const char *na_info_string, hg_bool_t na_listen)
{
    hg_return_t ret = HG_SUCCESS;

    /* First register finalize function if not set */
    if (!hg_atexit_g) {
        if (atexit(hg_hl_finalize) != 0) {
            HG_LOG_ERROR("Cannot set exit function");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        hg_atexit_g = HG_TRUE;
    }

    /* Get info string */
    if (!na_info_string) {
        na_info_string = getenv(HG_PORT_NAME);
    }
    if (!na_info_string) {
        HG_LOG_ERROR(HG_PORT_NAME " environment variable must be set");
        goto done;
    }

    /* Initialize HG */
    if (!HG_CLASS_DEFAULT) {
        HG_CLASS_DEFAULT = HG_Init(na_info_string, na_listen);
        if (!HG_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not initialize HG class");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Create HG context */
    if (!HG_CONTEXT_DEFAULT) {
        HG_CONTEXT_DEFAULT = HG_Context_create(HG_CLASS_DEFAULT);
        if (!HG_CONTEXT_DEFAULT) {
            HG_LOG_ERROR("Could not create HG context");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Initialize request class */
    if (!HG_REQUEST_CLASS_DEFAULT) {
        HG_REQUEST_CLASS_DEFAULT = hg_request_init(hg_hl_request_progress,
                hg_hl_request_trigger, HG_CONTEXT_DEFAULT);
        if (!HG_REQUEST_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not create HG request class");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_init_na(na_class_t *na_class)
{
    hg_return_t ret = HG_SUCCESS;

    /* First register finalize function if not set */
    if (!hg_atexit_g) {
        if (atexit(hg_hl_finalize) != 0) {
            HG_LOG_ERROR("Cannot set exit function");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        hg_atexit_g = HG_TRUE;
    }

    /* Initialize HG */
    if (!HG_CLASS_DEFAULT) {
        HG_CLASS_DEFAULT = HG_Init_na(na_class);
        if (!HG_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not initialize HG class");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Create HG context */
    if (!HG_CONTEXT_DEFAULT) {
        HG_CONTEXT_DEFAULT = HG_Context_create(HG_CLASS_DEFAULT);
        if (!HG_CONTEXT_DEFAULT) {
            HG_LOG_ERROR("Could not create HG context");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    /* Initialize request class */
    if (!HG_REQUEST_CLASS_DEFAULT) {
        HG_REQUEST_CLASS_DEFAULT = hg_request_init(hg_hl_request_progress,
                hg_hl_request_trigger, HG_CONTEXT_DEFAULT);
        if (!HG_REQUEST_CLASS_DEFAULT) {
            HG_LOG_ERROR("Could not create HG request class");
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_finalize(void)
{
    hg_return_t ret = HG_SUCCESS;

    /* Finalize request class */
    hg_request_finalize(HG_REQUEST_CLASS_DEFAULT, NULL);
    HG_REQUEST_CLASS_DEFAULT = NULL;

    /* Destroy context */
    ret = HG_Context_destroy(HG_CONTEXT_DEFAULT);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not destroy HG context");
        goto done;
    }
    HG_CONTEXT_DEFAULT = NULL;

    /* Finalize interface */
    ret = HG_Finalize(HG_CLASS_DEFAULT);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not finalize HG class");
        goto done;
    }
    HG_CLASS_DEFAULT = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_addr_lookup_wait(hg_context_t *context, hg_request_class_t *request_class,
    const char *name, hg_addr_t *addr, unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;
    struct hg_lookup_request_arg request_args;

    if (!request_class) {
        HG_LOG_ERROR("Uninitialized request class");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    request = hg_request_create(request_class);
    request_args.addr_ptr = addr;
    request_args.request = request;

    /* Forward call to remote addr and get a new request */
    ret = HG_Addr_lookup(context, hg_hl_addr_lookup_cb, &request_args, name,
            HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not lookup address");
        goto done;
    }

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    if (!flag) {
        HG_LOG_ERROR("Operation did not complete");
        ret = HG_TIMEOUT;
        goto done;
    }

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;

}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_forward_wait(hg_request_class_t *request_class, hg_handle_t handle,
    void *in_struct, unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    if (!request_class) {
        HG_LOG_ERROR("Uninitialized request class");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    request = hg_request_create(request_class);

    /* Forward call to remote addr and get a new request */
    ret = HG_Forward(handle, hg_hl_forward_cb, request, in_struct);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not forward call");
        goto done;
    }

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    if (!flag) {
        HG_LOG_ERROR("Operation did not complete");
        ret = HG_TIMEOUT;
        goto done;
    }

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
HG_Hl_bulk_transfer_wait(hg_context_t *context,
    hg_request_class_t *request_class, hg_bulk_op_t op,
    hg_addr_t origin_addr, hg_bulk_t origin_handle, hg_size_t origin_offset,
    hg_bulk_t local_handle, hg_size_t local_offset, hg_size_t size,
    unsigned int timeout)
{
    hg_request_t *request = NULL;
    hg_return_t ret = HG_SUCCESS;
    unsigned int flag = 0;

    if (!request_class) {
        HG_LOG_ERROR("Uninitialized request class");
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }

    request = hg_request_create(request_class);

    /* Transfer bulk data */
    ret = HG_Bulk_transfer(context, hg_hl_bulk_transfer_cb, request, op,
            origin_addr, origin_handle, origin_offset, local_handle,
            local_offset, size, HG_OP_ID_IGNORE);
    if (ret != HG_SUCCESS) {
        HG_LOG_ERROR("Could not transfer data");
        goto done;
    }

    /* Wait for request to be marked completed */
    hg_request_wait(request, timeout, &flag);
    if (!flag) {
        HG_LOG_ERROR("Operation did not complete");
        ret = HG_TIMEOUT;
        goto done;
    }

    /* Free request */
    hg_request_destroy(request);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
/* list nodes for storing registered protocols */
struct hg_protocol_list_node {
	struct hg_protocol_list_node *next;
	hg_id_t base_id;
	char protocol_name[HG_PROTOCOL_NAME_MAX];
	int version;
};

hg_return_t
HG_Hl_register_protocol(
	hg_class_t *hg_class,
	char *protocol_name,
	int version,
	struct rpc_func_t *rpc_func,
	int count,
	hg_id_t  *base_id
	)
{
	char tmp_name[64];

	if (strnlen(protocol_name,  HG_PROTOCOL_NAME_MAX + 1)
			> HG_PROTOCOL_NAME_MAX)
		return HG_PROTOCOL_NAME_TOO_LONG;
	snprintf(tmp_name, 64, "%s%d", protocol_name, version);
	*base_id = hg_hash_string(tmp_name);
	return HG_Hl_register_protocol_base(hg_class, protocol_name, version,
			rpc_func, count, *base_id);
}

hg_return_t
HG_Hl_register_protocol_base(
	hg_class_t *hg_class,
	char *protocol_name,
	int version,
	struct rpc_func_t *rpc_func,
	int count,
	hg_id_t  base_id
	)
{
	hg_return_t rc;
	int ii;

	if (strnlen(protocol_name,  HG_PROTOCOL_NAME_MAX + 1)
			> HG_PROTOCOL_NAME_MAX)
		return HG_PROTOCOL_NAME_TOO_LONG;
	for (ii = 0; ii < count; ii++) {
		rc = HG_Register(hg_class, base_id + ii + 1,
				rpc_func[ii].in_proc_cb,
				rpc_func[ii].out_proc_cb, rpc_func[ii].rpc_cb);
		if (rc != HG_SUCCESS)
			return rc;
	}
	return HG_Core_protocol_register_id(hg_class, protocol_name, version,
			base_id);
}

/** struct for the input of the rpc call */
struct hg_remote_registered_in_t {
	hg_id_t count;
	hg_const_string_t *protocol_name;
	int *version;
};

/** struct for the output of the rpc call */
struct hg_remote_registered_out_t {
	hg_id_t count;
	hg_id_t *results;
	hg_request_t *request;
};

hg_return_t
hg_proc_hg_remote_registered_in_t(hg_proc_t proc, void *data)
{
	hg_return_t ret;
	struct hg_remote_registered_in_t *in_data;
	int count;

	ret = HG_SUCCESS;
	in_data = (struct hg_remote_registered_in_t *) data;
	ret = hg_proc_hg_uint32_t(proc, &in_data->count);
	count = in_data->count;
	if (ret != HG_SUCCESS)
		return ret;
	if (in_data->protocol_name == NULL)
		in_data->protocol_name = (hg_const_string_t *)
			calloc(count, sizeof(hg_const_string_t));
	if (in_data->protocol_name == NULL)
		return HG_NOMEM_ERROR;
	if (in_data->version == NULL)
		in_data->version = (int *) calloc(count, sizeof(int));
	if (in_data->version == NULL)
		return HG_NOMEM_ERROR;
	for (int ii = 0; ii < count; ii++) {
		ret = hg_proc_hg_const_string_t(proc,
				&in_data->protocol_name[ii]);
		if (ret != HG_SUCCESS)
			return ret;
		ret = hg_proc_hg_int32_t(proc, &in_data->version[ii]);
		if (ret != HG_SUCCESS)
			return ret;
	}

	return ret;
}

hg_return_t
hg_proc_hg_remote_registered_out_t(hg_proc_t proc, void *data)
{
	hg_return_t ret;
	struct hg_remote_registered_out_t *out_data;
	int count;

	ret = HG_SUCCESS;
	out_data = (struct hg_remote_registered_out_t *) data;
	count = out_data->count;
	for (int ii = 0; ii < count; ii++) {
		ret = hg_proc_hg_uint32_t(proc, &(out_data->results[ii]));
		if (ret != HG_SUCCESS)
			return ret;
	}

	return ret;
}

/** the handler on the target */
static hg_return_t
HG_registered_remote_handler(hg_handle_t handle)
{
	/* extract input, check if registered locally, respond */
	struct hg_remote_registered_in_t ext_in_struct;
	struct hg_remote_registered_out_t ext_out_struct;
	hg_class_t *hg_class;
	const char *protocol_name;
	int version;
	int count;
	struct hg_info *hgi;

	hgi = HG_Get_info(handle);
	hg_class = hgi->hg_class;
	ext_in_struct.protocol_name = NULL;
	ext_in_struct.version = NULL;
	HG_Get_input(handle, &ext_in_struct);
	count = ext_in_struct.count;
	ext_out_struct.results = (hg_id_t *) calloc(count, sizeof(hg_id_t));
	for (int ii = 0; ii < count; ii++) {
		protocol_name = ext_in_struct.protocol_name[ii];
		version = ext_in_struct.version[ii];
		HG_Hl_registered_protocol(hg_class, protocol_name, version,
				&ext_out_struct.results[ii]);
	}
	HG_Free_input(handle, &ext_in_struct);
	free(ext_in_struct.protocol_name);
	free(ext_in_struct.version);
	ext_out_struct.count = count;
	HG_Respond(handle, NULL, NULL, &ext_out_struct);
	free(ext_out_struct.results);

	return HG_SUCCESS;
}

/** the callback on the origin */
static hg_return_t
hg_hl_registered_protocol_remote_cb(const struct hg_cb_info *info)
{
	/* extract output */
	hg_handle_t hg_handle;
	struct hg_remote_registered_out_t *user_data;

	user_data = (struct hg_remote_registered_out_t *) info->arg;
	hg_handle = info->info.forward.handle;
	HG_Get_output(hg_handle, user_data);
	hg_request_complete(user_data->request);

	return HG_SUCCESS;
}

hg_return_t HG_Hl_protocol_init(hg_class_t *hg_class)
{
	HG_Register_name(hg_class, "HG_registered_remote_handler",
			hg_proc_hg_remote_registered_in_t,
			hg_proc_hg_remote_registered_out_t,
			HG_registered_remote_handler);

	return HG_SUCCESS;
}

hg_return_t
HG_Hl_registered_protocol_remote_wait(
	hg_context_t *hg_context,
	hg_request_class_t *request_class,
	const char **protocol_name,
	int *version,
	int count,
	hg_addr_t addr,
	hg_id_t *results,
	unsigned int timeout
	)
{
	hg_request_t *request = NULL;
	hg_return_t ret = HG_SUCCESS;
	unsigned int flag = 0;
	struct hg_remote_registered_in_t ext_in_struct;
	struct hg_remote_registered_out_t ext_out_struct;
	hg_id_t query_rpc_id;
	hg_handle_t hg_handle;

	/* check protocol_name is not NULL */
	if (!request_class) {
		HG_LOG_ERROR("Uninitialized request class");
		ret = HG_PROTOCOL_ERROR;
		goto done;
	}
	request = hg_request_create(request_class);

	for (int ii = 0; ii < count; ii++) {
		if (strnlen(protocol_name[ii],  HG_PROTOCOL_NAME_MAX + 1)
				> HG_PROTOCOL_NAME_MAX)
			return HG_PROTOCOL_NAME_TOO_LONG;
	}
	query_rpc_id = hg_hash_string("HG_registered_remote_handler"); /** get rpc id */
	HG_Create(hg_context, addr, query_rpc_id, &hg_handle); /** create hg handle */
	ext_out_struct.results = results;
	ext_out_struct.count = count;
	ext_out_struct.request = request;

	ext_in_struct.protocol_name = protocol_name;
	ext_in_struct.version = version;
	ext_in_struct.count = count;
	/** forward call to remote addr and get a new request */
	ret = HG_Forward(hg_handle, hg_hl_registered_protocol_remote_cb, &ext_out_struct,
			&ext_in_struct);
	if (ret != HG_SUCCESS) {
		HG_LOG_ERROR("Could not lookup address");
		goto done;
	}

	/* Wait for request to be marked completed */
	hg_request_wait(request, timeout, &flag);
	if (!flag) {
		HG_LOG_ERROR("Operation did not complete");
		ret = HG_TIMEOUT;
		goto done;
	}

	/* Free request */
	hg_request_destroy(request);
	/* Free hg_handle */
	HG_Destroy(hg_handle);

done:
	return ret;
}

HG_EXPORT hg_return_t
HG_Hl_registered_protocol(
	hg_class_t *hg_class,
	const char *protocol_name,
	int version,
	hg_id_t *result
	)
{
	if (strnlen(protocol_name,  HG_PROTOCOL_NAME_MAX + 1)
			> HG_PROTOCOL_NAME_MAX)
		return HG_PROTOCOL_NAME_TOO_LONG;
	return HG_Core_registered_protocol(hg_class, protocol_name, version,
			result);
}
