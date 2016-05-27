#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "mercury.h"
#include "mercury_hl.h"

#include "protocol_common.h"

struct my_rpc_cb_args {
	char *name;
	hg_request_t *request;
};

hg_return_t my_rpc_cb(const struct hg_cb_info *info)
{
	my_rpc_test_out_t out_struct;
	hg_handle_t hg_handle;
	struct my_rpc_cb_args *user_data;

	hg_handle = info->info.forward.handle;

	user_data = (struct my_rpc_cb_args *) info->arg;
	HG_Get_output(hg_handle, &out_struct);
	fprintf(stdout, "%s ", user_data->name);
	fprintf(stdout, "rpc_test finished on remote node, ");
	fprintf(stdout, "return value: %d\n", out_struct.bb);
	hg_request_complete(user_data->request);

	return 0;
}

int main(void)
{
	na_class_t *na_class = NULL;
	na_context_t *na_context = NULL;
	hg_class_t *hg_class = NULL;
	hg_context_t *hg_context = NULL;
	hg_handle_t my_hg_handle;
	hg_return_t ret;
	unsigned int count = 3;
	hg_id_t my_rpc_id[3];
	char *server_uri       = "bmi+tcp://localhost:8898";
	char *my_uri       = "bmi+tcp://localhost:8889";
	na_addr_t my_server_addr;
	my_rpc_test_in_t in_struct;
	struct rpc_func_t rpc_func[3] = {
		{.in_proc_cb = &my_in_proc_cb01,
		 .out_proc_cb = &my_out_proc_cb01,
		 .rpc_cb = NULL},
		{.in_proc_cb = &my_in_proc_cb02,
		 .out_proc_cb = &my_out_proc_cb02,
		 .rpc_cb = NULL},
		{.in_proc_cb = &my_in_proc_cb03,
		 .out_proc_cb = &my_out_proc_cb03,
		 .rpc_cb = NULL},
	};
	hg_id_t results[2];
	char *protocol_name[2];
	int versions[2];
	hg_request_class_t *request_class = NULL;
	hg_request_t *request = NULL;
	struct my_rpc_cb_args my_rpc_cb_args;



	na_class = NA_Initialize(my_uri, NA_FALSE);
	assert(na_class);
	na_context = NA_Context_create(na_class);
	assert(na_context);

	ret = HG_Hl_init_na(na_class, na_context);
	if (ret != HG_SUCCESS) {
		fprintf(stderr, "Could not initialize Mercury\n");
		return ret;
	}
	/* the following has to come after hl_init */
	hg_class = HG_CLASS_DEFAULT;
	hg_context = HG_CONTEXT_DEFAULT;
	request_class = HG_REQUEST_CLASS_DEFAULT;
	request = hg_request_create(request_class);


        /* Look up addr using port name info */
        ret = HG_Hl_addr_lookup_wait(hg_context, request_class,
                server_uri, &my_server_addr, HG_MAX_IDLE_TIME);
        if (ret != HG_SUCCESS) {
            fprintf(stderr, "Could not find addr %s\n", server_uri);
	    return ret;
        }

	protocol_name[0] = "PROTO_01";
	protocol_name[1] = "PROTO_01";
	versions[0] = 0;
	versions[1] = 1;
	HG_Hl_protocol_init(hg_class);
	HG_Hl_registered_protocol_remote_wait(hg_context, request_class,
			protocol_name, versions, 2, my_server_addr, results,
			HG_MAX_IDLE_TIME);
	fprintf(stderr, "is protocal registered remotely? %s base_id %u\n",
		results[0] ?  "yes" : "no", results[0]);
	fprintf(stderr, "is protocal registered remotely? %s base_id %u\n",
		results[1] ?  "yes" : "no", results[1]);

	HG_Hl_register_protocol_base(hg_class, "PROTO_01", 0, rpc_func, count,
			results[0]);

	my_rpc_id[0] = results[0] + 1;
	my_rpc_id[1] = results[0] + 2;
	my_rpc_id[2] = results[0] + 3;

	protocol_name[0] = "PROT0_02";
	protocol_name[1] = "PROT0_02";
	versions[0] = 0;
	versions[1] = 1;
	HG_Hl_registered_protocol_remote_wait(hg_context, request_class,
			protocol_name, versions, 2, my_server_addr, results,
			HG_MAX_IDLE_TIME);
	fprintf(stderr, "is protocal registered remotely? %s\n",
		results[0] ?  "yes" : "no");
	fprintf(stderr, "is protocal registered remotely? %s\n",
		results[1] ?  "yes" : "no");
	in_struct.aa = 10;
	my_rpc_cb_args.request = request;
	/* rpc01 */
	my_rpc_cb_args.name = "first call";
	HG_Create(hg_context, my_server_addr, my_rpc_id[0], &my_hg_handle);
	HG_Forward(my_hg_handle, my_rpc_cb, &my_rpc_cb_args, &in_struct);
	hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
	/* rpc02 */
	my_rpc_cb_args.name = "second call";
	HG_Create(hg_context, my_server_addr, my_rpc_id[1], &my_hg_handle);
	HG_Forward(my_hg_handle, my_rpc_cb, &my_rpc_cb_args, &in_struct);
	hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);
	/* rpc03 */
	my_rpc_cb_args.name = "third call";
	HG_Create(hg_context, my_server_addr, my_rpc_id[2], &my_hg_handle);
	HG_Forward(my_hg_handle, my_rpc_cb, &my_rpc_cb_args, &in_struct);
	hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

	HG_Destroy(my_hg_handle);
	ret = HG_Hl_finalize();
	if (ret != HG_SUCCESS) {
		fprintf(stderr, "Could not finalize HG\n");
		return ret;
	}
	NA_Context_destroy(na_class, na_context);
	NA_Finalize(na_class);
	fprintf(stderr, "client exiting\n");

	return 0;
}
