#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <mercury.h>
#include "mercury_hl.h"
#include "mercury_atomic.h"

#include "protocol_common.h"

int main(void)
{
	na_class_t *na_class = NULL;
	na_context_t *na_context = NULL;
	hg_class_t *hg_class = NULL;
	hg_context_t *hg_context = NULL;
	hg_return_t ret;
	unsigned int count = 3;
	hg_id_t my_base_id;
	char *uri = "bmi+tcp://localhost:8898";
	unsigned int tmp_count = 0;
	unsigned int total_count = 0;
	struct rpc_func_t rpc_func[3] = {
		{.in_proc_cb = &my_in_proc_cb01,
		 .out_proc_cb = &my_out_proc_cb01,
		 .rpc_cb = my_rpc_handler01},
		{.in_proc_cb = &my_in_proc_cb02,
		 .out_proc_cb = &my_out_proc_cb02,
		 .rpc_cb = my_rpc_handler02},
		{.in_proc_cb = &my_in_proc_cb03,
		 .out_proc_cb = &my_out_proc_cb03,
		 .rpc_cb = my_rpc_handler03},
	};

	na_class = NA_Initialize(uri, NA_TRUE);
	assert(na_class);
	na_context = NA_Context_create(na_class);
	assert(na_context);

	ret = HG_Hl_init_na(na_class, na_context);
	if (ret != HG_SUCCESS) {
		fprintf(stderr, "Could not initialize Mercury\n");
		return ret;
	}
	hg_class = HG_CLASS_DEFAULT;
	hg_context = HG_CONTEXT_DEFAULT;

	hg_atomic_set32(&example_protocol_finalizing_g, 0);
	HG_Hl_protocol_init(hg_class);
	HG_Hl_register_protocol(hg_class, "PROTO_01", 0, rpc_func, count, &my_base_id);
	while (1) {
		do {
			tmp_count = 0;
			ret =
			    HG_Trigger(hg_context, 0, 1, &tmp_count);
			total_count += tmp_count;
		} while (ret == HG_SUCCESS && tmp_count);

		if (hg_atomic_cas32(&example_protocol_finalizing_g, 1, 1))
			break;

		HG_Progress(hg_context, 100);
	}

	ret = HG_Hl_finalize();
	if (ret != HG_SUCCESS) {
		fprintf(stderr, "Could not finalize HG\n");
		return ret;
	}
	NA_Context_destroy(na_class, na_context);
	NA_Finalize(na_class);
	fprintf(stderr, "server exiting\n");

	return 0;
}
