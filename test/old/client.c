#include "generic_client.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum {
    INIT = 1,
    CREATE,
    CLOSE,
    FINALIZE
};

//#define GEN_ENCODE_NAME(name) { name##_xdr_encode }
//#define RPCGENENCODE(name, type1) \{ int name(type1); \}
//RPCGENENCODE(test, int)‎

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    generic_op_id_t in1 = INIT, in2 = CREATE, in3 = CLOSE, in4 = FINALIZE;
    generic_op_status_t out1 = 0, out2 = 0, out3 = 0, out4 = 0;
    generic_request_id_t req1 = NULL, req2 = NULL, req3 = NULL, req4 = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BMI|MPI>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp("MPI", argv[1]) == 0) {
        generic_client_init(NA_MPI);
    } else {
        generic_client_init(NA_BMI);
    }

    generic_client_register(/* generic, in_ptr, out_ptr */);
    generic_client_forward(in1, &out1, &req1);
    generic_client_forward(in2, &out2, &req2);
    generic_client_forward(in3, &out3, &req3);
    generic_client_forward(in4, &out4, &req4);

    generic_client_wait(req3);
    generic_client_wait(req4);
    generic_client_wait(req1);
    generic_client_wait(req2);

    printf("Received op status: %d, %d, %d, %d\n", out1, out2, out3, out4);

    if (out1 != INIT || out2 != CREATE || out3 != CLOSE || out4 != FINALIZE) {
        fprintf(stderr, "Error: Op status mismatch\n");
        ret = EXIT_FAILURE;
    }

    generic_client_finalize();
    return ret;
}
