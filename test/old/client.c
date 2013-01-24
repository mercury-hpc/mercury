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

#include <boost/preprocessor.hpp>

#include <mpi.h>


#define RPC_ENCODER(r,data,elem) RPC_ENCPROCESS(elem)
#define RPC_ENCPROCESS(elem) enc_struct.RPC_PICKNAME(elem) = RPC_GETNAME(elem);
#define RPC_GETNAME(elem)    BOOST_PP_SEQ_FOLD_LEFT(RPC_WFOLD,               \
                                        BOOST_PP_SEQ_HEAD(elem),             \
                                        BOOST_PP_SEQ_TAIL(elem))
#define RPC_PICKNAME(elem)  BOOST_PP_SEQ_CAT(BOOST_PP_SEQ_TAIL(elem))

#define RPC_DECPARAM(r,data,elem) RPC_DECPROCESS(elem)
#define RPC_DECPROCESS(elem) param_.RPC_PICKNAME(elem) = &dec_struct.RPC_PICKNAME(elem);
#define RPC_WFOLD(r,data,elem) data elem
#define RPC_GENPROCESS(NAME, DECODELIST, ENCLIST)                            \
      void NAME_dec()                                                        \
      {                                                                      \
         process(dec_, dec_struct);                                          \
      }                                                                      \
      void NAME_enc()                                                        \
      {                                                                      \
          BOOST_PP_SEQ_FOR_EACH(RPC_ENCODER, , ENCLIST)                      \
          process (enc_, enc_struct);                                        \
      }

#define REM(...) __VA_ARGS__
#define EAT(...)

/* Retrieve the type */
#define TYPEOF(x) DETAIL_TYPEOF(DETAIL_TYPEOF_PROBE x,)
#define DETAIL_TYPEOF(...) DETAIL_TYPEOF_HEAD(__VA_ARGS__)
#define DETAIL_TYPEOF_HEAD(x, ...) REM x
#define DETAIL_TYPEOF_PROBE(...) (__VA_ARGS__),
/* Strip off the type */
#define STRIP(x) EAT x
/* Show the type without parenthesis */
#define PAIR(x) REM x

#define DETAIL_DEFINE_MEMBERS_EACH(r, data, x) PAIR(x);
#define DETAIL_DEFINE_ARGS_EACH(r, data, i, x) BOOST_PP_COMMA_IF(i) PAIR(x)
//#define DETAIL_DEFINE_FORWARD_EACH(r, data, i, x) BOOST_PP_COMMA_IF(i) STRIP(x)

#define DETAIL_DEFINE_MEMBERS(args) BOOST_PP_SEQ_FOR_EACH(DETAIL_DEFINE_MEMBERS_EACH, _, BOOST_PP_VARIADIC_TO_SEQ args)
#define DETAIL_DEFINE_ARGS(args) BOOST_PP_SEQ_FOR_EACH_I(DETAIL_DEFINE_ARGS_EACH, _, BOOST_PP_VARIADIC_TO_SEQ args)
//#define DETAIL_DEFINE_FORWARD(args) BOOST_PP_SEQ_FOR_EACH_I(DETAIL_DEFINE_FORWARD_EACH, _, BOOST_PP_VARIADIC_TO_SEQ args)

//static void (*encoding)(void *buf, na_size_t actual_size, void *in);
//static void (*decoding)(void *buf, na_size_t actual_size, void *out);

#define DETAIL_DEFINE(name, args, ...)                                   \
/* input parameters */                                                   \
struct BOOST_PP_CAT(name, _in)                                           \
{                                                                        \
    DETAIL_DEFINE_MEMBERS(args)                                          \
};                                                                       \
/* output parameters */                                                  \
struct BOOST_PP_CAT(name, _out)                                          \
{                                                                        \
    __VA_ARGS__ value;                                                   \
};                                                                       \
/* encoding function */                                                  \
static void BOOST_PP_CAT(name, _enc) (struct BOOST_PP_CAT(name, _in) enc_struct)\
{                                                                        \
 /*   return BOOST_PP_CAT(name, _impl) (DETAIL_DEFINE_FORWARD(args)); */ \
}                                                                        \
/* decoding function */                                                  \
static void BOOST_PP_CAT(name, _dec) (DETAIL_DEFINE_ARGS(args))          \
{                                                                        \
/*    return BOOST_PP_CAT(name, _impl) (DETAIL_DEFINE_FORWARD(args));*/  \
}                                                                        \
/* rpc call */                                                           \
static __VA_ARGS__ BOOST_PP_CAT(name, _rpc) (DETAIL_DEFINE_ARGS(args))   \
{                                                                        \
    /* tbd */                                                            \
}

#define IOFSL_REGISTER(x) DETAIL_DEFINE(TYPEOF(STRIP(x)),                \
          (TYPEOF(STRIP(STRIP(x)))), TYPEOF(x))


/* Dummy IOD prototype */
typedef int iod_ret_t;
typedef int iod_event_t;
typedef struct {
    int num_entries;
    iod_event_t *event;
} iod_eventq_t;

IOFSL_REGISTER((iod_ret_t)(iod_instantiate)((MPI_Comm) comm, (iod_eventq_t*) eq))

/*
 * typedef struct in_name {} in_name;
 * typedef struct out_name {} out_name;
 * static void xdr_encode_name()
 * static void xdr_decode_name()
 *
 * iod_ret_t
 * iod_instantiate {
 * MPI_Comm comm,  IN so IOD's can communicate with each other
 * iod_eventq_t *eq, OUT pointer to the event queue for this iod
 * }
 *
 */

//IOFSL_REGISTER((int)(iod_foo)((int) a, (float) b))
//IOFSL_REGISTER((int)(iod_foo)((int) a_in, (float) b_in)((int*) c_out, (float*) b_out))
//IOFSL_REGISTER((int)(iod_bar)((unsigned int) a, (int*) b))
//IOFSL_REGISTER((int)(iod_baz)((double) a, (char) b))

int main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    generic_op_id_t id1 = INIT, id2 = CREATE, id3 = CLOSE, id4 = FINALIZE;
    generic_op_status_t out1 = 0, out2 = 0, out3 = 0, out4 = 0;
    generic_request_id_t req1 = NULL, req2 = NULL, req3 = NULL, req4 = NULL;
    iofsl_addr_t dest;

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
    generic_client_forward(id1, &out1, &req1);

//    iod_instantiate_rpc(dest, MPI_Comm com, iod_eventq_t *eq, &req1);

//    generic_client_forward(id1, dest, &in1, &out1, &req1);
    generic_client_forward(id2, &out2, &req2);
    generic_client_forward(id3, &out3, &req3);
    generic_client_forward(id4, &out4, &req4);

    generic_client_wait(req3);
    generic_client_wait(req4);
    generic_client_wait(req1);
    generic_client_wait(req2);

//    iofsl_rpc_wait(req1);

    printf("Executed op status: %d, %d, %d, %d\n", out1, out2, out3, out4);

    if (out1 != INIT || out2 != CREATE || out3 != CLOSE || out4 != FINALIZE) {
        fprintf(stderr, "Error: Op status mismatch\n");
        ret = EXIT_FAILURE;
    }

    generic_client_finalize();
    return ret;
}
