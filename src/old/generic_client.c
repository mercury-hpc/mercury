/*
 * generic_client.c
 */

#include "generic_client.h"
#include "network_bmi.h"
#include "network_mpi.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <pthread.h>
#include <stdbool.h>

#define ION_ENV "ZOIDFS_ION_NAME"

/* TODO (keep that for now) Define the ZOIDFS operations */
enum {
    PROTO_GENERIC = 16, /* TODO map to zoidfs proto */

    /* First invalid operation id */
    PROTO_MAX
};

static char *ion_name;
static na_addr_t ion_target = 0;

typedef struct {
    XDR  xdr;
    bool xdr_init;
} generic_xdr_t;

typedef struct {
    na_request_t send_request;
    na_request_t recv_request;
    void *       send_buf;
    void *       recv_buf;
    void *       out_param;
} generic_request_t;

/* TLS key for tag */
static pthread_key_t ptk_tag;
static unsigned int next_tag = 0;
static pthread_mutex_t tag_lock = PTHREAD_MUTEX_INITIALIZER;

#define NA_MAXTAG 65536

static void (*xdr_encode)(void *buf, na_size_t actual_size, void *in);
static void (*xdr_decode)(void *buf, na_size_t actual_size, void *out);

/*
 * In considering the multi-threaded client (e.g. FUSE), we use different tag
 * for communication to identify the threads. This enables that bmi_post_recv()
 * receives the proper message which is heading to the caller's thread.
 *
 * Tags above  ZOIDFS_BMI_MAXTAG are reserved for other uses.
 *
 * NOTE: Uses thread local storage now, but if we add full async support we
 * might want to use OpenPA and use an atomic increment. This will break
 * other things, as the code now seems to assume that gen_tag always returns
 * the same value for the same thread.
 */
static na_tag_t gen_tag(void)
{
    intptr_t tag;

    tag = (intptr_t) pthread_getspecific(ptk_tag);
    if (!tag) {
        pthread_mutex_lock(&tag_lock);
        tag = ++next_tag;
        pthread_mutex_unlock(&tag_lock);
        pthread_setspecific(ptk_tag, (void*) tag);
    }
    assert(tag < NA_MAXTAG);
    return tag;
}

/*
 * zoidfs message data types
 * Used by the zoidfs xdr processor to encode / decode data
 */
typedef enum {
    OP_ID_T = 0,
    OP_STATUS_T
} generic_msg_data_t;

#ifdef __APPLE__
#define XDR_UINT32 xdr_u_int32_t

#ifdef __LP64__
unsigned int
#else
unsigned long
#endif
xdr_sizeof(xdrproc_t func, void *data);

#else
#define XDR_UINT32 xdr_uint32_t
#endif

/*
 * xdr_generic_op_id_t
 * Encode/decode generic_op_id_t using XDR.
 */
static inline bool_t xdr_generic_op_id_t(XDR *xdrs, generic_op_id_t *op_id) {
    return(XDR_UINT32(xdrs, op_id));
}

/*
 * xdr_generic_op_status_t
 * Encode/decode generic_op_status_t using XDR.
 */
static inline bool_t xdr_generic_op_status_t(XDR *xdrs, generic_op_status_t *op_status) {
    return(xdr_int32_t(xdrs, op_status));
}

static unsigned int generic_xdr_size_processor(generic_msg_data_t data_t, void *data)
{
    unsigned int size = 0;
    if(data) {
        switch(data_t) {
            case OP_ID_T:
                size = xdr_sizeof((xdrproc_t)xdr_generic_op_id_t, data);
                break;
            case OP_STATUS_T:
                size = xdr_sizeof((xdrproc_t)xdr_generic_op_status_t, (generic_op_status_t *)data);
                break;
            default:
                fprintf(stderr, "%s(): processing error, unknown zoidfs data type, %s:%i.\n", __func__, __FILE__, __LINE__);
                size = 0;
                break;
        }
    }
    return size;
}

/*
 * xdr processing for generic messages
 */
static int generic_xdr_processor(generic_msg_data_t data_t, void *data, generic_xdr_t *xdr)
{
    switch(data_t) {
        case OP_ID_T:
            if (!xdr_generic_op_id_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_id_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        case OP_STATUS_T:
            if (!xdr_generic_op_status_t(&xdr->xdr, data)) {
                fprintf(stderr, "%s(): xdr_zoidfs_op_status_t() failed, %s:%i.\n", __func__, __FILE__, __LINE__);
            }
            break;
        default:
            fprintf(stderr, "%s(): processing error, unknown zoidfs data type, %s:%i.\n", __func__, __FILE__, __LINE__);
            break;
    }
    return 0;
}

static void generic_xdr_encode(void *buf, na_size_t actual_size, void *in)
{
    generic_xdr_t send_xdr;
    generic_op_id_t zoidfs_op_id = PROTO_GENERIC; /* TODO keep that for now */
    generic_op_id_t *in_op_id = (generic_op_id_t *) in;

    xdrmem_create(&send_xdr.xdr, buf, (unsigned int) actual_size, XDR_ENCODE);
    send_xdr.xdr_init = 1;
    generic_xdr_processor(OP_ID_T, &zoidfs_op_id, &send_xdr);
    generic_xdr_processor(OP_ID_T, in_op_id, &send_xdr);
}

static void generic_xdr_decode(void *buf, na_size_t actual_size, void *out)
{
    generic_xdr_t recv_xdr;
    generic_op_status_t zoidfs_op_status = 0;
    generic_op_status_t *out_op_status = (generic_op_status_t *) out;

    xdrmem_create(&recv_xdr.xdr, buf, (unsigned int) actual_size, XDR_DECODE);
    recv_xdr.xdr_init = 1;

    if (generic_xdr_processor(OP_STATUS_T, &zoidfs_op_status, &recv_xdr) != 0)
        fprintf(stderr, "generic_xdr_processor failed.\n");

    if(zoidfs_op_status == 0) {
        if (generic_xdr_processor(OP_STATUS_T, out_op_status, &recv_xdr) != 0)
            fprintf(stderr, "zoidfs_test_request: zoidfs_xdr_processor failed.\n");
    }
}

/*
 * Initialize the client subsystems.
 */
int generic_client_init(generic_na_id_t na_id) {

    /* Initialize the network interface here */
    switch (na_id) {
        case NA_BMI:
            na_bmi_init(NULL, NULL, 0);
            break;
        case NA_MPI:
        {
            FILE *config;
            na_mpi_init(NULL, 0);
            if ((config = fopen("port.cfg", "r")) != NULL) {
                char mpi_port_name[MPI_MAX_PORT_NAME];
                fread(mpi_port_name, sizeof(char), MPI_MAX_PORT_NAME, config);
                printf("Using MPI port name: %s.\n", mpi_port_name);
                fclose(config);
                setenv(ION_ENV, mpi_port_name, 1);
            }
        }
            break;
        default:
            fprintf(stderr, "unrecognized network ID\n");
            break;
    }

    /*
     * Pick up the ION hostname from an environment variable (ZOIDFS_ION_NAME).
     */
    ion_name = getenv(ION_ENV);
    if (!ion_name) {
        fprintf(stderr, "getenv(\"%s\") failed.\n", ION_ENV);
    }

    /* Perform an address lookup on the ION */
    na_addr_lookup(ion_name, &ion_target);

    /* Initialize TLS tags */
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;
    return 0;
}

/*
 * Finalize the client subsystems.
 */
int generic_client_finalize(void) {

    /* Cleanup peer_addr */
    if(ion_target) {
        na_addr_free(ion_target);
        ion_target = NULL;
    }
    na_finalize();

    /* Free TLS key */
    pthread_key_delete(ptk_tag);
    return 0;
}

int generic_client_register(/* const char *function_name, void (*in)(...), void (*out)(...) */)
{
    xdr_encode = generic_xdr_encode;
    xdr_decode = generic_xdr_decode;
    return 0;
}

/*
 * generic_client_forward
 * Executes task corresponding to generic op ID.
 */
int generic_client_forward(generic_op_id_t generic_op_id, generic_op_status_t *generic_op_status,
        generic_request_id_t *generic_request_id) {
    void *send_buf = NULL;
    void *recv_buf = NULL;
    na_size_t send_buf_len;
    na_size_t recv_buf_len;

    static int tag_incr = 0;
    na_tag_t send_tag, recv_tag;

    generic_op_id_t zoidfs_op_id = PROTO_GENERIC; /* TODO keep that for now */
    generic_op_status_t zoidfs_op_status;

    generic_request_t *generic_request = NULL;

    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > NA_MAXTAG) tag_incr = 0;

    send_buf_len = generic_xdr_size_processor(OP_ID_T, &zoidfs_op_id)
                + generic_xdr_size_processor(OP_ID_T, &generic_op_id);

    recv_buf_len = generic_xdr_size_processor(OP_STATUS_T, &zoidfs_op_status)
                    + generic_xdr_size_processor(OP_STATUS_T, generic_op_status);

    send_buf = malloc(send_buf_len);
    if (!send_buf) {
        fprintf(stderr, "send buffer allocation failed.\n");
    }
    recv_buf = malloc(recv_buf_len);
    if (!recv_buf) {
        fprintf(stderr, "recv buffer allocation failed.\n");
    }

    /* Encode the function parameters using XDR */
    xdr_encode(send_buf, send_buf_len, &generic_op_id);

    /* Post the send message and pre-post the recv message */
    generic_request = malloc(sizeof(generic_request_t));
    generic_request->send_buf = send_buf;
    generic_request->recv_buf = recv_buf;
    generic_request->out_param = (void*) generic_op_status;
    *generic_request_id = (generic_request_id_t) generic_request;

//    if (metadata) {
        na_send_unexpected(send_buf, send_buf_len, ion_target, send_tag, &generic_request->send_request, NULL);
        na_recv(recv_buf, recv_buf_len, ion_target, recv_tag, &generic_request->recv_request, NULL);
//    } else {
//        na_mem_register()
//    }
    return 0;
}

int generic_client_wait(generic_request_id_t generic_request_id)
{
    generic_request_t *generic_request = (generic_request_t*) generic_request_id;
    na_status_t recv_status;
    int ret = NA_SUCCESS;

    ret = na_wait(generic_request->send_request, NULL, NA_BMI_MAX_IDLE_TIME, NA_STATUS_IGNORE);
    ret = na_wait(generic_request->recv_request, NULL, NA_BMI_MAX_IDLE_TIME, &recv_status);

    /* Decode using XDR */
    xdr_decode(generic_request->recv_buf, recv_status.count,
            generic_request->out_param);

    free(generic_request->send_buf);
    free(generic_request->recv_buf);
    free(generic_request);
    generic_request = NULL;
    return ret;
}
