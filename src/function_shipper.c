/*
 * function_shipper.c
 */

#include "function_shipper.h"
#include "network_abstraction.h"
#include "iofsl_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

/* Private structs */
typedef struct fs_priv_request_t {
    na_request_t send_request;
    na_request_t recv_request;
    void *       send_buf;
    void *       recv_buf;
    void *       out_param;
} fs_priv_request_t;

static char *ion_name;
static na_addr_t ion_target = 0;

/* TLS key for tag */
static pthread_key_t ptk_tag;
static unsigned int next_tag = 0;
static pthread_mutex_t tag_lock = PTHREAD_MUTEX_INITIALIZER;

#define FS_MAXTAG 65536

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
    long int tag;

    tag = (long int) pthread_getspecific(ptk_tag);
    if (!tag) {
        pthread_mutex_lock(&tag_lock);
        tag = ++next_tag;
        pthread_mutex_unlock(&tag_lock);
        pthread_setspecific(ptk_tag, (void*) tag);
    }
    assert(tag < FS_MAXTAG);
    return tag;
}

/*---------------------------------------------------------------------------
 * Function:    fs_init
 *
 * Purpose:     Initialize the function shipper and select a network protocol
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_init()
{
    /* Perform an address lookup on the ION */
    na_addr_lookup(ion_name, &ion_target);

    /* Initialize TLS tags */
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;

    return 0;
}

/*---------------------------------------------------------------------------
 * Function:    fs_finalize
 *
 * Purpose:     Finalize the function shipper
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_finalize(void)
{
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

/*---------------------------------------------------------------------------
 * Function:    fs_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
fs_id_t fs_register(const char *name,
        int (*enc_routine)(void *buf, int buf_len, void *struct_in),
        int (*dec_routine)(void *struct_out, void *buf, int buf_len))
{
//    xdr_encode = generic_xdr_encode;
//    xdr_decode = generic_xdr_decode;
    return 0;
}

/*---------------------------------------------------------------------------
 * Function:    fs_forward
 *
 * Purpose:     Forward a call to a remote server
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_forward(fs_addr_t addr, fs_id_t id, void *struct_in, void *struct_out,
        fs_request_t *request)
{
    void *send_buf = NULL;
    void *recv_buf = NULL;
    na_size_t send_buf_len;
    na_size_t recv_buf_len;

    static int tag_incr = 0;
    na_tag_t send_tag, recv_tag;

    fs_id_t zoidfs_op_id = PROTO_GENERIC; /* TODO keep that for now */
    fs_status_t zoidfs_op_status;

    fs_priv_request_t *priv_request = NULL;

    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

//    send_buf_len = generic_xdr_size_processor(OP_ID_T, &zoidfs_op_id)
//                + generic_xdr_size_processor(OP_ID_T, &generic_op_id);
//
//    recv_buf_len = generic_xdr_size_processor(OP_STATUS_T, &zoidfs_op_status)
//                    + generic_xdr_size_processor(OP_STATUS_T, generic_op_status);

    send_buf = malloc(send_buf_len);
    if (!send_buf) {
        fprintf(stderr, "send buffer allocation failed.\n");
    }
    recv_buf = malloc(recv_buf_len);
    if (!recv_buf) {
        fprintf(stderr, "recv buffer allocation failed.\n");
    }

    /* Encode the function parameters using XDR */
//    xdr_encode(send_buf, send_buf_len, &generic_op_id);

    /* Post the send message and pre-post the recv message */
    priv_request = malloc(sizeof(fs_priv_request_t));
    priv_request->send_buf = send_buf;
    priv_request->recv_buf = recv_buf;
    priv_request->out_param = struct_out;
    *request = (fs_request_t) priv_request;

//    if (metadata) {
        na_send_unexpected(send_buf, send_buf_len, ion_target, send_tag, &priv_request->send_request, NULL);
        na_recv(recv_buf, recv_buf_len, ion_target, recv_tag, &priv_request->recv_request, NULL);
//    } else {
//        na_mem_register()
//    }
    return 0;
}

/*---------------------------------------------------------------------------
 * Function:    fs_wait
 *
 * Purpose:     Wait for an operation request to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_wait(fs_request_t request, unsigned int timeout, fs_status_t *status)
{
    fs_priv_request_t *priv_request = (fs_priv_request_t*) request;
    na_status_t recv_status;
    int ret = NA_SUCCESS;

    ret = na_wait(priv_request->send_request, timeout, NA_STATUS_IGNORE);
    ret = na_wait(priv_request->recv_request, timeout, &recv_status);

    /* Decode depending on op ID */
//    fs_decode()
//    xdr_decode(generic_request->recv_buf, recv_status.count,
//            generic_request->out_param);

    free(priv_request->send_buf);
    free(priv_request->recv_buf);
    free(priv_request);
    priv_request = NULL;
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_wait_all
 *
 * Purpose:     Wait for all operations to complete
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_wait_all(int count, fs_request_t array_of_requests[],
        unsigned int timeout, fs_status_t array_of_statuses[])
{
    return 0;
}
