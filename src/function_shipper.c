/*
 * function_shipper.c
 */

#include "function_shipper.h"
#include "function_map.h"
#include "iofsl_compat.h"
#include "shipper_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

/* Private structs */
typedef struct fs_priv_request {
    fs_id_t      id;
    void *       send_buf;
    void *       recv_buf;
    void *       out_struct;
    na_request_t send_request;
    na_request_t recv_request;
} fs_priv_request_t;

typedef struct fs_proc_info {
    int (*enc_routine)(fs_proc_t proc, void *in_struct);
    int (*dec_routine)(fs_proc_t proc, void *out_struct);
} fs_proc_info_t;

/* Function map */
static func_map_t *func_map;

/* TLS key for tag */
static pthread_key_t ptk_tag;
static unsigned int next_tag = 0;
static pthread_mutex_t tag_lock = PTHREAD_MUTEX_INITIALIZER;

static na_network_class_t *fs_network_class = NULL;

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
int fs_init(na_network_class_t *network_class)
{
    int ret = S_SUCCESS;

    if (fs_network_class) {
        S_ERROR_DEFAULT("Already initialized");
        ret = S_FAIL;
        return ret;
    }

    fs_network_class = network_class;

    /* Initialize TLS tags */
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;

    /* Create new function map */
    func_map = func_map_new();

    return ret;
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
    int ret = S_SUCCESS;

    if (!fs_network_class) {
        S_ERROR_DEFAULT("Already finalized");
        ret = S_FAIL;
        return ret;
    }

    na_finalize(fs_network_class);

    /* Delete function map */
    func_map_free(func_map);
    func_map = NULL;

    /* Free TLS key */
    pthread_key_delete(ptk_tag);

    fs_network_class = NULL;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
fs_id_t fs_register(const char *func_name,
        int (*enc_routine)(fs_proc_t proc, void *in_struct),
        int (*dec_routine)(fs_proc_t proc, void *out_struct))
{
    fs_id_t *id;
    fs_proc_info_t *proc_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));

    *id = fs_proc_string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    proc_info = malloc(sizeof(fs_proc_info_t));

    proc_info->enc_routine = enc_routine;
    proc_info->dec_routine = dec_routine;
    func_map_insert(func_map, id, proc_info);

    return *id;
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
int fs_forward(na_addr_t addr, fs_id_t id, const void *in_struct, void *out_struct,
        fs_request_t *request)
{
    int ret = S_SUCCESS;
    fs_proc_info_t *proc_info;

    void *send_buf = NULL;
    void *recv_buf = NULL;
    /* buf len is the size of an unexpected message by default */
    na_size_t send_buf_len = na_get_unexpected_size(fs_network_class);
    na_size_t recv_buf_len = na_get_unexpected_size(fs_network_class);

    /* Send buf len may be determined once the encoding function is called */
//    na_size_t send_buf_len = 0;
//    na_size_t min_send_buf_len = 0;

    fs_proc_t  enc_proc;
    void      *enc_buf_ptr;
    na_size_t  enc_buf_len = 0;

    static int tag_incr = 0;
    na_tag_t   send_tag, recv_tag;
    fs_priv_request_t *priv_request = NULL;

    /* Retrieve encoding function from function map */
    proc_info = func_map_lookup(func_map, &id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    /* Get the minimum encoding size */
//    func_info->enc_routine(NULL, &min_send_buf_len, NULL);
//    if (min_send_buf_len == 0) {
//        S_ERROR_DEFAULT("encoding function requires a non-zero buffer length");
//        ret = S_FAIL;
//        return ret;
//    }
    /* We need some extra space to add IOFSL ids */
//    min_send_buf_len += iofsl_compat_get_size_id() + sizeof(fs_id_t);

//    if (min_send_buf_len < na_get_unexpected_size(fs_network_class)) {
//        send_buf_len = na_get_unexpected_size(fs_network_class);
//    } else {
//        S_ERROR_DEFAULT("Buffer length currently not supported");
//        ret = S_FAIL;
//        return ret;
//    }

    send_buf = malloc(send_buf_len);
    if (!send_buf) {
        S_ERROR_DEFAULT("send buffer allocation failed.\n");
        ret = S_FAIL;
        return ret;
    }
    recv_buf = malloc(recv_buf_len);
    if (!recv_buf) {
        S_ERROR_DEFAULT("recv buffer allocation failed");
        free(send_buf);
        send_buf = NULL;
        ret = S_FAIL;
        return ret;
    }

    enc_buf_ptr = send_buf;
    enc_buf_len = send_buf_len;

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    iofsl_compat_proc_enc_id(enc_buf_ptr, enc_buf_len);
    enc_buf_ptr += iofsl_compat_get_size_id();
    enc_buf_len -= iofsl_compat_get_size_id();

    /* Create a new encoding proc */
    fs_proc_create(enc_buf_ptr, enc_buf_len, FS_ENCODE, &enc_proc);

    /* Add generic op id now (do a simple memcpy) */
    fs_proc_uint32_t(enc_proc, &id);

    /* Encode the function parameters */
    proc_info->enc_routine(enc_proc, (void*)in_struct);

    /* Post the send message and pre-post the recv message */
    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

    priv_request = malloc(sizeof(fs_priv_request_t));

    priv_request->id = id;
    priv_request->send_buf = send_buf;
    priv_request->recv_buf = recv_buf;
    priv_request->out_struct = out_struct;

    ret = na_send_unexpected(fs_network_class, send_buf, send_buf_len, addr,
            send_tag, &priv_request->send_request, NULL);
    if (ret != S_SUCCESS) {
        ret = S_FAIL;
        free(send_buf);
        send_buf = NULL;
        free(recv_buf);
        recv_buf = NULL;
        free(priv_request);
        priv_request = NULL;
        return ret;
    }
    ret = na_recv(fs_network_class, recv_buf, recv_buf_len, addr,
            recv_tag, &priv_request->recv_request, NULL);
    if (ret != S_SUCCESS) {
        ret = S_FAIL;
        free(send_buf);
        send_buf = NULL;
        free(recv_buf);
        recv_buf = NULL;
        free(priv_request);
        priv_request = NULL;
        return ret;
    }

    *request = (fs_request_t) priv_request;

    /* Free the encoding proc */
    fs_proc_free(enc_proc);

    return ret;
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
    na_status_t        recv_status;
    fs_proc_info_t  *proc_info;

    fs_proc_t  dec_proc;
    void      *dec_buf_ptr;
    na_size_t  dec_buf_len = 0;

    int ret = S_SUCCESS;

    ret = na_wait(fs_network_class, priv_request->send_request, timeout, NA_STATUS_IGNORE);

    ret = na_wait(fs_network_class, priv_request->recv_request, timeout, &recv_status);

    /* Decode depending on op ID */
    proc_info = func_map_lookup(func_map, &priv_request->id);
    if (!proc_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    dec_buf_ptr = priv_request->recv_buf;
    dec_buf_len = recv_status.count;

    /* Check op status from parameters (used for IOFSL compat) */
    iofsl_compat_proc_dec_status(dec_buf_ptr, dec_buf_len);
    dec_buf_ptr += iofsl_compat_get_size_status();
    dec_buf_len -= iofsl_compat_get_size_status();

    /* Create a new decoding proc */
    fs_proc_create(dec_buf_ptr, dec_buf_len, FS_DECODE, &dec_proc);

    /* Decode function parameters */
    proc_info->dec_routine(dec_proc, priv_request->out_struct);

    /* Free the decoding proc */
    fs_proc_free(dec_proc);

    /* Free request */
    free(priv_request->send_buf);
    priv_request->send_buf = NULL;
    free(priv_request->recv_buf);
    priv_request->recv_buf = NULL;
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
    return S_SUCCESS;
}
