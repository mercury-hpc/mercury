/*
 * function_shipper.c
 */

#include "function_shipper.h"
#include "network_abstraction.h"
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

typedef struct fs_client_info {
    int (*enc_routine)(void *buf, size_t buf_len, const void *in_struct);
    int (*dec_routine)(void *out_struct, const void *buf, size_t buf_len);
} fs_client_info_t;

typedef struct fs_server_info {
    size_t size_in_struct;
    size_t size_out_struct;
    int (*dec_routine)(void *in_struct, const void *buf, size_t buf_len);
    int (*exe_routine)(const void *in_struct, void *out_struct, fs_info_t info);
    int (*enc_routine)(void *buf, size_t buf_len, const void *out_struct);
} fs_server_info_t;

typedef struct fs_priv_info {
    na_addr_t addr;
    na_tag_t  tag;
} fs_priv_info_t;

/* Function map */
func_map_t *func_map;

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

/* Hash function name for unique ID to register */
static inline unsigned int string_hash(const char *string)
{
    /* This is the djb2 string hash function */

    unsigned int result = 5381;
    unsigned char *p;

    p = (unsigned char *) string;

    while (*p != '\0') {
        result = (result << 5) + result + *p;
        ++p;
    }
    return result;
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
 * Function:    fs_peer_lookup
 *
 * Purpose:     Lookup a peer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_peer_lookup(const char *name, fs_peer_t *peer)
{
    int ret = S_SUCCESS;

    /* Perform an address lookup on the ION */
    na_addr_lookup(fs_network_class, name, (na_addr_t*)peer);

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_peer_free
 *
 * Purpose:     Free the peer
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_peer_free(fs_peer_t peer)
{
    int ret = S_SUCCESS;

    /* Cleanup peer_addr */
    na_addr_free(fs_network_class, (na_addr_t)peer);

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
        int (*enc_routine)(void *buf, size_t buf_len, const void *in_struct),
        int (*dec_routine)(void *out_struct, const void *buf, size_t buf_len))
{
    fs_id_t *id;
    fs_client_info_t *func_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));

    *id = string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    func_info = malloc(sizeof(fs_client_info_t));

    func_info->enc_routine = enc_routine;
    func_info->dec_routine = dec_routine;
    func_map_insert(func_map, id, func_info);

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
int fs_forward(fs_peer_t peer, fs_id_t id, const void *in_struct, void *out_struct,
        fs_request_t *request)
{
    int ret = S_SUCCESS;
    fs_client_info_t *func_info;

    void *send_buf = NULL;
    void *recv_buf = NULL;

    na_size_t send_buf_len = na_get_unexpected_size(fs_network_class);
    na_size_t recv_buf_len = na_get_unexpected_size(fs_network_class);

    static int tag_incr = 0;
    na_tag_t send_tag, recv_tag;

    fs_priv_request_t *priv_request = NULL;

    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

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

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    iofsl_compat_xdr_process_id(send_buf, send_buf_len, ENCODE);

    /* Add generic op id now  (do a simple memcpy) */
    memcpy(send_buf + iofsl_compat_xdr_get_size_id(), &id, sizeof(fs_id_t));

    /* Retrieve encoding function from function map */
    func_info = func_map_lookup(func_map, &id);
    if (!func_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    /* Encode the function parameters */
    func_info->enc_routine(send_buf + iofsl_compat_xdr_get_size_id() + sizeof(fs_id_t),
            send_buf_len - iofsl_compat_xdr_get_size_id() - sizeof(fs_id_t), in_struct);

    /* Post the send message and pre-post the recv message */
    priv_request = malloc(sizeof(fs_priv_request_t));

    priv_request->id = id;
    priv_request->send_buf = send_buf;
    priv_request->recv_buf = recv_buf;
    priv_request->out_struct = out_struct;

    ret = na_send_unexpected(fs_network_class, send_buf, send_buf_len, peer,
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
    ret = na_recv(fs_network_class, recv_buf, recv_buf_len, peer,
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

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_wait
 *
 * Purpose:     Forward a call that has an execution dependency
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_forward_depend(fs_peer_t peer, fs_id_t id,
        int num_parents, fs_request_t array_of_parent_requests[],
        const void *in_struct, void *out_struct, fs_request_t *request)
{
    int ret = S_SUCCESS;

    fs_forward(peer, id, in_struct, out_struct, request);
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
    na_status_t recv_status;
    fs_client_info_t *func_info;
    int ret = S_SUCCESS;

    ret = na_wait(fs_network_class, priv_request->send_request, timeout, NA_STATUS_IGNORE);

    ret = na_wait(fs_network_class, priv_request->recv_request, timeout, &recv_status);

    /* Check op status from parameters (used for IOFSL compat) */
    iofsl_compat_xdr_process_status(priv_request->recv_buf, recv_status.count, DECODE);

    /* Decode depending on op ID */
    func_info = func_map_lookup(func_map, &priv_request->id);
    if (!func_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    func_info->dec_routine(priv_request->out_struct,
            priv_request->recv_buf + iofsl_compat_xdr_get_size_status(),
            recv_status.count - iofsl_compat_xdr_get_size_status());

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

/*---------------------------------------------------------------------------
 * Function:    fs_server_register
 *
 * Purpose:     Register a function name and provide a unique ID
 *
 * Returns:     Unsigned integer
 *
 *---------------------------------------------------------------------------
 */
fs_id_t fs_server_register(const char *func_name,
        size_t size_in_struct, size_t size_out_struct,
        int (*dec_routine)(void *in_struct, const void *buf, size_t buf_len),
        int (*exe_routine)(const void *in_struct, void *out_struct, fs_info_t info),
        int (*enc_routine)(void *buf, size_t buf_len, const void *out_struct))
{
    fs_id_t *id;
    fs_server_info_t *server_func_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));

    *id = string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    server_func_info = malloc(sizeof(fs_server_info_t));

    server_func_info->size_in_struct = size_in_struct;
    server_func_info->size_out_struct = size_out_struct;
    server_func_info->dec_routine = dec_routine;
    server_func_info->exe_routine = exe_routine;
    server_func_info->enc_routine = enc_routine;
    func_map_insert(func_map, id, server_func_info);

    return *id;
}

/*---------------------------------------------------------------------------
 * Function:    fs_server_receive
 *
 * Purpose:     Receive a new function call
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_server_receive(fs_id_t *id, fs_info_t *info, void **in_struct)
{
    void *recv_buf = NULL;
    na_size_t recv_buf_len = 0;
    fs_server_info_t *server_func_info;
    fs_priv_info_t *priv_info = NULL;
    void *priv_in_struct = NULL;

    int ret = S_SUCCESS;

    /* Keep info from received call */
    priv_info = malloc(sizeof(fs_priv_info_t));

    /* Do not expect message bigger than unexpected size (otherwise something went wrong) */
    recv_buf_len = na_get_unexpected_size(fs_network_class);
    recv_buf = malloc(recv_buf_len);

    /* Recv a message from a client (blocking for now) */
    na_recv_unexpected(fs_network_class, recv_buf, &recv_buf_len, &priv_info->addr, &priv_info->tag, NULL, NULL);

    /* Decode IOFSL id (used for compat) */
    iofsl_compat_xdr_process_id(recv_buf, recv_buf_len, DECODE);

    /* Get generic op id */
    memcpy(id, recv_buf + iofsl_compat_xdr_get_size_id(), sizeof(fs_id_t));

    /* Retrieve decoding function from function map */
    server_func_info = func_map_lookup(func_map, id);
    if (!server_func_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    priv_in_struct = malloc(server_func_info->size_in_struct);

    /* Decode input parameters */
    server_func_info->dec_routine(priv_in_struct,
            recv_buf + iofsl_compat_xdr_get_size_id() + sizeof(fs_id_t),
            recv_buf_len - iofsl_compat_xdr_get_size_id() - sizeof(fs_id_t));

    /* Free recv buf */
    free(recv_buf);

    *info  = (fs_info_t) priv_info;
    *in_struct = priv_in_struct;

    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_server_execute
 *
 * Purpose:     Execute the function call
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_server_execute(fs_id_t id, fs_info_t info, const void *in_struct, void **out_struct)
{
    fs_server_info_t *server_func_info;
    fs_priv_info_t *priv_info = (fs_priv_info_t *) info;
    void *priv_out_struct = NULL;
    int ret = S_SUCCESS;

    /* Retrieve exe function from function map */
    server_func_info = func_map_lookup(func_map, &id);
    if (!server_func_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    /* Allocate the output structure */
    priv_out_struct = malloc(server_func_info->size_out_struct);

    /* Execute function and fill output parameters */
    server_func_info->exe_routine(in_struct, priv_out_struct, priv_info);

    *out_struct = priv_out_struct;
    return ret;
}

/*---------------------------------------------------------------------------
 * Function:    fs_server_respond
 *
 * Purpose:     Send the response back to the caller
 *
 * Returns:     Non-negative on success or negative on failure
 *
 *---------------------------------------------------------------------------
 */
int fs_server_respond(fs_id_t id, fs_info_t info, const void *out_struct)
{
    void *send_buf = NULL;
    na_size_t send_buf_len = 0;

    na_request_t send_request = NULL;

    fs_server_info_t *server_func_info;
    fs_priv_info_t *priv_info = (fs_priv_info_t *) info;

    int ret = S_SUCCESS;

    /* Do not expect message bigger than unexpected size (otherwise something went wrong) */
    send_buf_len = na_get_unexpected_size(fs_network_class);
    send_buf = malloc(send_buf_len);

    /* Simulate IOFSL behavior and add op status */
    iofsl_compat_xdr_process_status(send_buf, send_buf_len, ENCODE);

    /* Retrieve encoding function from function map */
    server_func_info = func_map_lookup(func_map, &id);
    if (!server_func_info) {
        S_ERROR_DEFAULT("func_map_lookup failed");
        ret = S_FAIL;
        return ret;
    }

    /* Encode output parameters */
    server_func_info->enc_routine(send_buf + iofsl_compat_xdr_get_size_status(),
            send_buf_len - iofsl_compat_xdr_get_size_status(), out_struct);

    /* Respond back */
    na_send(fs_network_class, send_buf, send_buf_len, priv_info->addr, priv_info->tag, &send_request, NULL);

    na_wait(fs_network_class, send_request, NA_MAX_IDLE_TIME, NA_STATUS_IGNORE);

    /* Free send buf */
    free(send_buf);

    /* Free info */
    na_addr_free(fs_network_class, priv_info->addr);
    priv_info->addr = NULL;

    free(priv_info);
    priv_info = NULL;

    return ret;
}
