/*
 * function_shipper.c
 */

#include "function_shipper.h"
#include "network_abstraction.h"
#include "function_map.h"
#include "iofsl_compat.h"

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

typedef struct fs_func_info {
    int (*enc_routine)(void *buf, int buf_len, void *in_struct);
    int (*dec_routine)(void *out_struct, void *buf, int buf_len);
} fs_func_info_t;

/* Function map */
func_map_t *func_map;

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
    na_register(network_class);

    /* Initialize TLS tags */
    pthread_key_create(&ptk_tag, 0);
    next_tag = 1;

    /* Create new function map */
    func_map = func_map_new();
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
    na_finalize();

    /* Delete function map */
    func_map_free(func_map);
    func_map = NULL;

    /* Free TLS key */
    pthread_key_delete(ptk_tag);
    return 0;
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
    /* Perform an address lookup on the ION */
    na_addr_lookup(name, (na_addr_t*)peer);
    return 0;
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
    /* Cleanup peer_addr */
    na_addr_free((na_addr_t)peer);
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
fs_id_t fs_register(const char *func_name,
        int (*enc_routine)(void *buf, int buf_len, void *in_struct),
        int (*dec_routine)(void *out_struct, void *buf, int buf_len))
{
    fs_id_t *id;
    fs_func_info_t *func_info;

    /* Generate a key from the string */
    id = malloc(sizeof(fs_id_t));
    *id = string_hash(func_name);

    /* Fill a func info struct and store it into the function map */
    func_info = malloc(sizeof(fs_func_info_t));
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
int fs_forward(fs_peer_t peer, fs_id_t id, void *in_struct, void *out_struct,
        fs_request_t *request)
{
    fs_func_info_t *func_info;

    void *send_buf = NULL;
    void *recv_buf = NULL;

    na_size_t send_buf_len = na_get_unexpected_size();
    na_size_t recv_buf_len = na_get_unexpected_size();

    static int tag_incr = 0;
    na_tag_t send_tag, recv_tag;

    fs_priv_request_t *priv_request = NULL;

    send_tag = gen_tag() + tag_incr;
    recv_tag = gen_tag() + tag_incr;
    tag_incr++;
    if (send_tag > FS_MAXTAG) tag_incr = 0;

    /* Retrieve decoding function from function map */
    func_info = func_map_lookup(func_map, &id);
    if (!func_info) {
        FS_ERROR_DEFAULT("func_map_lookup failed");
        return FS_FAIL;
    }

    send_buf = malloc(send_buf_len);
    if (!send_buf) {
        fprintf(stderr, "send buffer allocation failed.\n");
    }
    recv_buf = malloc(recv_buf_len);
    if (!recv_buf) {
        fprintf(stderr, "recv buffer allocation failed.\n");
    }

    /* Add IOFSL op id to parameters (used for IOFSL compat) */
    iofsl_compat_xdr_process_id(send_buf, send_buf_len, ENCODE);

    /* Add generic op id now  (do a simple memcpy) */
    memcpy(send_buf + iofsl_compat_xdr_get_size_id(), &id, sizeof(fs_id_t));

    /* Encode the function parameters */
    func_info->enc_routine(send_buf + iofsl_compat_xdr_get_size_id() + sizeof(fs_id_t),
            send_buf_len - iofsl_compat_xdr_get_size_id() - sizeof(fs_id_t), in_struct);

    /* Post the send message and pre-post the recv message */
    priv_request = malloc(sizeof(fs_priv_request_t));
    priv_request->id = id;
    priv_request->send_buf = send_buf;
    priv_request->recv_buf = recv_buf;
    priv_request->out_struct = out_struct;
    *request = (fs_request_t) priv_request;

//    printf("Sending on tag %d\n", send_tag);
//    printf("Receiving on tag %d\n", recv_tag);
    na_send_unexpected(send_buf, send_buf_len, peer, send_tag, &priv_request->send_request, NULL);
    na_recv(recv_buf, recv_buf_len, peer, recv_tag, &priv_request->recv_request, NULL);
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
    fs_func_info_t *func_info;
    int ret = FS_SUCCESS;

    ret = na_wait(priv_request->send_request, timeout, NA_STATUS_IGNORE);
    ret = na_wait(priv_request->recv_request, timeout, &recv_status);

    /* Check op status from parameters (used for IOFSL compat) */
    iofsl_compat_xdr_process_status(priv_request->recv_buf, recv_status.count, DECODE);

    /* Decode depending on op ID */
    func_info = func_map_lookup(func_map, &priv_request->id);
    func_info->dec_routine(priv_request->out_struct,
            priv_request->recv_buf + iofsl_compat_xdr_get_size_status(),
            recv_status.count - iofsl_compat_xdr_get_size_status());

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
