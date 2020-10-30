/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_test_drc.h"
#include "mercury_hl.h"

/****************/
/* Local Macros */
/****************/

/* Use token option */
//#define HG_TEST_DRC_USE_TOKEN

/* Ignore DRC calls (for local testing) */
//#define HG_TEST_DRC_IGNORE

/* Convert value to string */
#define DRC_ERROR_STRING_MACRO(def, value, string)                             \
    if (value == def)                                                          \
    string = #def

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Define hg_test_drc_grant_in_t */
typedef struct {
    uint32_t wlm_id;
} hg_test_drc_grant_in_t;

/* Define hg_test_drc_grant_out_t */
typedef struct {
#ifdef HG_TEST_DRC_USE_TOKEN
    hg_string_t token;
#else
    uint32_t credential;
#endif
} hg_test_drc_grant_out_t;

/********************/
/* Local Prototypes */
/********************/

#ifndef HG_TEST_DRC_IGNORE
static const char *
drc_strerror(int errnum);
#endif

/* Register DRC function */
static void
hg_test_drc_register(hg_class_t *hg_class);

/* Define hg_proc_hg_test_drc_grant_in_t */
static HG_INLINE hg_return_t
hg_proc_hg_test_drc_grant_in_t(hg_proc_t proc, void *data);

/* Define hg_proc_rpc_open_out_t */
static HG_INLINE hg_return_t
hg_proc_hg_test_drc_grant_out_t(hg_proc_t proc, void *data);

/* Grant access to other job */
static hg_return_t
hg_test_drc_grant_cb(hg_handle_t handle);

/* Acquire local DRC token */
static hg_return_t
hg_test_drc_token_acquire(struct hg_test_info *hg_test_info);

/* Request access to other job and get token */
static hg_return_t
hg_test_drc_token_request(struct hg_test_info *hg_test_info);

/* Request callback */
static hg_return_t
hg_test_drc_token_request_cb(const struct hg_cb_info *callback_info);

/*******************/
/* Local Variables */
/*******************/

static hg_id_t hg_test_drc_grant_id_g = 0;

/*---------------------------------------------------------------------------*/
#ifndef HG_TEST_DRC_IGNORE
static const char *
drc_strerror(int errnum)
{
    const char *errstring = "UNDEFINED";

    DRC_ERROR_STRING_MACRO(DRC_SUCCESS, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_EINVAL, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_EPERM, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_ENOSPC, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_ECONNREFUSED, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_ALREADY_GRANTED, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_CRED_NOT_FOUND, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_CRED_CREATE_FAILURE, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_CRED_EXTERNAL_FAILURE, errnum, errstring);
    DRC_ERROR_STRING_MACRO(DRC_BAD_TOKEN, errnum, errstring);

    return errstring;
}
#endif

/*---------------------------------------------------------------------------*/
static void
hg_test_drc_register(hg_class_t *hg_class)
{
    hg_test_drc_grant_id_g = MERCURY_REGISTER(hg_class, "hg_test_drc_grant",
        hg_test_drc_grant_in_t, hg_test_drc_grant_out_t, hg_test_drc_grant_cb);
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_proc_hg_test_drc_grant_in_t(hg_proc_t proc, void *data)
{
    hg_test_drc_grant_in_t *struct_data = (hg_test_drc_grant_in_t *) data;
    hg_return_t ret = HG_SUCCESS;

    ret = hg_proc_hg_uint32_t(proc, &struct_data->wlm_id);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Proc error");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static HG_INLINE hg_return_t
hg_proc_hg_test_drc_grant_out_t(hg_proc_t proc, void *data)
{
    hg_test_drc_grant_out_t *struct_data = (hg_test_drc_grant_out_t *) data;
    hg_return_t ret = HG_SUCCESS;

#ifdef HG_TEST_DRC_USE_TOKEN
    ret = hg_proc_hg_string_t(proc, &struct_data->token);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Proc error");
        goto done;
    }
#else
    ret = hg_proc_hg_uint32_t(proc, &struct_data->credential);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Proc error");
        goto done;
    }
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_drc_grant_cb(hg_handle_t handle)
{
    const struct hg_info *hg_info = NULL;
    struct hg_test_info *hg_test_info = NULL;
    hg_test_drc_grant_in_t in_struct;
    hg_test_drc_grant_out_t out_struct;
    hg_return_t ret = HG_SUCCESS;
#ifdef HG_TEST_DRC_USE_TOKEN
    hg_string_t token;
#endif
#ifndef HG_TEST_DRC_IGNORE
    int rc;
#endif

    /* Get info from handle */
    hg_info = HG_Get_info(handle);

    /* Get test info */
    hg_test_info = (struct hg_test_info *) HG_Class_get_data(hg_info->hg_class);

    /* Get input buffer */
    ret = HG_Get_input(handle, &in_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not get input");
        goto done;
    }

    /* Get parameters */
    hg_test_info->wlm_id = in_struct.wlm_id;

    /* Grant access to another job */
    printf("# Granting access to wlm_id %u...\n", hg_test_info->wlm_id);
    fflush(stdout);
#ifndef HG_TEST_DRC_IGNORE
drc_grant_again:
    rc = drc_grant(
        hg_test_info->credential, hg_test_info->wlm_id, DRC_FLAGS_TARGET_WLM);
    if (rc != DRC_SUCCESS && rc != -DRC_ALREADY_GRANTED) {
        if (rc == -DRC_EINVAL) {
            sleep(1);
            goto drc_grant_again;
        }
        HG_TEST_LOG_ERROR("drc_grant() to %d failed (%d, %s)",
            hg_test_info->wlm_id, rc, drc_strerror(-rc));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
#endif

#ifdef HG_TEST_DRC_USE_TOKEN
    /* Get the token to pass around to processes in other job */
#    ifndef HG_TEST_DRC_IGNORE
    rc = drc_get_credential_token(hg_test_info->credential, &token);
    if (rc != DRC_SUCCESS) {
        HG_TEST_LOG_ERROR("drc_get_credential_token() failed (%d, %s)", rc,
            drc_strerror(-rc));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
#    else
    token = "my_test_token";
#    endif

    /* Fill output structure */
    printf("# Access granted, token is %s\n", token);
    fflush(stdout);
    out_struct.token = token;
#else
    out_struct.credential = hg_test_info->credential;
#endif

    /* Free handle and send response back */
    ret = HG_Respond(handle, NULL, NULL, &out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not respond");
        goto done;
    }

    HG_Free_input(handle, &in_struct);
    HG_Destroy(handle);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_drc_token_acquire(struct hg_test_info *hg_test_info)
{
    hg_return_t ret = HG_SUCCESS;
#ifndef HG_TEST_DRC_IGNORE
    int rc;
#endif

    /* Acquire credential */
#ifndef HG_TEST_DRC_IGNORE
    if (!hg_test_info->credential) {
drc_acquire_again:
        rc = drc_acquire(&hg_test_info->credential, 0);
        if (rc != DRC_SUCCESS) { /* failed to acquire credential */
            if (rc == -DRC_EINVAL) {
                sleep(1);
                goto drc_acquire_again;
            }
            HG_TEST_LOG_ERROR(
                "drc_acquire() failed (%d, %s)", rc, drc_strerror(-rc));
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }
#else
    hg_test_info->credential = 12345;
#endif
    printf("# Acquired credential %u\n", hg_test_info->credential);
    fflush(stdout);

    /* Access credential */
#ifndef HG_TEST_DRC_IGNORE
drc_access_again:
    rc =
        drc_access(hg_test_info->credential, 0, &hg_test_info->credential_info);
    if (rc != DRC_SUCCESS) { /* failed to access credential */
        if (rc == -DRC_EINVAL) {
            sleep(1);
            goto drc_access_again;
        }
        HG_TEST_LOG_ERROR(
            "drc_access() failed (%d, %s)", rc, drc_strerror(-rc));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
#endif

    /* Set cookie for further use */
#ifndef HG_TEST_DRC_IGNORE
    hg_test_info->cookie = drc_get_first_cookie(hg_test_info->credential_info);
#else
    hg_test_info->cookie = 123456789;
#endif
    printf("# Cookie is %u\n", hg_test_info->cookie);
    fflush(stdout);

#ifndef HG_TEST_DRC_IGNORE
done:
#endif
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_drc_token_request(struct hg_test_info *hg_test_info)
{
    hg_request_t *request = NULL;
    hg_handle_t handle;
#ifdef HG_TEST_DRC_USE_TOKEN
    hg_string_t token;
#else
    hg_uint32_t credential;
#endif
    hg_test_drc_grant_in_t in_struct;
    hg_test_drc_grant_out_t out_struct;
    hg_return_t ret = HG_SUCCESS;
#ifndef HG_TEST_DRC_IGNORE
    int rc;
#endif

    /* Look up target addr using target name info */
    ret = HG_Hl_addr_lookup_wait(hg_test_info->context,
        hg_test_info->request_class, hg_test_info->na_test_info.target_name,
        &hg_test_info->target_addr, HG_MAX_IDLE_TIME);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not find addr for target %s",
            hg_test_info->na_test_info.target_name);
        goto done;
    }

    /* Create new request */
    request = hg_request_create(hg_test_info->request_class);

    /* Create request with invalid RPC id */
    ret = HG_Create(hg_test_info->context, hg_test_info->target_addr,
        hg_test_drc_grant_id_g, &handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not create handle");
        goto done;
    }

    /* Get WLM ID and set input */
#ifndef HG_TEST_DRC_IGNORE
    in_struct.wlm_id = drc_get_wlm_id();
#else
    in_struct.wlm_id = 12340;
#endif

    /* Forward call to target addr */
    printf("# %u requesting access to remote...\n", in_struct.wlm_id);
    fflush(stdout);
    ret = HG_Forward(handle, hg_test_drc_token_request_cb, request, &in_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR(
            "Could not forward call with id=%d", hg_test_drc_grant_id_g);
        goto done;
    }

    /* Wait for completion */
    hg_request_wait(request, HG_MAX_IDLE_TIME, NULL);

    /* Get output */
    ret = HG_Get_output(handle, &out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not get output");
        goto done;
    }

#ifdef HG_TEST_DRC_USE_TOKEN
    /* Get token back */
    token = out_struct.token;
    printf("# Received token %s\n", token);
    fflush(stdout);

    /* Translate token */
#    ifndef HG_TEST_DRC_IGNORE
    rc = drc_access_with_token(token, 0, &hg_test_info->credential_info);
    if (rc != DRC_SUCCESS) { /* failed to grant access to the credential */
        HG_TEST_LOG_ERROR(
            "drc_access_with_token() failed (%d, %s)", rc, drc_strerror(-rc));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
#    endif
#else
    /* Get credential back */
    credential = out_struct.credential;
    printf("# Received credential %u\n", credential);
    fflush(stdout);

    /* Access credential */
#    ifndef HG_TEST_DRC_IGNORE
drc_access_again:
    rc = drc_access(credential, 0, &hg_test_info->credential_info);
    if (rc != DRC_SUCCESS) { /* failed to access credential */
        if (rc == -DRC_EINVAL) {
            sleep(1);
            goto drc_access_again;
        }
        HG_TEST_LOG_ERROR(
            "drc_access() failed (%d, %s)", rc, drc_strerror(-rc));
        ret = HG_PROTOCOL_ERROR;
        goto done;
    }
#    endif
#endif

    /* Set cookie for further use */
#ifndef HG_TEST_DRC_IGNORE
    hg_test_info->cookie = drc_get_first_cookie(hg_test_info->credential_info);
#else
    hg_test_info->cookie = 123456789;
#endif
    printf("# Cookie is %u\n", hg_test_info->cookie);
    fflush(stdout);

    /* Clean up resources */
    ret = HG_Free_output(handle, &out_struct);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not free output");
        goto done;
    }

    ret = HG_Destroy(handle);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not destroy handle");
        goto done;
    }

    hg_request_destroy(request);

    /* Free target addr */
    ret = HG_Addr_free(hg_test_info->hg_class, hg_test_info->target_addr);
    if (ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Could not free addr");
        goto done;
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static hg_return_t
hg_test_drc_token_request_cb(const struct hg_cb_info *callback_info)
{
    hg_request_t *request = (hg_request_t *) callback_info->arg;
    hg_return_t ret = HG_SUCCESS;

    if (callback_info->ret != HG_SUCCESS) {
        HG_TEST_LOG_ERROR("Return from callback info is not HG_SUCCESS");
        goto done;
    }

done:
    hg_request_complete(request);
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_test_drc_acquire(int argc, char *argv[], struct hg_test_info *hg_test_info)
{
    struct hg_test_info hg_test_drc_info = {0};
    struct hg_init_info hg_test_drc_init_info = HG_INIT_INFO_INITIALIZER;
    hg_return_t ret = HG_SUCCESS;

    if (!hg_test_info->credential) {
        /* Create an NA class with "tcp" protocol */
        hg_test_drc_info.na_test_info.extern_init = NA_TRUE;
        hg_test_drc_info.na_test_info.protocol = strdup("tcp");
        hg_test_drc_info.na_test_info.listen =
            hg_test_info->na_test_info.listen;
        if (NA_Test_init(argc, argv, &hg_test_drc_info.na_test_info) !=
            NA_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not initialize NA test layer");
            ret = HG_NA_ERROR;
            goto done;
        }

        /* Assign NA class */
        hg_test_drc_init_info.na_class = hg_test_drc_info.na_test_info.na_class;

        /* Init HG HL with init options */
        ret = HG_Hl_init_opt(
            NULL, hg_test_drc_info.na_test_info.listen, &hg_test_drc_init_info);
        if (ret != HG_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not initialize HG HL");
            goto done;
        }
        hg_test_drc_info.hg_class = HG_CLASS_DEFAULT;
        hg_test_drc_info.context = HG_CONTEXT_DEFAULT;
        hg_test_drc_info.request_class = HG_REQUEST_CLASS_DEFAULT;

        /* Attach test info to class */
        HG_Class_set_data(hg_test_drc_info.hg_class, &hg_test_drc_info, NULL);

        /* Register routines */
        hg_test_drc_register(hg_test_drc_info.hg_class);

        /* Acquire DRC token */
        if (hg_test_drc_info.na_test_info.listen) {
            char addr_string[NA_TEST_MAX_ADDR_NAME];
            na_size_t addr_string_len = NA_TEST_MAX_ADDR_NAME;
            hg_addr_t self_addr;

            ret = hg_test_drc_token_acquire(&hg_test_drc_info);
            if (ret != HG_SUCCESS) {
                HG_TEST_LOG_ERROR("Could not acquire DRC token");
                goto done;
            }

            /* TODO only rank 0 */
            ret = HG_Addr_self(hg_test_drc_info.hg_class, &self_addr);
            if (ret != HG_SUCCESS) {
                HG_TEST_LOG_ERROR("Could not get self addr");
                goto done;
            }

            ret = HG_Addr_to_string(hg_test_drc_info.hg_class, addr_string,
                &addr_string_len, self_addr);
            if (ret != HG_SUCCESS) {
                HG_TEST_LOG_ERROR("Could not convert addr to string");
                goto done;
            }
            HG_Addr_free(hg_test_drc_info.hg_class, self_addr);

            na_test_set_config(addr_string);

            /* Used by CTest Test Driver to know when to launch clients */
            HG_TEST_READY_MSG();

            /* Progress */
            do {
                unsigned int total_count = 0;
                unsigned int actual_count = 0;

                do {
                    ret = HG_Trigger(
                        hg_test_drc_info.context, 0, 1, &actual_count);
                    total_count += actual_count;
                } while ((ret == HG_SUCCESS) && actual_count);

                /* Break as soon as something was triggered */
                if (total_count)
                    break;

                ret = HG_Progress(hg_test_drc_info.context, HG_MAX_IDLE_TIME);
            } while (ret == HG_SUCCESS || ret == HG_TIMEOUT);
        } else {
            char test_addr_name[NA_TEST_MAX_ADDR_NAME] = {'\0'};

            if (hg_test_drc_info.na_test_info.mpi_comm_rank == 0)
                na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME);

            /* Broadcast addr name */
            NA_Test_bcast(test_addr_name, NA_TEST_MAX_ADDR_NAME, 0,
                &hg_test_drc_info.na_test_info);

            hg_test_drc_info.na_test_info.target_name = strdup(test_addr_name);
            printf("# Target name read: %s\n",
                hg_test_drc_info.na_test_info.target_name);

            ret = hg_test_drc_token_request(&hg_test_drc_info);
            if (ret != HG_SUCCESS) {
                HG_TEST_LOG_ERROR("Could not request DRC token");
                goto done;
            }
        }

#ifdef HG_TEST_HAS_PARALLEL
        /* TODO bcast cookie when parallel mode */
#endif

        /* Finalize HG HL interface */
        ret = HG_Hl_finalize();
        if (ret != HG_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not finalize HG HL");
            goto done;
        }

        /* Finalize NA test class interface */
#ifdef HG_TEST_HAS_PARALLEL
        hg_test_drc_info.na_test_info.mpi_no_finalize = NA_TRUE;
#endif
        if (NA_Test_finalize(&hg_test_drc_info.na_test_info) != NA_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not finalize NA test interface");
            ret = HG_NA_ERROR;
            goto done;
        }
        hg_test_info->credential = hg_test_drc_info.credential;
    } else {
        hg_test_drc_info.credential = hg_test_info->credential;
        ret = hg_test_drc_token_acquire(&hg_test_drc_info);
        if (ret != HG_SUCCESS) {
            HG_TEST_LOG_ERROR("Could not acquire DRC token");
            goto done;
        }
    }

    /* Copy cookie/credential info */
    hg_test_info->wlm_id = hg_test_drc_info.wlm_id;
    hg_test_info->credential_info = hg_test_drc_info.credential_info;
    hg_test_info->cookie = hg_test_drc_info.cookie;

    /* Sleep a few seconds to make sure listener is initialized */
    if (!hg_test_drc_info.na_test_info.listen) {
        unsigned int sleep_sec = 5;

        printf("# Sleeping now for %d seconds...\n", sleep_sec);
        fflush(stdout);
        sleep(sleep_sec);
    }

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
hg_return_t
hg_test_drc_release(struct hg_test_info *hg_test_info)
{
    hg_return_t ret = HG_SUCCESS;
#ifndef HG_TEST_DRC_IGNORE
    int rc;
#endif

    /* Release the reference to the credential */
#ifndef HG_TEST_DRC_IGNORE
    if (hg_test_info->credential_info) {
        rc = drc_release_local(&hg_test_info->credential_info);
        if (rc != DRC_SUCCESS) { /* failed to release credential info */
            HG_TEST_LOG_ERROR("Could not release credential info (%d, %s)", rc,
                drc_strerror(-rc));
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
        free((void *) hg_test_info->credential_info);
    }

    if (hg_test_info->wlm_id && hg_test_info->credential) {
        rc = drc_revoke(hg_test_info->credential, hg_test_info->wlm_id,
            DRC_FLAGS_TARGET_WLM);
        if (rc != DRC_SUCCESS) { /* failed to release credential info */
            HG_TEST_LOG_ERROR("Could not revoke access for %d (%d, %s)",
                hg_test_info->wlm_id, rc, drc_strerror(-rc));
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

    if (hg_test_info->credential) {
        printf("# Releasing credential %u\n", hg_test_info->credential);
        rc = drc_release(hg_test_info->credential, 0);
        if (rc != DRC_SUCCESS) { /* failed to release credential */
            HG_TEST_LOG_ERROR(
                "Could not release credential (%d, %s)", rc, drc_strerror(-rc));
            ret = HG_PROTOCOL_ERROR;
            goto done;
        }
    }

done:
#else
    (void) hg_test_info;
#endif

    return ret;
}
