/**
 * Copyright (c) 2013-2021 UChicago Argonne, LLC and The HDF Group.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "na_test.h"
#include "na_test_getopt.h"

#ifdef NA_HAS_MPI
#    include "na_mpi.h"
#endif

#include "mercury_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#    include <Winsock2.h>
#    include <Ws2tcpip.h>
#else
#    include <arpa/inet.h>
#    include <netdb.h>
#    include <netinet/in.h>
#    include <sys/socket.h>
#    include <sys/types.h>
#    include <unistd.h>
#    if defined(HG_TEST_HAS_SYSPRCTL_H)
#        include <sys/prctl.h>
#    endif
#endif

/****************/
/* Local Macros */
/****************/
#define HG_TEST_CONFIG_FILE_NAME "/port.cfg"

/************************************/
/* Local Type and Struct Definition */
/************************************/

/********************/
/* Local Prototypes */
/********************/

static void
na_test_parse_options(
    int argc, char *argv[], struct na_test_info *na_test_info);

#ifdef HG_TEST_HAS_PARALLEL
static na_return_t
na_test_mpi_init(struct na_test_info *na_test_info);

static void
na_test_mpi_finalize(struct na_test_info *na_test_info);
#endif

static char *
na_test_gen_config(struct na_test_info *na_test_info, int i);

static na_return_t
na_test_self_addr_publish(na_class_t *na_class, bool append);

/*******************/
/* Local Variables */
/*******************/

extern int na_test_opt_ind_g;         /* token pointer */
extern const char *na_test_opt_arg_g; /* flag argument (or value) */
extern const char *na_test_short_opt_g;
extern const struct na_test_opt na_test_opt_g[];

/* Default log outlets */
HG_LOG_SUBSYS_DECL_REGISTER(na_test, hg);

/*---------------------------------------------------------------------------*/
void
na_test_usage(const char *execname)
{
    printf("usage: %s [OPTIONS]\n", execname);
    printf("    NA OPTIONS\n");
    printf("    -h, --help           Print a usage message and exit\n");
    printf("    -c, --comm           Select NA plugin\n"
           "                         NA plugins: bmi, mpi, cci, etc\n");
    printf("    -d, --domain         Select NA OFI domain\n");
    printf("    -p, --protocol       Select plugin protocol\n"
           "                         Available protocols: tcp, ib, etc\n");
    printf("    -H, --hostname       Select hostname / IP address to use\n"
           "                         Default: any\n");
    printf("    -P, --port           Select port to use\n"
           "                         Default: any\n");
    printf("    -L, --listen         Listen for incoming messages\n");
    printf("    -S, --self_send      Send to self\n");
    printf("    -k, --key            Pass auth key\n");
    printf("    -l, --loop           Number of loops (default: 1)\n");
    printf("    -b, --busy           Busy wait\n");
    printf("    -y  --buf_size_min   Min buffer size (in bytes)\n");
    printf("    -z, --buf_size_max   Max buffer size (in bytes)\n");
    printf("    -R, --force-register Force registration of buffers\n");
    printf("    -V, --verbose        Print verbose output\n");
}

/*---------------------------------------------------------------------------*/
static void
na_test_parse_options(int argc, char *argv[], struct na_test_info *na_test_info)
{
    int opt;

    if (argc < 2) {
        na_test_usage(argv[0]);
        exit(1);
    }

    while ((opt = na_test_getopt(
                argc, argv, na_test_short_opt_g, na_test_opt_g)) != EOF) {
        switch (opt) {
            case 'h':
                na_test_usage(argv[0]);
                exit(1);
            case 'c': /* Comm */
                /* Prevent from overriding comm */
                if (!na_test_info->comm)
                    na_test_info->comm = strdup(na_test_opt_arg_g);
                break;
            case 'd': /* Domain */
                na_test_info->domain = strdup(na_test_opt_arg_g);
                break;
            case 'p': /* Protocol */
                /* Prevent from overriding protocol */
                if (!na_test_info->protocol)
                    na_test_info->protocol = strdup(na_test_opt_arg_g);
                break;
            case 'H': /* hostname */
                na_test_info->hostname = strdup(na_test_opt_arg_g);
                break;
            case 'P': /* port */
                na_test_info->port = atoi(na_test_opt_arg_g);
                break;
            case 'L': /* listen */
                na_test_info->listen = true;
                break;
            case 's': /* static */
                na_test_info->mpi_static = true;
                break;
            case 'S': /* self */
                na_test_info->self_send = true;
                break;
            case 'k': /* key */
                na_test_info->key = strdup(na_test_opt_arg_g);
                break;
            case 'l': /* loop */
                na_test_info->loop = atoi(na_test_opt_arg_g);
                break;
            case 'b': /* busy */
                na_test_info->busy_wait = true;
                break;
            case 'C': /* number of classes */
                na_test_info->max_classes = (uint8_t) atoi(na_test_opt_arg_g);
                break;
            case 'X': /* number of contexts */
                na_test_info->max_contexts = (uint8_t) atoi(na_test_opt_arg_g);
                break;
            case 'y': /* min buffer size */
                na_test_info->buf_size_min = (size_t) atol(na_test_opt_arg_g);
                break;
            case 'z': /* max buffer size */
                na_test_info->buf_size_max = (size_t) atol(na_test_opt_arg_g);
                break;
            case 'Z': /* msg size */
                na_test_info->max_msg_size = (size_t) atol(na_test_opt_arg_g);
                break;
            case 'R': /* force-register */
                na_test_info->force_register = true;
                break;
            case 'v': /* verify */
                na_test_info->verify = true;
                break;
            case 'V': /* verbose */
                na_test_info->verbose = true;
                break;
            default:
                break;
        }
    }
    na_test_opt_ind_g = 1;

    if (!na_test_info->protocol) {
        na_test_usage(argv[0]);
        exit(1);
    }
    if (!na_test_info->loop)
        na_test_info->loop = 1; /* Default */
}

/*---------------------------------------------------------------------------*/
#ifdef HG_TEST_HAS_PARALLEL
static na_return_t
na_test_mpi_init(struct na_test_info *na_test_info)
{
    int mpi_initialized = 0;
    na_return_t ret;
    int rc;

    rc = MPI_Initialized(&mpi_initialized);
    NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret, NA_PROTOCOL_ERROR,
        "MPI_Initialized() failed");
    NA_TEST_CHECK_ERROR(mpi_initialized, error, ret, NA_PROTOCOL_ERROR,
        "MPI was already initialized");

#    ifdef NA_MPI_HAS_GNI_SETUP
    /* Setup GNI job before initializing MPI */
    ret = NA_MPI_Gni_job_setup();
    NA_TEST_CHECK_NA_ERROR(error, ret, "Could not setup GNI job");
#    endif

    if (na_test_info->listen || na_test_info->mpi_static) {
        int provided;

        rc = MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret, NA_PROTOCOL_ERROR,
            "MPI_Init_thread() failed");

        NA_TEST_CHECK_ERROR(provided != MPI_THREAD_MULTIPLE, error, ret,
            NA_PROTOCOL_ERROR, "MPI_THREAD_MULTIPLE cannot be set");

        /* Only if we do static MPMD MPI */
        if (na_test_info->mpi_static) {
            int color, global_rank;

            rc = MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
            NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret,
                NA_PROTOCOL_ERROR, "MPI_Comm_rank() failed");

            /* Color is 1 for server, 2 for client */
            color = (na_test_info->listen) ? 1 : 2;

            /* Assume that the application did not split MPI_COMM_WORLD already
             */
            rc = MPI_Comm_split(
                MPI_COMM_WORLD, color, global_rank, &na_test_info->mpi_comm);
            NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret,
                NA_PROTOCOL_ERROR, "MPI_Comm_split() failed");

#    ifdef NA_HAS_MPI
            /* Set init comm that will be used to setup NA MPI */
            NA_MPI_Set_init_intra_comm(na_test_info->mpi_comm);
#    endif
        } else
            na_test_info->mpi_comm = MPI_COMM_WORLD; /* default */
    } else {
        rc = MPI_Init(NULL, NULL);
        NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret, NA_PROTOCOL_ERROR,
            "MPI_Init() failed");

        na_test_info->mpi_comm = MPI_COMM_WORLD; /* default */
    }

    rc = MPI_Comm_rank(na_test_info->mpi_comm, &na_test_info->mpi_comm_rank);
    NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret, NA_PROTOCOL_ERROR,
        "MPI_Comm_rank() failed");

    rc = MPI_Comm_size(na_test_info->mpi_comm, &na_test_info->mpi_comm_size);
    NA_TEST_CHECK_ERROR(rc != MPI_SUCCESS, error, ret, NA_PROTOCOL_ERROR,
        "MPI_Comm_size() failed");

    return NA_SUCCESS;

error:
    na_test_mpi_finalize(na_test_info);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_test_mpi_finalize(struct na_test_info *na_test_info)
{
    int mpi_finalized = 0;

    if (na_test_info->mpi_no_finalize)
        return;

    (void) MPI_Finalized(&mpi_finalized);
    if (mpi_finalized)
        return;

    if (na_test_info->mpi_static && na_test_info->mpi_comm != MPI_COMM_NULL)
        (void) MPI_Comm_free(&na_test_info->mpi_comm);

    (void) MPI_Finalize();
}
#endif

/*---------------------------------------------------------------------------*/
static char *
na_test_gen_config(struct na_test_info *na_test_info, int i)
{
    char *info_string = NULL, *info_string_ptr = NULL;

    info_string = (char *) malloc(sizeof(char) * NA_TEST_MAX_ADDR_NAME);
    NA_TEST_CHECK_ERROR_NORET(
        info_string == NULL, error, "Could not allocate info string");

    memset(info_string, '\0', NA_TEST_MAX_ADDR_NAME);
    info_string_ptr = info_string;
    if (na_test_info->comm)
        info_string_ptr += sprintf(info_string_ptr, "%s+", na_test_info->comm);
    info_string_ptr +=
        sprintf(info_string_ptr, "%s://", na_test_info->protocol);
    if (na_test_info->domain)
        info_string_ptr +=
            sprintf(info_string_ptr, "%s/", na_test_info->domain);

    if (strcmp("sm", na_test_info->protocol) == 0) {
#if defined(PR_SET_PTRACER) && defined(PR_SET_PTRACER_ANY)
        FILE *scope_config;
        int yama_val = '0';

        /* Try to open ptrace_scope */
        scope_config = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
        if (scope_config) {
            yama_val = fgetc(scope_config);
            fclose(scope_config);
        }

        /* Enable CMA on systems with YAMA */
        if (yama_val != '0') {
            int rc = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
            NA_TEST_CHECK_ERROR_NORET(rc < 0, error, "Could not set ptracer");
        }
#endif
    } else if (strcmp("static", na_test_info->protocol) == 0) {
        /* Nothing */
    } else if (strcmp("dynamic", na_test_info->protocol) == 0) {
        /* Nothing */
    } else {
        if (na_test_info->hostname)
            info_string_ptr +=
                sprintf(info_string_ptr, "%s", na_test_info->hostname);
        if (na_test_info->port)
            info_string_ptr +=
                sprintf(info_string_ptr, ":%d", na_test_info->port + i);
    }

    return info_string;

error:
    free(info_string);

    return NULL;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_set_config(const char *addr_name, bool append)
{
    FILE *config = NULL;
    na_return_t ret;

    config = fopen(
        HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME, append ? "a" : "w");
    NA_TEST_CHECK_ERROR(config == NULL, error, ret, NA_NOENTRY,
        "Could not open config file from: %s",
        HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);

    fprintf(config, "%s\n", addr_name);
    fclose(config);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
na_test_get_config(char *addr_name, size_t len)
{
    FILE *config = NULL;
    char *s;
    na_return_t ret;
    int rc;

    config = fopen(HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME, "r");
    NA_TEST_CHECK_ERROR(config == NULL, error, ret, NA_NOENTRY,
        "Could not open config file from: %s",
        HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);

    s = fgets(addr_name, (int) len, config);
    NA_TEST_CHECK_ERROR(
        s == NULL, error, ret, NA_NOENTRY, "Could not retrieve config name");

    /* This prevents retaining the newline, if any */
    addr_name[strlen(addr_name) - 1] = '\0';

    rc = fclose(config);
    config = NULL;
    NA_TEST_CHECK_ERROR(
        rc != 0, error, ret, NA_PROTOCOL_ERROR, "fclose() failed");

    return NA_SUCCESS;

error:
    if (config != NULL)
        fclose(config);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_test_self_addr_publish(na_class_t *na_class, bool append)
{
    char addr_string[NA_TEST_MAX_ADDR_NAME];
    size_t addr_string_len = NA_TEST_MAX_ADDR_NAME;
    na_addr_t self_addr = NA_ADDR_NULL;
    na_return_t ret;

    ret = NA_Addr_self(na_class, &self_addr);
    NA_TEST_CHECK_NA_ERROR(
        error, ret, "NA_Addr_self() failed (%s)", NA_Error_to_string(ret));

    ret = NA_Addr_to_string(na_class, addr_string, &addr_string_len, self_addr);
    NA_TEST_CHECK_NA_ERROR(
        error, ret, "NA_Addr_to_string() failed (%s)", NA_Error_to_string(ret));

    ret = NA_Addr_free(na_class, self_addr);
    NA_TEST_CHECK_NA_ERROR(
        error, ret, "NA_Addr_free() failed (%s)", NA_Error_to_string(ret));

    ret = na_test_set_config(addr_string, append);
    NA_TEST_CHECK_NA_ERROR(error, ret, "na_test_set_config() failed (%s)",
        NA_Error_to_string(ret));

    return NA_SUCCESS;

error:
    if (self_addr != NA_ADDR_NULL)
        (void) NA_Addr_free(na_class, self_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_init(int argc, char *argv[], struct na_test_info *na_test_info)
{
    char *info_string = NULL;
    struct na_init_info na_init_info = NA_INIT_INFO_INITIALIZER;
    na_return_t ret = NA_SUCCESS;
    const char *log_subsys = getenv("HG_LOG_SUBSYS");
    int i;

    if (!log_subsys) {
        const char *log_level = getenv("HG_LOG_LEVEL");

        /* Set log level */
        if (!log_level)
            log_level = "warning";

        /* Set global log level */
        NA_Set_log_level(log_level);
        HG_Util_set_log_level(log_level);
    }

    na_test_parse_options(argc, argv, na_test_info);

#ifdef HG_TEST_HAS_PARALLEL
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(na_test_info);
    na_test_info->max_number_of_peers = MPIEXEC_MAX_NUMPROCS;
#else
    na_test_info->mpi_comm_rank = 0;
    na_test_info->mpi_comm_size = 1;
    na_test_info->max_number_of_peers = 1;
#endif
    if (na_test_info->max_classes == 0)
        na_test_info->max_classes = 1;

    /* Call cleanup before doing anything */
    if (na_test_info->listen && na_test_info->mpi_comm_rank == 0)
        NA_Cleanup();

    if (na_test_info->busy_wait) {
        na_init_info.progress_mode = NA_NO_BLOCK;
        printf("# Initializing NA in busy wait mode\n");
    }
    na_init_info.auth_key = na_test_info->key;
    if (na_test_info->max_contexts != 0)
        na_init_info.max_contexts = na_test_info->max_contexts;
    na_init_info.max_unexpected_size = (size_t) na_test_info->max_msg_size;
    na_init_info.max_expected_size = (size_t) na_test_info->max_msg_size;
    na_init_info.thread_mode =
        na_test_info->use_threads ? 0 : NA_THREAD_MODE_SINGLE;

    na_test_info->na_classes = (na_class_t **) malloc(
        sizeof(na_class_t *) * na_test_info->max_classes);
    NA_TEST_CHECK_ERROR(na_test_info->na_classes == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA classes");

    for (i = 0; i < na_test_info->max_classes; i++) {
        /* Generate NA init string and get config options */
        info_string = na_test_gen_config(na_test_info,
            i + na_test_info->mpi_comm_rank * na_test_info->max_classes);
        NA_TEST_CHECK_ERROR(info_string == NULL, error, ret, NA_PROTOCOL_ERROR,
            "Could not generate config string");

        printf("# Using info string: %s\n", info_string);

        na_test_info->na_classes[i] =
            NA_Initialize_opt(info_string, na_test_info->listen, &na_init_info);
        NA_TEST_CHECK_ERROR(na_test_info->na_classes[i] == NULL, error, ret,
            NA_PROTOCOL_ERROR, "NA_Initialize_opt(%s) failed", info_string);

        free(info_string);
        info_string = NULL;
    }
    if (na_test_info->na_classes && na_test_info->na_classes[0])
        na_test_info->na_class = na_test_info->na_classes[0]; /* default */

    if (na_test_info->extern_init)
        return NA_SUCCESS; /* Upper layer will do the rest */

    if (na_test_info->listen) {
        for (i = 0; i < na_test_info->max_classes; i++) {
            ret = na_test_self_addr_publish(na_test_info->na_classes[i], i > 0);
            NA_TEST_CHECK_NA_ERROR(
                error, ret, "na_test_self_addr_publish() failed");
        }

#ifdef HG_TEST_HAS_PARALLEL
        /* If static client must wait for server to write config file */
        if (na_test_info->mpi_static)
            MPI_Barrier(MPI_COMM_WORLD);
#endif

        /* Used by CTest Test Driver to know when to launch clients */
        HG_TEST_READY_MSG();
    }
    /* Get config from file if self option is not passed */
    else if (!na_test_info->self_send) {
        char test_addr_name[NA_TEST_MAX_ADDR_NAME] = {'\0'};

#ifdef HG_TEST_HAS_PARALLEL
        /* If static client must wait for server to write config file */
        if (na_test_info->mpi_static)
            MPI_Barrier(MPI_COMM_WORLD);
#endif
        if (na_test_info->mpi_comm_rank == 0) {
            ret = na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME);
            NA_TEST_CHECK_NA_ERROR(error, ret,
                "na_test_get_config() failed (%s)", NA_Error_to_string(ret));
        }

#ifdef HG_TEST_HAS_PARALLEL
        /* Broadcast addr name */
        MPI_Bcast(test_addr_name, NA_TEST_MAX_ADDR_NAME, MPI_BYTE, 0,
            na_test_info->mpi_comm);
#endif

        na_test_info->target_name = strdup(test_addr_name);
        NA_TEST_CHECK_ERROR(na_test_info->target_name == NULL, error, ret,
            NA_NOMEM, "strdup() of target_name failed");

        printf("# Target name read: %s\n", na_test_info->target_name);
    }

    return NA_SUCCESS;

error:
    free(info_string);
    NA_Test_finalize(na_test_info);

    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_finalize(struct na_test_info *na_test_info)
{
    na_return_t ret = NA_SUCCESS;
    int i;

    if (na_test_info->na_classes != NULL) {
        for (i = 0; i < na_test_info->max_classes; i++) {
            ret = NA_Finalize(na_test_info->na_classes[i]);
            NA_TEST_CHECK_NA_ERROR(done, ret, "NA_Finalize() failed (%s)",
                NA_Error_to_string(ret));
        }
        free(na_test_info->na_classes);
        na_test_info->na_classes = NULL;
        na_test_info->na_class = NULL;
    }
    if (na_test_info->target_name != NULL) {
        free(na_test_info->target_name);
        na_test_info->target_name = NULL;
    }
    if (na_test_info->comm != NULL) {
        free(na_test_info->comm);
        na_test_info->comm = NULL;
    }
    if (na_test_info->protocol != NULL) {
        free(na_test_info->protocol);
        na_test_info->protocol = NULL;
    }
    if (na_test_info->hostname != NULL) {
        free(na_test_info->hostname);
        na_test_info->hostname = NULL;
    }
    if (na_test_info->domain != NULL) {
        free(na_test_info->domain);
        na_test_info->domain = NULL;
    }
    if (na_test_info->key != NULL) {
        free(na_test_info->key);
        na_test_info->key = NULL;
    }

#ifdef HG_TEST_HAS_PARALLEL
    na_test_mpi_finalize(na_test_info);
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Test_barrier(const struct na_test_info *na_test_info)
{
#ifdef HG_TEST_HAS_PARALLEL
    MPI_Barrier(na_test_info->mpi_comm);
#else
    (void) na_test_info;
#endif
}

/*---------------------------------------------------------------------------*/
void
NA_Test_bcast(
    char *buf, int count, int root, const struct na_test_info *na_test_info)
{
#ifdef HG_TEST_HAS_PARALLEL
    MPI_Bcast(buf, count, MPI_BYTE, root, na_test_info->mpi_comm);
#else
    (void) na_test_info;
    (void) count;
    (void) root;
    (void) buf;
#endif
}
