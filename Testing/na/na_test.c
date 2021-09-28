/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_test.h"
#include "na_test_getopt.h"

#ifdef NA_HAS_MPI
#    include "na_mpi.h"
#endif

#include "mercury_util.h"

#include <assert.h>
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
static void
na_test_mpi_init(struct na_test_info *na_test_info);

static void
na_test_mpi_finalize(struct na_test_info *na_test_info);
#endif

static char *
na_test_gen_config(struct na_test_info *na_test_info);

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
    printf("    -h, --help          Print a usage message and exit\n");
    printf("    -c, --comm          Select NA plugin\n"
           "                        NA plugins: bmi, mpi, cci, etc\n");
    printf("    -d, --domain        Select NA OFI domain\n");
    printf("    -p, --protocol      Select plugin protocol\n"
           "                        Available protocols: tcp, ib, etc\n");
    printf("    -H, --hostname      Select hostname / IP address to use\n"
           "                        Default: any\n");
    printf("    -P, --port          Select port to use\n"
           "                        Default: any\n");
    printf("    -L, --listen        Listen for incoming messages\n");
    printf("    -S, --self_send     Send to self\n");
    printf("    -k, --key           Pass auth key\n");
    printf("    -l, --loop          Number of loops (default: 1)\n");
    printf("    -b, --busy          Busy wait\n");
    printf("    -V, --verbose       Print verbose output\n");
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
                na_test_info->listen = NA_TRUE;
                break;
            case 's': /* static */
                na_test_info->mpi_static = NA_TRUE;
                break;
            case 'S': /* self */
                na_test_info->self_send = NA_TRUE;
                break;
            case 'k': /* key */
                na_test_info->key = strdup(na_test_opt_arg_g);
                break;
            case 'l': /* loop */
                na_test_info->loop = atoi(na_test_opt_arg_g);
                break;
            case 'b': /* busy */
                na_test_info->busy_wait = NA_TRUE;
                break;
            case 'C': /* number of contexts */
                na_test_info->max_contexts =
                    (na_uint8_t) atoi(na_test_opt_arg_g);
                break;
            case 'Z': /* msg size */
                na_test_info->max_msg_size = atoi(na_test_opt_arg_g);
                break;
            case 'V': /* verbose */
                na_test_info->verbose = NA_TRUE;
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
static void
na_test_mpi_init(struct na_test_info *na_test_info)
{
    int mpi_initialized = 0;
    int mpi_finalized = 0;

    na_test_info->mpi_comm = MPI_COMM_WORLD; /* default */

    MPI_Initialized(&mpi_initialized);
    if (mpi_initialized) {
        NA_TEST_LOG_WARNING("MPI was already initialized");
        goto done;
    }
    MPI_Finalized(&mpi_finalized);
    if (mpi_finalized) {
        NA_TEST_LOG_ERROR("MPI was already finalized");
        goto done;
    }

#    ifdef NA_MPI_HAS_GNI_SETUP
    /* Setup GNI job before initializing MPI */
    if (NA_MPI_Gni_job_setup() != NA_SUCCESS) {
        NA_TEST_LOG_ERROR("Could not setup GNI job");
        return;
    }
#    endif
    if (na_test_info->listen || na_test_info->mpi_static) {
        int provided;

        MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        if (provided != MPI_THREAD_MULTIPLE) {
            NA_TEST_LOG_ERROR("MPI_THREAD_MULTIPLE cannot be set");
        }

        /* Only if we do static MPMD MPI */
        if (na_test_info->mpi_static) {
            int mpi_ret, color, global_rank;

            MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
            /* Color is 1 for server, 2 for client */
            color = (na_test_info->listen) ? 1 : 2;

            /* Assume that the application did not split MPI_COMM_WORLD already
             */
            mpi_ret = MPI_Comm_split(
                MPI_COMM_WORLD, color, global_rank, &na_test_info->mpi_comm);
            if (mpi_ret != MPI_SUCCESS) {
                NA_TEST_LOG_ERROR("Could not split communicator");
            }
#    ifdef NA_HAS_MPI
            /* Set init comm that will be used to setup NA MPI */
            NA_MPI_Set_init_intra_comm(na_test_info->mpi_comm);
#    endif
        }
    } else {
        MPI_Init(NULL, NULL);
    }

done:
    MPI_Comm_rank(na_test_info->mpi_comm, &na_test_info->mpi_comm_rank);
    MPI_Comm_size(na_test_info->mpi_comm, &na_test_info->mpi_comm_size);

    return;
}

/*---------------------------------------------------------------------------*/
static void
na_test_mpi_finalize(struct na_test_info *na_test_info)
{
    int mpi_finalized = 0;

    MPI_Finalized(&mpi_finalized);
    if (!mpi_finalized && !na_test_info->mpi_no_finalize) {
        if (na_test_info->mpi_static)
            MPI_Comm_free(&na_test_info->mpi_comm);
        MPI_Finalize();
    }
}
#endif

/*---------------------------------------------------------------------------*/
static char *
na_test_gen_config(struct na_test_info *na_test_info)
{
    char *info_string = NULL, *info_string_ptr = NULL;
    na_return_t ret = NA_SUCCESS;

    info_string = (char *) malloc(sizeof(char) * NA_TEST_MAX_ADDR_NAME);
    if (!info_string) {
        NA_TEST_LOG_ERROR("Could not allocate info string");
        ret = NA_NOMEM;
        goto done;
    }
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
        if ((yama_val != '0') &&
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) < 0) {
            NA_TEST_LOG_ERROR("Could not set ptracer\n");
            exit(1);
        }
#endif
    } else if (strcmp("static", na_test_info->protocol) == 0) {
        /* Nothing */
    } else if (strcmp("dynamic", na_test_info->protocol) == 0) {
        /* Nothing */
    } else if (na_test_info->hostname) {
        sprintf(info_string_ptr, "%s:%d", na_test_info->hostname,
            na_test_info->port + na_test_info->mpi_comm_rank);
    }

done:
    if (ret != NA_SUCCESS) {
        free(info_string);
        info_string = NULL;
    }
    return info_string;
}

/*---------------------------------------------------------------------------*/
void
na_test_set_config(const char *addr_name)
{
    FILE *config = NULL;

    config = fopen(HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME, "w+");
    if (!config) {
        NA_TEST_LOG_ERROR("Could not open config file from: %s",
            HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
        exit(1);
    }
    fprintf(config, "%s\n", addr_name);
    fclose(config);
}

/*---------------------------------------------------------------------------*/
void
na_test_get_config(char *addr_name, na_size_t len)
{
    FILE *config = NULL;

    config = fopen(HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME, "r");
    if (!config) {
        NA_TEST_LOG_ERROR("Could not open config file from: %s",
            HG_TEST_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
        exit(1);
    }
    if (fgets(addr_name, (int) len, config) == NULL) {
        NA_TEST_LOG_ERROR("Could not retrieve config name");
        fclose(config);
        exit(1);
    }
    /* This prevents retaining the newline, if any */
    addr_name[strlen(addr_name) - 1] = '\0';
    fclose(config);
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_init(int argc, char *argv[], struct na_test_info *na_test_info)
{
    char *info_string = NULL;
    struct na_init_info na_init_info = NA_INIT_INFO_INITIALIZER;
    na_return_t ret = NA_SUCCESS;
    const char *log_subsys = getenv("HG_LOG_SUBSYS");

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

    /* Generate NA init string and get config options */
    info_string = na_test_gen_config(na_test_info);
    if (!info_string) {
        NA_TEST_LOG_ERROR("Could not generate config string");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    /* Call cleanup before doing anything */
    if (na_test_info->listen && na_test_info->mpi_comm_rank == 0)
        NA_Cleanup();

    if (na_test_info->busy_wait) {
        na_init_info.progress_mode = NA_NO_BLOCK;
        printf("# Initializing NA in busy wait mode\n");
    }
    na_init_info.auth_key = na_test_info->key;
    na_init_info.max_contexts = na_test_info->max_contexts;
    na_init_info.max_unexpected_size = (na_size_t) na_test_info->max_msg_size;
    na_init_info.max_expected_size = (na_size_t) na_test_info->max_msg_size;
    na_init_info.thread_mode =
        na_test_info->use_threads ? 0 : NA_THREAD_MODE_SINGLE;

    printf("# Using info string: %s\n", info_string);
    na_test_info->na_class =
        NA_Initialize_opt(info_string, na_test_info->listen, &na_init_info);
    if (!na_test_info->na_class) {
        NA_TEST_LOG_ERROR("Could not initialize NA");
        ret = NA_PROTOCOL_ERROR;
        goto done;
    }

    if (!na_test_info->extern_init) {
        if (na_test_info->listen) {
            char addr_string[NA_TEST_MAX_ADDR_NAME];
            na_size_t addr_string_len = NA_TEST_MAX_ADDR_NAME;
            na_addr_t self_addr;
            na_return_t nret;

            /* TODO only rank 0 */
            nret = NA_Addr_self(na_test_info->na_class, &self_addr);
            if (nret != NA_SUCCESS) {
                NA_TEST_LOG_ERROR("Could not get self addr");
            }

            nret = NA_Addr_to_string(na_test_info->na_class, addr_string,
                &addr_string_len, self_addr);
            if (nret != NA_SUCCESS) {
                NA_TEST_LOG_ERROR("Could not convert addr to string");
            }
            NA_Addr_free(na_test_info->na_class, self_addr);

            na_test_set_config(addr_string);

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
                na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME);
            }

#ifdef HG_TEST_HAS_PARALLEL
            /* Broadcast addr name */
            MPI_Bcast(test_addr_name, NA_TEST_MAX_ADDR_NAME, MPI_BYTE, 0,
                na_test_info->mpi_comm);
#endif

            na_test_info->target_name = strdup(test_addr_name);
            printf("# Target name read: %s\n", na_test_info->target_name);
        }
    }

done:
    if (ret != NA_SUCCESS)
        NA_Test_finalize(na_test_info);
    free(info_string);
    return ret;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_finalize(struct na_test_info *na_test_info)
{
    na_return_t ret;

    ret = NA_Finalize(na_test_info->na_class);
    if (ret != NA_SUCCESS) {
        NA_TEST_LOG_ERROR("Could not finalize NA interface");
        goto done;
    }
    free(na_test_info->target_name);
    free(na_test_info->comm);
    free(na_test_info->protocol);
    free(na_test_info->hostname);
    free(na_test_info->key);

#ifdef HG_TEST_HAS_PARALLEL
    na_test_mpi_finalize(na_test_info);
#endif

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Test_barrier(struct na_test_info *na_test_info)
{
#ifdef HG_TEST_HAS_PARALLEL
    MPI_Barrier(na_test_info->mpi_comm);
#else
    (void) na_test_info;
#endif
}

/*---------------------------------------------------------------------------*/
void
NA_Test_bcast(char *buf, int count, int root, struct na_test_info *na_test_info)
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
