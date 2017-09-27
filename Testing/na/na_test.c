/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
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
#include "na_mpi.h"
#endif
#ifdef MERCURY_HAS_PARALLEL_TESTING
#include <mpi.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#if defined(HG_TESTING_HAS_SYSPRCTL_H)
#include <sys/prctl.h>
#endif
#endif

/****************/
/* Local Macros */
/****************/
#define HG_TEST_CONFIG_FILE_NAME "/port.cfg"

/*******************/
/* Local Variables */
/*******************/
int na_test_comm_rank_g = 0;
int na_test_comm_size_g = 1;

#ifdef MERCURY_HAS_PARALLEL_TESTING
static MPI_Comm na_test_comm_g = MPI_COMM_WORLD;
static int mpi_internally_initialized = NA_FALSE;
#endif

static char **na_addr_table = NULL;
static unsigned int na_addr_table_size = 0;

static const char *na_test_short_opt_g = "hc:p:H:sSVE";
static const struct na_test_opt na_test_opt_g[] = {
    { "help", no_arg, 'h'},
    { "comm", require_arg, 'c' },
    { "protocol", require_arg, 'p' },
    { "host", require_arg, 'H' },
    { "static", no_arg, 's' },
//    { "device", require_arg, 'd' },
//    { "iface", require_arg, 'i' }
    { "self", no_arg, 'S' },
    { "variable", no_arg, 'V' },
    { "extra", no_arg, 'E' },
    { NULL, 0, '\0' } /* Must add this at the end */
};

static na_bool_t na_test_use_static_mpi_g = NA_FALSE;
na_bool_t na_test_use_self_g = NA_FALSE;
na_bool_t na_test_use_variable_g = NA_FALSE;
na_bool_t na_test_use_extra_g = NA_FALSE;

/********************/
/* Local Prototypes */
/********************/
#ifdef MERCURY_HAS_PARALLEL_TESTING
static void
na_test_mpi_init(na_bool_t server);

static void
na_test_mpi_finalize(void);
#endif

static void
na_test_usage(const char *execname);

static const char *
na_test_gen_config(int argc, char *argv[], int listen);

static void
na_test_set_config(const char *addr_name);

static void
na_test_get_config(char *addr_name, na_size_t len);

/*---------------------------------------------------------------------------*/
static void
na_test_usage(const char *execname)
{
    printf("usage: %s [OPTIONS]\n", execname);
    printf("  OPTIONS\n");
    printf("     -h,   --help         Print a usage message and exit\n");
    printf("     -c,   --comm         Select NA plugin\n"
           "                          NA plugins: bmi, mpi, cci, etc\n");
    printf("     -p,   --protocol     Select plugin protocol\n"
           "                          Available protocols: tcp, ib, etc\n");
    printf("     -H,   --host         Select hostname / IP address to use\n"
           "                          Default: localhost\n");
}

/*---------------------------------------------------------------------------*/
#ifdef MERCURY_HAS_PARALLEL_TESTING
static void
na_test_mpi_init(na_bool_t server)
{
    int mpi_initialized = 0;

    MPI_Initialized(&mpi_initialized);
    if (mpi_initialized) goto done;

#ifdef NA_MPI_HAS_GNI_SETUP
    /* Setup GNI job before initializing MPI */
    if (NA_MPI_Gni_job_setup() != NA_SUCCESS) {
        NA_LOG_ERROR("Could not setup GNI job");
        return;
    }
#endif
    if (server || na_test_use_static_mpi_g) {
        int provided;

        MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        if (provided != MPI_THREAD_MULTIPLE) {
            NA_LOG_ERROR("MPI_THREAD_MULTIPLE cannot be set");
        }

        /* Only if we do static MPMD MPI */
        if (na_test_use_static_mpi_g) {
            int mpi_ret, color, global_rank;

            MPI_Comm_rank(MPI_COMM_WORLD, &global_rank);
            /* Color is 1 for server, 2 for client */
            color = (server) ? 1 : 2;

            /* Assume that the application did not split MPI_COMM_WORLD already */
            mpi_ret = MPI_Comm_split(MPI_COMM_WORLD, color, global_rank,
                    &na_test_comm_g);
            if (mpi_ret != MPI_SUCCESS) {
                NA_LOG_ERROR("Could not split communicator");
            }
#ifdef NA_HAS_MPI
            /* Set init comm that will be used to setup NA MPI */
            NA_MPI_Set_init_intra_comm(na_test_comm_g);
#endif
        }
    } else {
        MPI_Init(NULL, NULL);
    }
    mpi_internally_initialized = NA_TRUE;

done:
    MPI_Comm_rank(na_test_comm_g, &na_test_comm_rank_g);
    MPI_Comm_size(na_test_comm_g, &na_test_comm_size_g);
}

/*---------------------------------------------------------------------------*/
static void
na_test_mpi_finalize(void)
{
    int mpi_finalized = 0;

    MPI_Finalized(&mpi_finalized);
    if (!mpi_finalized && mpi_internally_initialized) {
        if (na_test_use_static_mpi_g) {
            MPI_Comm_free(&na_test_comm_g);
        }
        MPI_Finalize();
        mpi_internally_initialized = NA_FALSE;
    }
}
#endif

/*---------------------------------------------------------------------------*/
static const char *
na_test_gen_config(int argc, char *argv[], int listen)
{
    char *na_class_name = NULL;
    char *na_protocol_name = NULL;
    char *na_hostname = NULL;
    static char info_string[NA_TEST_MAX_ADDR_NAME];
    unsigned int na_port = 22222;
    char *info_string_ptr = info_string;
    int opt;

    if (argc < 2) {
        na_test_usage(argv[0]);
        exit(1);
    }

    while ((opt = na_test_getopt(argc, argv, na_test_short_opt_g,
            na_test_opt_g)) != EOF) {
        switch (opt) {
            case 'h':
                na_test_usage(argv[0]);
                exit(1);
            case 'c':
                /* NA class name */
                na_class_name = strdup(na_test_opt_arg_g);
                break;
            case 'p':
                /* NA protocol name */
                na_protocol_name = strdup(na_test_opt_arg_g);
                break;
            case 'H':
                /* hostname */
                na_hostname = strdup(na_test_opt_arg_g);
                break;
            case 's':
                na_test_use_static_mpi_g = NA_TRUE;
                if (na_protocol_name) free(na_protocol_name);
                na_protocol_name = strdup("static");
                break;
            case 'S':
                na_test_use_self_g = NA_TRUE;
                break;
            case 'V':
                na_test_use_variable_g = NA_TRUE;
                break;
            case 'E':
                na_test_use_extra_g = NA_TRUE;
                break;
            default:
                break;
        }
    }

    memset(info_string, '\0', NA_TEST_MAX_ADDR_NAME);

    if (!na_class_name) {
        na_test_usage(argv[0]);
        exit(1);
    }

    info_string_ptr += sprintf(info_string_ptr, "%s+", na_class_name);

    if (!na_protocol_name) {
        na_test_usage(argv[0]);
        exit(1);
    }

    info_string_ptr += sprintf(info_string_ptr, "%s", na_protocol_name);

    if (strcmp("sm", na_protocol_name) == 0) {
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
        if ((yama_val != '0')
            && prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) < 0) {
            NA_LOG_ERROR("Could not set ptracer\n");
            exit(1);
        }
#endif
        if (listen) {
            /* special-case SM (pid:id) */
            sprintf(info_string_ptr, "://%d/0", (int) getpid());
        }
    } else if ((strcmp("tcp", na_protocol_name) == 0)
        || (strcmp("verbs", na_protocol_name) == 0)
        || (strcmp("psm2", na_protocol_name) == 0)
        || (strcmp("sockets", na_protocol_name) == 0)) {
        if (listen) {
            const char *hostname = na_hostname ? na_hostname : "localhost";
            na_port += (unsigned int) na_test_comm_rank_g;
            sprintf(info_string_ptr, "://%s:%d", hostname, na_port);
        } else {
            const char *hostname = na_hostname ? na_hostname : "localhost";
            sprintf(info_string_ptr, "://%s", hostname);
        }
    } else if (strcmp("static", na_protocol_name) == 0) {
        /* Nothing */
    } else if (strcmp("dynamic", na_protocol_name) == 0) {
        /* Nothing */
    } else if (strcmp("gni", na_protocol_name) == 0) {
        const char *hostname = na_hostname ? na_hostname : "localhost";
        na_port += (unsigned int) na_test_comm_rank_g;
        sprintf(info_string_ptr, "://%s:%d", hostname, na_port);
    } else {
        NA_LOG_ERROR("Unknown protocol: %s", na_protocol_name);
        exit(1);
    }

    free(na_class_name);
    free(na_protocol_name);
    free(na_hostname);
    return info_string;
}

/*---------------------------------------------------------------------------*/
static void
na_test_set_config(const char *addr_name)
{
    FILE *config = NULL;
    unsigned int max_port_name_length = 256; /* default set to 256 */
    int i;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    max_port_name_length = MPI_MAX_PORT_NAME;
#endif

    /* Allocate table addrs */
    na_addr_table = (char**) malloc((unsigned int) na_test_comm_size_g * sizeof(char*));
    for (i = 0; i < na_test_comm_size_g; i++) {
        na_addr_table[i] = (char*) malloc(max_port_name_length);
    }

    strcpy(na_addr_table[na_test_comm_rank_g], addr_name);

    na_addr_table_size = (unsigned int) na_test_comm_size_g;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    for (i = 0; i < na_test_comm_size_g; i++) {
        MPI_Bcast(na_addr_table[i], MPI_MAX_PORT_NAME, MPI_BYTE, i,
                na_test_comm_g);
    }
#endif

    /* Only rank 0 writes file */
    if (na_test_comm_rank_g == 0) {
        config = fopen(MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME,
                "w+");
        if (!config) {
            NA_LOG_ERROR("Could not open config file from: %s",
                    MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
            exit(1);
        }
        for (i = 0; i < na_test_comm_size_g; i++) {
            fprintf(config, "%s\n", na_addr_table[i]);
        }
        fclose(config);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* If static client must wait for server to write config file */
    if (na_test_use_static_mpi_g)
        MPI_Barrier(MPI_COMM_WORLD);
#endif
}

/*---------------------------------------------------------------------------*/
static void
na_test_get_config(char *addr_name, na_size_t len)
{
    FILE *config = NULL;
    char config_addr_name[NA_TEST_MAX_ADDR_NAME];

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* If static client must wait for server to write config file */
    if (na_test_use_static_mpi_g)
        MPI_Barrier(MPI_COMM_WORLD);
#endif

    /* Only rank 0 reads file */
    if (na_test_comm_rank_g == 0) {
        config = fopen(MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME,
                "r");
        if (!config) {
            NA_LOG_ERROR("Could not open config file from: %s",
                    MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
            exit(1);
        }
        fgets(config_addr_name, NA_TEST_MAX_ADDR_NAME, config);
        /* This prevents retaining the newline, if any */
        config_addr_name[strlen(config_addr_name) - 1] = '\0';
        printf("# Port name read: %s\n", config_addr_name);
        fclose(config);
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Broadcast port name */
    MPI_Bcast(config_addr_name, NA_TEST_MAX_ADDR_NAME, MPI_BYTE, 0,
            na_test_comm_g);
#endif

    strncpy(addr_name, config_addr_name,
            (len < NA_TEST_MAX_ADDR_NAME) ? len : NA_TEST_MAX_ADDR_NAME);
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Test_client_init(int argc, char *argv[], char *addr_name,
        na_size_t max_addr_name, int *rank)
{
    const char *info_string = NULL;
    na_class_t *na_class = NULL;

    info_string = na_test_gen_config(argc, argv, 0);

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(NA_FALSE);
#endif

    printf("# Initializing NA with %s\n", info_string);
    na_class = NA_Initialize(info_string, NA_FALSE);

    /* Get config from file if self option is not passed */
    if (!na_test_use_self_g) {
        char test_addr_name[NA_TEST_MAX_ADDR_NAME];

        na_test_get_config(test_addr_name, NA_TEST_MAX_ADDR_NAME);

        strncpy(addr_name, test_addr_name,
                (max_addr_name < NA_TEST_MAX_ADDR_NAME) ?
                        max_addr_name : NA_TEST_MAX_ADDR_NAME);
    }

    if (rank) *rank = na_test_comm_rank_g;

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Test_server_init(int argc, char *argv[], na_bool_t print_ready,
        char ***addr_table, unsigned int *addr_table_size,
        unsigned int *max_number_of_peers)
{
    na_class_t *na_class = NULL;
    const char *info_string = NULL;
    char addr_string[NA_TEST_MAX_ADDR_NAME];
    na_addr_t self_addr = NA_ADDR_NULL;
    na_size_t addr_string_len = NA_TEST_MAX_ADDR_NAME;
    na_return_t nret;

    /* TODO call it once first for now to set static MPI */
    na_test_gen_config(argc, argv, 1);
    na_test_opt_ind_g = 1;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(NA_TRUE);
#endif

    info_string = na_test_gen_config(argc, argv, 1);

    printf("# Initializing NA with %s\n", info_string);
    na_class = NA_Initialize(info_string, NA_TRUE);

    nret = NA_Addr_self(na_class, &self_addr);
    if (nret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not get self addr");
    }

    nret = NA_Addr_to_string(na_class, addr_string, &addr_string_len, self_addr);
    if (nret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not convert addr to string");
    }
    NA_Addr_free(na_class, self_addr);

    na_test_set_config(addr_string);

    /* As many entries in addr table as number of server ranks */
    if (addr_table_size) *addr_table_size = na_addr_table_size;

    /* Point addr table to NA MPI addr table */
    if (addr_table) *addr_table = na_addr_table;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    if (max_number_of_peers) *max_number_of_peers = MPIEXEC_MAX_NUMPROCS;
#else
    if (max_number_of_peers) *max_number_of_peers = 1;
#endif

    if (print_ready) {
        /* Used by CTest Test Driver */
        printf("# Waiting for client...\n");
        fflush(stdout);
    }

    return na_class;
}

/*---------------------------------------------------------------------------*/
na_return_t
NA_Test_finalize(na_class_t *na_class)
{
    na_return_t ret;
    unsigned int i;

    ret = NA_Finalize(na_class);
    if (ret != NA_SUCCESS) {
        NA_LOG_ERROR("Could not finalize NA interface");
        goto done;
    }

    if (na_addr_table_size && na_addr_table) {
        for (i = 0; i < na_addr_table_size; i++) {
            free(na_addr_table[i]);
        }
        free(na_addr_table);
        na_addr_table = NULL;
        na_addr_table_size = 0;
    }

#ifdef MERCURY_HAS_PARALLEL_TESTING
    na_test_mpi_finalize();
#endif

done:
     return ret;
}

/*---------------------------------------------------------------------------*/
void
NA_Test_barrier(void)
{
#ifdef MERCURY_HAS_PARALLEL_TESTING
    MPI_Barrier(na_test_comm_g);
#endif
}
