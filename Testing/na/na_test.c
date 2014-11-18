/*
 * Copyright (C) 2013-2014 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
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
#ifdef NA_HAS_CCI
#include "na_cci.h"
#endif
#ifdef MERCURY_HAS_PARALLEL_TESTING
#include <mpi.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
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

static const char *na_test_short_opt_g = "hc:p:sSVE";
static const struct na_test_opt na_test_opt_g[] = {
    { "help", no_arg, 'h'},
    { "comm", require_arg, 'c' },
    { "protocol", require_arg, 'p' },
    { "static", no_arg, 's' },
//    { "device", require_arg, 'd' },
//    { "iface", require_arg, 'i' }
    { "self", no_arg, 'S' },
    { "variable", no_arg, 'V' },
    { "extra", no_arg, 'E' },
    { NULL, 0, '\0' } /* Must add this at the end */
};

static na_bool_t na_test_use_mpi_g = NA_FALSE;
static na_bool_t na_test_use_cci_g = NA_FALSE;
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
na_test_gen_config(int argc, char *argv[]);

static void
na_test_set_config(const char *addr_name);

static void
na_test_get_config(char *addr_name, na_size_t len);

static void
na_test_gethostname(char *name, na_size_t len);

static char *
na_test_getaddrinfo(const char *hostname);

/*---------------------------------------------------------------------------*/
static void
na_test_usage(const char *execname)
{
    printf("usage: %s [OPTIONS]\n", execname);
    printf("  OPTIONS\n");
    printf("     -h,   --help         Print a usage message and exit\n");
    printf("     -c,   --comm         Select NA plugin\n"
           "                          NA plugins: bmi, mpi, ssm\n");
    printf("     -p,   --protocol     Select plugin protocol\n"
           "                          Available protocols: tcp, ib\n");
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
        fprintf(stderr, "Could not setup GNI job\n");
        return;
    }
#endif
    if (server || na_test_use_static_mpi_g) {
        int provided;

        MPI_Init_thread(NULL, NULL, MPI_THREAD_MULTIPLE, &provided);
        if (provided != MPI_THREAD_MULTIPLE) {
            fprintf(stderr, "MPI_THREAD_MULTIPLE cannot be set\n");
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
                fprintf(stderr, "Could not split communicator\n");
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
na_test_gen_config(int argc, char *argv[])
{
    char *na_class_name = NULL;
    char *na_protocol_name = NULL;
    static char info_string[NA_TEST_MAX_ADDR_NAME];
    char na_hostname[NA_TEST_MAX_ADDR_NAME];
    unsigned int na_port = 22222;
    char *info_string_ptr = info_string;
    int opt;

    if (argc < 2) {
        na_test_usage(argv[0]);
        exit(0);
    }

    while ((opt = na_test_getopt(argc, argv, na_test_short_opt_g,
            na_test_opt_g)) != EOF) {
        switch (opt) {
            case 'h':
                na_test_usage(argv[0]);
                exit(0);
            case 'c':
                /* NA class name */
                na_class_name = strdup(na_test_opt_arg_g);
                if (strcmp("mpi", na_class_name) == 0)
                    na_test_use_mpi_g = NA_TRUE;
                if (strcmp("cci", na_class_name) == 0)
                    na_test_use_cci_g = NA_TRUE;
                break;
            case 'p':
                /* NA protocol name */
                na_protocol_name = strdup(na_test_opt_arg_g);
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

    /* Add NA class */
    if (na_class_name)
        info_string_ptr += sprintf(info_string_ptr, "%s+", na_class_name);

    /* Use default if nothing specified */
    na_protocol_name = (na_protocol_name) ? na_protocol_name : strdup("tcp");
    info_string_ptr += sprintf(info_string_ptr, "%s", na_protocol_name);

    /* Generate a port number depending on server rank */
    na_port += na_test_comm_rank_g;
    na_test_gethostname(na_hostname, NA_TEST_MAX_ADDR_NAME);
    sprintf(info_string_ptr, "://%s:%d", na_test_getaddrinfo(na_hostname),
            na_port);

    free(na_class_name);
    free(na_protocol_name);
    return info_string;
}

/*---------------------------------------------------------------------------*/
static void
na_test_set_config(const char *addr_name)
{
    FILE *config = NULL;
    int max_port_name_length = 256; /* default set to 256 */
    int i;

#ifdef MERCURY_HAS_PARALLEL_TESTING
    max_port_name_length = MPI_MAX_PORT_NAME;
#endif

    /* Allocate table addrs */
    na_addr_table = (char**) malloc(na_test_comm_size_g * sizeof(char*));
    for (i = 0; i < na_test_comm_size_g; i++) {
        na_addr_table[i] = (char*) malloc(max_port_name_length);
    }

    strcpy(na_addr_table[na_test_comm_rank_g], addr_name);

    na_addr_table_size = na_test_comm_size_g;

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
            fprintf(stderr, "Could not open config file from: %s\n",
                    MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
            exit(0);
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
            fprintf(stderr, "Could not open config file from: %s\n",
                    MERCURY_TESTING_TEMP_DIRECTORY HG_TEST_CONFIG_FILE_NAME);
            exit(0);
        }
        fgets(config_addr_name, NA_TEST_MAX_ADDR_NAME, config);
        /* This prevents retaining the newline, if any */
        config_addr_name[strlen(config_addr_name) - 1] = '\0';
        printf("Port name read: %s\n", config_addr_name);
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
static void
na_test_gethostname(char *name, na_size_t len)
{
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(2, 0);

    if (WSAStartup(wVersionRequested, &wsaData) != 0)
        goto done;
#endif

    gethostname(name, len);

#ifdef _WIN32
done:
    WSACleanup();
#endif
}

/*---------------------------------------------------------------------------*/
static char *
na_test_getaddrinfo(const char *hostname)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;
    char *result_addr = NULL;
#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(2, 0);

    if (WSAStartup(wVersionRequested, &wsaData) != 0)
        goto done;
#endif

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    s = getaddrinfo(hostname, NULL, &hints, &result);
    if (s != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      goto done;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in *rp_addr_in =
                (struct sockaddr_in *) rp->ai_addr;
        result_addr = inet_ntoa(rp_addr_in->sin_addr);
        /* Try to avoid localhost addresses */
        if (strcmp("127.0.0.1", result_addr) != 0)
            break;
    }

done:
    freeaddrinfo(result);
#ifdef _WIN32
    WSACleanup();
#endif
    return result_addr;
}

/*---------------------------------------------------------------------------*/
na_class_t *
NA_Test_client_init(int argc, char *argv[], char *addr_name,
        na_size_t max_addr_name, int *rank)
{
    const char *info_string = NULL;
    na_class_t *na_class = NULL;

    info_string = na_test_gen_config(argc, argv);

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(NA_FALSE);
#endif

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

    info_string = na_test_gen_config(argc, argv);

#ifdef MERCURY_HAS_PARALLEL_TESTING
    /* Test run in parallel using mpirun so must intialize MPI to get
     * basic setup info etc */
    na_test_mpi_init(NA_TRUE);
#endif

    na_class = NA_Initialize(info_string, NA_TRUE);

#ifdef NA_HAS_MPI
    if (na_test_use_mpi_g) {
        na_test_set_config(NA_MPI_Get_port_name(na_class));
    } else
#endif
#ifdef NA_HAS_CCI
    if (na_test_use_cci_g) {
	    const char *uri = NA_CCI_Get_port_name(na_class);
	    na_test_set_config(uri);
    } else
#endif
    {
        /* Gather strings and write config */
        na_test_set_config(info_string);
    }

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
        printf("Waiting for client...\n");
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
        fprintf(stderr, "Could not finalize NA interface\n");
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
