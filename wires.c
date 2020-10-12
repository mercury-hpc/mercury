#include <assert.h>
#include <err.h>
#include <inttypes.h>   /* for PRIx8, etc. */
#include <libgen.h>     /* basename */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>  /* for MIN, MAX */

#include <ucp/api/ucp.h>

#include "ring.h"
#include "util.h"
#include "wiring.h"
#include "wireup.h"

static void
usage(const char *_progname)
{
    char *progname = strdup(_progname);
    assert(progname != NULL);
    fprintf(stderr, "usage: %s [remote address]\n", basename(progname));
    free(progname);
    exit(EXIT_FAILURE);
}

static void
run_client(ucp_worker_h worker, size_t request_size,
    ucp_address_t *laddr, size_t laddrlen,
    ucp_address_t *raddr, size_t raddrlen)
{
    wiring_t *wiring;

    if ((wiring = wiring_create(worker, request_size)) == NULL)
        errx(EXIT_FAILURE, "%s: could not create wiring", __func__);

    wireup_start(&wiring, laddr, laddrlen, raddr, raddrlen);

    while (wireup_once(wiring))
            ucp_worker_progress(worker);

    wiring_destroy(wiring);
}

static void
run_server(ucp_worker_h worker, size_t request_size)
{
    wiring_t *wiring;

    if ((wiring = wiring_create(worker, request_size)) == NULL)
        errx(EXIT_FAILURE, "%s: could not create wiring", __func__);

    while (wireup_once(wiring))
            ucp_worker_progress(worker);

    wiring_destroy(wiring);
}

int
main(int argc, char **argv)
{
    ucs_status_t status;
    ucp_config_t *config;
    ucp_context_h context;
    ucp_worker_h worker;
    ucp_address_t *laddr;
    ucp_address_t *raddr;
    size_t i, laddrlen, raddrlen;
    const char *delim = "";
    ucp_context_attr_t context_attrs;
    ucp_params_t global_params = {
      .field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_REQUEST_SIZE |
                    UCP_PARAM_FIELD_REQUEST_INIT
    , .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA
    , .request_size = sizeof(rxdesc_t)
    , .request_init = rxdesc_init
    };
    ucp_worker_params_t worker_params = {
      .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE
    , .thread_mode = UCS_THREAD_MODE_MULTI
    };

    if (argc > 2)
        usage(argv[0]);
    if (argc == 2) {
        uint8_t *buf;

        if (colon_separated_octets_to_bytes(argv[1], &buf,
                                            &raddrlen) == -1)
            errx(EXIT_FAILURE, "could not parse remote address `%s`", argv[1]);
        printf("parsed %zu-byte remote address\n", raddrlen);
        raddr = (void *)buf;
    } else {
        raddr = NULL;
    }

    if ((status = ucp_config_read(NULL, NULL, &config)) != UCS_OK)
        errx(EXIT_FAILURE, "%s: ucp_config_read", __func__);

    status = ucp_init(&global_params, config, &context);

    ucp_config_release(config);

    if (status != UCS_OK)
        errx(EXIT_FAILURE, "%s: ucp_init", __func__);

    context_attrs.field_mask = UCP_ATTR_FIELD_REQUEST_SIZE;
    status = ucp_context_query(context, &context_attrs);

    if (status != UCS_OK)
        errx(EXIT_FAILURE, "%s: ucp_context_query", __func__);

    if ((context_attrs.field_mask & UCP_ATTR_FIELD_REQUEST_SIZE) == 0)
        errx(EXIT_FAILURE, "context attributes contain no request size");

    status = ucp_worker_create(context, &worker_params, &worker);
    if (status != UCS_OK) {
        warnx("%s: ucp_worker_create", __func__);
        goto cleanup_context;
    }

    status = ucp_worker_get_address(worker, &laddr, &laddrlen);
    if (status != UCS_OK) {
        warnx("%s: ucp_worker_get_address", __func__);
        goto cleanup_worker;
    }

    printf("%zu-byte local address ", laddrlen);
    for (i = 0; i < laddrlen; i++) {
        printf("%s%02" PRIx8, delim, ((uint8_t *)laddr)[i]);
        delim = ":";
    }
    printf("\n");

    if (raddr != NULL) {      /* * * client mode * * */
        run_client(worker, context_attrs.request_size,
            laddr, laddrlen, raddr, raddrlen);
        free(raddr);
    } else {                        /* * * server mode * * */
        run_server(worker, context_attrs.request_size);
    }

    ucp_worker_release_address(worker, laddr);
cleanup_worker:
    ucp_worker_destroy(worker);
cleanup_context:
    ucp_cleanup(context);
    return EXIT_SUCCESS;
}
