/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mercury.h"

#include <stdio.h>
#include <stdlib.h>

#define NWIDTH 20

/*---------------------------------------------------------------------------*/
static hg_return_t
print_info(const char *info_string)
{
    struct na_protocol_info *protocol_infos = NULL, *protocol_info;
    hg_return_t ret;

    ret = HG_Get_na_protocol_info(info_string, &protocol_infos);
    if (ret != HG_SUCCESS) {
        fprintf(stderr, "HG_Get_protocol_info() failed (%s)\n",
            HG_Error_to_string(ret));
        return ret;
    }
    if (protocol_infos == NULL) {
        fprintf(stderr, "No protocol found for \"%s\"\n", info_string);
        return HG_PROTONOSUPPORT;
    }

    printf("--------------------------------------------------\n");
    printf("%-*s%*s%*s\n", 10, "Class", NWIDTH, "Protocol", NWIDTH, "Device");
    printf("--------------------------------------------------\n");
    for (protocol_info = protocol_infos; protocol_info != NULL;
         protocol_info = protocol_info->next)
        printf("%-*s%*s%*s\n", 10, protocol_info->class_name, NWIDTH,
            protocol_info->protocol_name, NWIDTH, protocol_info->device_name);

    HG_Free_na_protocol_info(protocol_infos);

    return HG_SUCCESS;
}

/*---------------------------------------------------------------------------*/
int
main(int argc, char *argv[])
{
    const char *info_string = NULL;
    hg_return_t hg_ret;

    if (argc == 1) {
        printf("Retrieving protocol info for all protocols...\n");
    } else if (argc == 2) {
        info_string = argv[1];
        printf("Retrieving protocol info for \"%s\"...\n", info_string);
    } else {
        printf("usage: %s [<class+protocol>]\n", argv[0]);
        goto err;
    }

    hg_ret = print_info(info_string);
    if (hg_ret != HG_SUCCESS)
        goto err;

    return EXIT_SUCCESS;

err:
    return EXIT_FAILURE;
}
