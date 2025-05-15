/**
 * Copyright (c) 2013-2022 UChicago Argonne, LLC and The HDF Group.
 * Copyright (c) 2022-2024 Intel Corporation.
 * Copyright (c) 2024-2025 Hewlett Packard Enterprise Development LP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#endif
#include "mercury_dl.h"

#include <string.h>

/*---------------------------------------------------------------------------*/
int
hg_dl_get_path(const void *addr, char *path, size_t path_size)
{
#ifdef _WIN32
    HMODULE module;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR) addr, &module))
        return GetModuleFileNameA(module, path, (DWORD) path_size);
#else
    Dl_info info;
    if (dladdr(addr, &info) && info.dli_fname) {
        strncpy(path, info.dli_fname, path_size);
        path[path_size - 1] = '\0';
        return HG_UTIL_SUCCESS;
    }
#endif

    return HG_UTIL_FAIL;
}
