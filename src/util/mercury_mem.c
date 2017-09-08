/*
 * Copyright (C) 2013-2017 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "mercury_mem.h"
#include "mercury_util_error.h"

#ifdef _WIN32
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/stat.h>        /* For mode constants */
  #include <fcntl.h>           /* For O_* constants */
  #include <string.h>
  #include <errno.h>
#endif
#include <stdlib.h>

/*---------------------------------------------------------------------------*/
long
hg_mem_get_page_size(void)
{
    long page_size;

#ifdef _WIN32
    SYSTEM_INFO system_info;
    GetSystemInfo (&system_info);
    page_size = system_info.dwPageSize;
#else
    page_size = sysconf(_SC_PAGE_SIZE);
#endif

    return page_size;
}

/*---------------------------------------------------------------------------*/
void *
hg_mem_aligned_alloc(size_t alignment, size_t size)
{
    void *mem_ptr = NULL;

#ifdef _WIN32
    mem_ptr = _aligned_malloc(size, alignment);
#else
#ifdef _ISOC11_SOURCE
    mem_ptr = aligned_alloc(alignment, size);
#else
    if (posix_memalign(&mem_ptr, alignment, size) != 0) {
        HG_UTIL_LOG_ERROR("posix_memalign failed");
        return NULL;
    }
#endif
#endif

    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
void
hg_mem_aligned_free(void *mem_ptr)
{
#ifdef _WIN32
    _aligned_free(mem_ptr);
#else
    free(mem_ptr);
#endif
}

/*---------------------------------------------------------------------------*/
void *
hg_mem_shm_map(const char *name, size_t size, hg_util_bool_t create)
{
    void *mem_ptr = NULL;
    int ret = HG_UTIL_SUCCESS;
#ifdef _WIN32
    HANDLE fd = INVALID_HANDLE_VALUE;
    LARGE_INTEGER large = {.QuadPart = size};
    DWORD access = FILE_MAP_READ | FILE_MAP_WRITE;

    if (create) {
        fd = CreateFileMappingA(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE,
            large.HighPart, large.LowPart, name);
        if (!fd) {
            HG_UTIL_LOG_ERROR("CreateFileMappingA() failed");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    } else {
        fd = OpenFileMappingA(access, FALSE, name);
        if (!fd) {
            HG_UTIL_LOG_ERROR("OpenFileMappingA() failed");
            ret = HG_UTIL_FAIL;
            goto done;
        }
    }

    mem_ptr = MapViewOfFile(fd, access, 0, 0, size);
    if (!mem_ptr) {
        HG_UTIL_LOG_ERROR("MapViewOfFile() failed");
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* The handle can be closed without affecting the memory mapping */
    CloseHandle(fd);
#else
    int fd = 0;
    int flags = O_RDWR | (create ? O_CREAT : 0);
    struct stat shm_stat;

    fd = shm_open(name, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HG_UTIL_LOG_ERROR("shm_open() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (fstat(fd, &shm_stat)) {
        HG_UTIL_LOG_ERROR("fstat() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
     }

     if (shm_stat.st_size == 0) {
         if (ftruncate(fd, (off_t) size) < 0) {
             HG_UTIL_LOG_ERROR("ftruncate() failed (%s)", strerror(errno));
             ret = HG_UTIL_FAIL;
             goto done;
         }
     } else if (shm_stat.st_size < (off_t) size) {
         HG_UTIL_LOG_ERROR("shm file size too small");
         ret = HG_UTIL_FAIL;
         goto done;
     }

    mem_ptr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    if (mem_ptr == MAP_FAILED) {
        HG_UTIL_LOG_ERROR("mmap() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }

    /* The file descriptor can be closed without affecting the memory mapping */
    if (close(fd) == -1) {
        HG_UTIL_LOG_ERROR("close() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#endif

done:
    if (ret != HG_UTIL_SUCCESS) {
        /* TODO free buf */
    }
    return mem_ptr;
}

/*---------------------------------------------------------------------------*/
int
hg_mem_shm_unmap(const char *name, void *mem_ptr, size_t size)
{
    int ret = HG_UTIL_SUCCESS;

#ifdef _WIN32
    if (mem_ptr)
        UnmapViewOfFile(mem_ptr);
//    if (fd)
//        CloseHandle(fd);
#else
    if (mem_ptr && mem_ptr != MAP_FAILED && munmap(mem_ptr, size) == -1) {
        HG_UTIL_LOG_ERROR("munmap() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }

    if (name && shm_unlink(name) == -1) {
        HG_UTIL_LOG_ERROR("shm_unlink() failed (%s)", strerror(errno));
        ret = HG_UTIL_FAIL;
        goto done;
    }
#endif

done:
    return ret;
}
