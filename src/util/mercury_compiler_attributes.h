/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_COMPILER_ATTRIBUTES_H
#define MERCURY_COMPILER_ATTRIBUTES_H

/*************************************/
/* Public Type and Struct Definition */
/*************************************/

/*****************/
/* Public Macros */
/*****************/

/*
 * __has_attribute is supported on gcc >= 5, clang >= 2.9 and icc >= 17.
 * In the meantime, to support gcc < 5, we implement __has_attribute
 * by hand.
 */
#ifndef __has_attribute
#    define __has_attribute(x)                          __GCC4_has_attribute_##x
#    define __GCC4_has_attribute___visibility__         1
#    define __GCC4_has_attribute___warn_unused_result__ 1
#    define __GCC4_has_attribute___unused__             1
#    define __GCC4_has_attribute___aligned__            1
#    define __GCC4_has_attribute___format__             1
#    define __GCC4_has_attribute___fallthrough__        0
#endif

/* Visibility of symbols */
#if defined(_WIN32)
#    define HG_ATTR_ABI_IMPORT __declspec(dllimport)
#    define HG_ATTR_ABI_EXPORT __declspec(dllexport)
#    define HG_ATTR_ABI_HIDDEN
#elif __has_attribute(__visibility__)
#    define HG_ATTR_ABI_IMPORT __attribute__((__visibility__("default")))
#    define HG_ATTR_ABI_EXPORT __attribute__((__visibility__("default")))
#    define HG_ATTR_ABI_HIDDEN __attribute__((__visibility__("hidden")))
#else
#    define HG_ATTR_ABI_IMPORT
#    define HG_ATTR_ABI_EXPORT
#    define HG_ATTR_ABI_HIDDEN
#endif

/* Unused return values */
#if __has_attribute(__warn_unused_result__)
#    define HG_ATTR_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#    define HG_ATTR_WARN_UNUSED_RESULT
#endif

/* Remove warnings when plugin does not use callback arguments */
#if __has_attribute(__unused__)
#    define HG_ATTR_UNUSED __attribute__((__unused__))
#else
#    define HG_ATTR_UNUSED
#endif

/* Alignment */
#if __has_attribute(__aligned__)
#    define HG_ATTR_ALIGNED(x) __attribute__((__aligned__(x)))
#else
#    define HG_ATTR_ALIGNED(x)
#endif

/* Check format arguments */
#if __has_attribute(__format__)
#    define HG_ATTR_FORMAT(_func, _fmt, _firstarg)                             \
        __attribute__((__format__(_func, _fmt, _firstarg)))
#else
#    define HG_ATTR_FORMAT(_func, _fmt, _firstarg)
#endif

/* Constructor (not optional) */
#define HG_ATTR_CONSTRUCTOR             __attribute__((__constructor__))
#define HG_ATTR_CONSTRUCTOR_PRIORITY(x) __attribute__((__constructor__(x)))

/* Destructor (not optional) */
#define HG_ATTR_DESTRUCTOR __attribute__((__destructor__))

/* Fallthrough (prevent icc from throwing warnings) */
#if __has_attribute(__fallthrough__) && !defined(__INTEL_COMPILER)
#    define HG_ATTR_FALLTHROUGH __attribute__((__fallthrough__))
#else /* clang-format off */
#    define HG_ATTR_FALLTHROUGH do {} while (0) /* fallthrough */
#endif /* clang-format on */

#endif /* MERCURY_COMPILER_ATTRIBUTES_H */
