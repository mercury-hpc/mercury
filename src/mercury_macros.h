/*
 * Copyright (C) 2013 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#ifndef MERCURY_MACROS_H
#define MERCURY_MACROS_H

#include "mercury_config.h"
#include "mercury_error.h"

#ifdef MERCURY_HAS_BOOST
#include <boost/preprocessor.hpp>

#define GEN_GET_TYPE(field) BOOST_PP_SEQ_HEAD(field)
#define GEN_GET_NAME(field) BOOST_PP_SEQ_CAT(BOOST_PP_SEQ_TAIL(field))

#define GEN_STRUCT_FIELD(r, data, param) GEN_GET_TYPE(param) GEN_GET_NAME(param);

#define MERCURY_GEN_STRUCT(struct_type_name, fields) \
typedef struct \
{   \
    BOOST_PP_SEQ_FOR_EACH(GEN_STRUCT_FIELD, , fields) \
    \
} struct_type_name;

#define GEN_PROC(r, struct_name, field) \
    ret = BOOST_PP_CAT(hg_proc_, GEN_GET_TYPE(field)(proc, &struct_name->GEN_GET_NAME(field))); \
    if (ret != HG_SUCCESS) { \
      HG_ERROR_DEFAULT("Proc error"); \
      ret = HG_FAIL; \
      return ret; \
    }

#define MERCURY_GEN_STRUCT_PROC(struct_type_name, fields) \
static inline int BOOST_PP_CAT(hg_proc_, struct_type_name) \
    (hg_proc_t proc, void *data) \
{   \
    int ret = HG_SUCCESS; \
    struct_type_name *struct_data = (struct_type_name *) data; \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_PROC, struct_data, fields) \
    \
    return ret; \
}

#define MERCURY_GEN_PROC(struct_type_name, fields) \
        MERCURY_GEN_STRUCT(struct_type_name, fields) \
        MERCURY_GEN_STRUCT_PROC(struct_type_name, fields)

#define MERCURY_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        HG_Register(func_name, BOOST_PP_CAT(hg_proc_, in_struct_type_name), \
                BOOST_PP_CAT(hg_proc_, out_struct_type_name))

#define MERCURY_HANDLER_REGISTER(func_name, func_callback, in_struct_type_name, out_struct_type_name) \
        HG_Handler_register(func_name, func_callback, \
                BOOST_PP_CAT(hg_proc_, in_struct_type_name), \
                BOOST_PP_CAT(hg_proc_, out_struct_type_name))

#else /* MERCURY_HAS_BOOST */

#define MERCURY_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        HG_Register(func_name, hg_proc_ ## in_struct_type_name, \
                hg_proc_ ## out_struct_type_name)

#define MERCURY_HANDLER_REGISTER(func_name, func_callback, in_struct_type_name, out_struct_type_name) \
        HG_Handler_register(func_name, func_callback, \
                hg_proc_ ## in_struct_type_name, \
                hg_proc_ ## out_struct_type_name)

#endif /* MERCURY_HAS_BOOST */

#define MERCURY_HANDLER_REGISTER_CALLBACK(func_name, func_callback) \
        HG_Handler_register(func_name, func_callback, NULL, NULL)

#define MERCURY_REGISTER_FINALIZE() \
        HG_Register("MERCURY_REGISTER_FINALIZE", NULL, NULL)

#define MERCURY_HANDLER_REGISTER_FINALIZE(func_callback) \
        HG_Handler_register("MERCURY_REGISTER_FINALIZE", func_callback, NULL, NULL)

#endif /* MERCURY_MACROS_H */
