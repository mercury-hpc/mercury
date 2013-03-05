/*
 * generic_macros.h
 */

#ifndef GENERIC_MACROS_H
#define GENERIC_MACROS_H

#include "shipper_config.h"
#include "shipper_error.h"

#ifdef IOFSL_SHIPPER_HAS_BOOST
#include <boost/preprocessor.hpp>

#define GEN_GET_TYPE(field) BOOST_PP_SEQ_HEAD(field)
#define GEN_GET_NAME(field) BOOST_PP_SEQ_CAT(BOOST_PP_SEQ_TAIL(field))

#define GEN_STRUCT_FIELD(r, data, param) GEN_GET_TYPE(param) GEN_GET_NAME(param);

#define IOFSL_SHIPPER_GEN_STRUCT(struct_type_name, fields) \
typedef struct \
{   \
    BOOST_PP_SEQ_FOR_EACH(GEN_STRUCT_FIELD, , fields) \
    \
} struct_type_name;

#define GEN_PROC(r, struct_name, field) \
    ret = BOOST_PP_CAT(fs_proc_, GEN_GET_TYPE(field)(proc, &struct_name->GEN_GET_NAME(field))); \
    if (ret != S_SUCCESS) { \
      S_ERROR_DEFAULT("Proc error"); \
      ret = S_FAIL; \
      return ret; \
    }

#define IOFSL_SHIPPER_GEN_STRUCT_PROC(struct_type_name, fields) \
static inline int BOOST_PP_CAT(fs_proc_, struct_type_name) \
    (fs_proc_t proc, void *data) \
{   \
    int ret = S_SUCCESS; \
    struct_type_name *struct_data = (struct_type_name *) data; \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_PROC, struct_data, fields) \
    \
    return ret; \
}

#define IOFSL_SHIPPER_GEN_PROC(struct_type_name, fields) \
        IOFSL_SHIPPER_GEN_STRUCT(struct_type_name, fields) \
        IOFSL_SHIPPER_GEN_STRUCT_PROC(struct_type_name, fields)

#define IOFSL_SHIPPER_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        fs_register(#func_name, BOOST_PP_CAT(fs_proc_, in_struct_type_name), \
                BOOST_PP_CAT(fs_proc_, out_struct_type_name))

#define IOFSL_SHIPPER_HANDLER_REGISTER(func_name, fs_func_name, in_struct_type_name, out_struct_type_name) \
        fs_handler_register(#func_name, fs_func_name, BOOST_PP_CAT(fs_proc_, in_struct_type_name), \
                BOOST_PP_CAT(fs_proc_, out_struct_type_name))

#else /* IOFSL_SHIPPER_HAS_BOOST */

#define IOFSL_SHIPPER_REGISTER(func_name, in_struct_type_name, out_struct_type_name) \
        fs_register(#func_name, fs_proc_ ## in_struct_type_name, \
                fs_proc_ ## out_struct_type_name)

#define IOFSL_SHIPPER_HANDLER_REGISTER(func_name, fs_func_name, in_struct_type_name, out_struct_type_name) \
        fs_handler_register(#func_name, fs_func_name, fs_proc_ ## in_struct_type_name, \
                fs_proc_ ## out_struct_type_name)

#endif /* IOFSL_SHIPPER_HAS_BOOST */

#endif /* GENERIC_MACROS_H */
