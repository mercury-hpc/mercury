/*
 * generic_macros.h
 */

#ifndef GENERIC_MACROS_H
#define GENERIC_MACROS_H

#include "shipper_config.h"

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

/*****************************************************************************/

#define GEN_ENCODER(r, enc_struct_name, field) GEN_ENC_PROC(enc_struct_name, field)
#define GEN_ENC_PROC(enc_struct_name, field) BOOST_PP_CAT(fs_proc_enc_, \
        GEN_GET_TYPE(field)(enc_proc, &enc_struct_name->GEN_GET_NAME(field)));

#define GEN_DECODER(r, dec_struct_name, field) GEN_DEC_PROC(dec_struct_name, field)
#define GEN_DEC_PROC(dec_struct_name, field) BOOST_PP_CAT(fs_proc_dec_, \
        GEN_GET_TYPE(field)(dec_proc, &dec_struct_name->GEN_GET_NAME(field)));


#define IOFSL_SHIPPER_GEN_ENC_PROC(struct_type_name, fields) \
static inline int BOOST_PP_CAT(fs_proc_enc_, struct_type_name) \
    (fs_proc_t enc_proc, const struct_type_name *data) \
{   \
    int ret = S_SUCCESS; \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_ENCODER, data, fields) \
    \
    return ret; \
}

#define IOFSL_SHIPPER_GEN_DEC_PROC(struct_type_name, fields) \
static inline int BOOST_PP_CAT(fs_proc_dec_, struct_type_name) \
    (fs_proc_t dec_proc, struct_type_name *data) \
{   \
    int ret = S_SUCCESS; \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_DECODER, data, fields) \
    \
    return ret; \
}

#define IOFSL_SHIPPER_GEN_ENC(enc_func_name, enc_struct_type, enc_struct_name, func_params) \
static int enc_func_name (void *buf, size_t *buf_len, const void *struct_ptr) \
{   \
    int ret = S_SUCCESS; \
    const enc_struct_type *enc_struct_name = struct_ptr; \
    fs_proc_t enc_proc; \
    \
    /* TODO here for now but we want enc_proc to handle that */ \
    if (!buf || (*buf_len == 0)) { \
        *buf_len = sizeof(enc_struct_type); \
        ret = S_FAIL; \
        return ret; \
    } \
    \
    if (*buf_len < sizeof(enc_struct_type)) { \
        S_ERROR_DEFAULT("Buffer size too small for serializing parameter"); \
        ret = S_FAIL; \
        return ret; \
    } \
    \
    fs_proc_enc_create(&enc_proc, buf, *buf_len); \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_ENCODER, enc_struct_name, func_params) \
    \
    fs_proc_enc_free(enc_proc); \
    \
    return ret; \
}

#define IOFSL_SHIPPER_GEN_DEC(dec_func_name, dec_struct_type, dec_struct_name, func_params) \
static int dec_func_name (void *struct_ptr, const void *buf, size_t buf_len) \
{   \
    int ret = S_SUCCESS; \
    dec_struct_type *dec_struct_name = struct_ptr; \
    fs_proc_t dec_proc; \
    \
    if (buf_len < sizeof(dec_struct_type)) { \
        S_ERROR_DEFAULT("Buffer size too small for deserializing parameter"); \
        ret = S_FAIL; \
        return ret; \
    } \
    \
    fs_proc_dec_create(&dec_proc, buf, buf_len); \
    \
    BOOST_PP_SEQ_FOR_EACH(GEN_DECODER, dec_struct_name, func_params) \
    \
    fs_proc_enc_free(dec_proc); \
    \
    return ret; \
    \
}

#define GEN_ADD_RET(func_ret, func_name, func_params) \
    BOOST_PP_SEQ_INSERT(func_params, 0, (func_ret)(BOOST_PP_CAT(func_name, _ret)))

#define GEN_CLIENT(func_name, func_in, func_out) \
    IOFSL_SHIPPER_GEN_STRUCT(BOOST_PP_CAT(func_name, _in_t), func_in) \
    IOFSL_SHIPPER_GEN_STRUCT(BOOST_PP_CAT(func_name, _out_t), func_out) \
    IOFSL_SHIPPER_GEN_ENC(BOOST_PP_CAT(func_name, _enc), \
            BOOST_PP_CAT(func_name, _in_t), \
            BOOST_PP_CAT(func_name, _in_struct), func_in) \
    IOFSL_SHIPPER_GEN_DEC(BOOST_PP_CAT(func_name, _dec), \
            BOOST_PP_CAT(func_name, _out_t), \
            BOOST_PP_CAT(func_name, _out_struct), func_out)

#define GEN_SERVER(func_name, func_in, func_out) \
    IOFSL_SHIPPER_GEN_STRUCT(BOOST_PP_CAT(func_name, _in_t), func_in) \
    IOFSL_SHIPPER_GEN_STRUCT(BOOST_PP_CAT(func_name, _out_t), func_out) \
    IOFSL_SHIPPER_GEN_ENC(BOOST_PP_CAT(func_name, _enc), \
            BOOST_PP_CAT(func_name, _out_t), \
            BOOST_PP_CAT(func_name, _out_struct), func_out) \
    IOFSL_SHIPPER_GEN_DEC(BOOST_PP_CAT(func_name, _dec), \
            BOOST_PP_CAT(func_name, _in_t), \
            BOOST_PP_CAT(func_name, _in_struct), func_in)

#define IOFSL_SHIPPER_GEN_CLIENT(func_ret, func_name, func_in, func_out) \
    GEN_CLIENT(func_name, func_in, GEN_ADD_RET(func_ret, func_name, func_out))

#define IOFSL_SHIPPER_GEN_SERVER(func_ret, func_name, func_in, func_out) \
    GEN_SERVER(func_name, func_in, GEN_ADD_RET(func_ret, func_name, func_out))

#endif /* IOFSL_SHIPPER_HAS_BOOST */

#endif /* GENERIC_MACROS_H */
