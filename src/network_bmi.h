/*
 * network_bmi.h
 */

#ifndef NETWORK_BMI_H
#define NETWORK_BMI_H

#include "network_abstraction.h"

#include <bmi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the BMI plugin */
na_network_class_t *na_bmi_init(const char *method_list, const char *listen_addr, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_BMI_H */
