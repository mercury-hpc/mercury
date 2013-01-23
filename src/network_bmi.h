/*
 * network_bmi.h
 *
 *  Created on: Nov 5, 2012
 *      Author: soumagne
 */

#ifndef NETWORK_BMI_H
#define NETWORK_BMI_H

#include "network_abstraction.h"

#include <bmi.h>

#define NA_BMI_MAX_IDLE_TIME (3600*1000)

#ifdef __cplusplus
extern "C" {
#endif

void na_bmi_init(const char *method_list, const char *listen_addr, int flags);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_BMI_H */
