#ifndef _WIREUP_H_
#define _WIREUP_H_

#include <stdint.h> /* uint32_t, uint16_t, uint8_t */

typedef enum {
      OP_REQ        = 0
    , OP_ACK        = 1
    , OP_KEEPALIVE  = 2
} wireup_op_t;

typedef struct _wireup_msg {
    uint32_t sender_id;
    uint16_t op;        // wireup_op_t
    uint16_t addrlen;
    uint8_t addr[];
} wireup_msg_t;

const char *wireup_op_string(wireup_op_t);

#endif /* _WIREUP_H_ */
