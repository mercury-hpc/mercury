#ifndef _TAG_H_
#define _TAG_H_

#include "bits.h"

/* Bits 63:62 indicate the message channel.  There are two unused
 * channels that wireup ignores as of this writing but reserves for
 * itself, an app channel that is for the use of the wireup-using
 * application, and a wireup channel reserved for carrying wireup
 * messages.
 */
#define TAG_CHNL_MASK       BITS(63, 62)

/* In a message on the wireup channel, bits 61:0 carry a sender ID. */
#define TAG_ID_MASK         BITS(61, 0)

#define CHANNEL_UNUSED0 0
#define CHANNEL_WIREUP  1
#define CHANNEL_APP     2
#define CHANNEL_UNUSED3 3

/* Definitions suitable for bitwise-OR'ing into a tag number. */
#define TAG_CHNL_UNUSED0    SHIFTIN(CHANNEL_UNUSED0, TAG_CHNL_MASK)
#define TAG_CHNL_WIREUP     SHIFTIN(CHANNEL_WIREUP, TAG_CHNL_MASK)
#define TAG_CHNL_APP        SHIFTIN(CHANNEL_APP, TAG_CHNL_MASK)
#define TAG_CHNL_UNUSED3    SHIFTIN(CHANNEL_UNUSED3, TAG_CHNL_MASK)

/* Extract the sender ID or the channel number from a tag number. */
#define TAG_GET_ID(_x)      SHIFTOUT(_x, TAG_ID_MASK)
#define TAG_GET_CHNL(_x)    SHIFTOUT(_x, TAG_CHNL_MASK)

#endif /* _TAG_H_ */
