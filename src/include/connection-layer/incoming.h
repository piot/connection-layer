/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/connection-layer
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
#ifndef CONNECTION_LAYER_INCOMING_H
#define CONNECTION_LAYER_INCOMING_H

#include <stdint.h>

struct FldInStream;

typedef struct {
    uint64_t remoteSecret;
    uint8_t remoteSecretAsArray[4];
} ConnectionLayerIncoming;

void connectionLayerIncomingInit(ConnectionLayerIncoming* self, uint64_t secret);
int connectionLayerIncomingVerify(ConnectionLayerIncoming* self, struct FldInStream* stream);

#endif //CONNECTION_LAYER_INCOMING_H
