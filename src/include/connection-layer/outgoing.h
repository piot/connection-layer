/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/connection-layer
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
#ifndef CONNECTION_LAYER_OUTGOING_H
#define CONNECTION_LAYER_OUTGOING_H

#include <stddef.h>
#include <stdint.h>

struct FldOutStream;

typedef struct {
    uint64_t remoteSecret;
    uint8_t remoteSecretAsArray[4];
} ConnectionLayerOutgoing;

void connectionLayerOutgoingInit(ConnectionLayerOutgoing* self, uint64_t secret);
int connectionLayerOutgoingWrite(ConnectionLayerOutgoing* self, struct FldOutStream* stream,
    const uint8_t* data, size_t octetLength);

#endif //CONNECTION_LAYER_OUTGOING_H
