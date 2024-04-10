/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/connection-layer
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
#include <connection-layer/outgoing.h>
#include <flood/out_stream.h>
#include <mash/murmur.h>
#include <stddef.h>

void connectionLayerOutgoingInit(ConnectionLayerOutgoing* self, uint64_t secret)
{
    self->remoteSecret = secret;
    self->remoteSecretAsArray[0] = (secret >> 24) & 0xff;
    self->remoteSecretAsArray[1] = (secret >> 16) & 0xff;
    self->remoteSecretAsArray[2] = (secret >> 8) & 0xff;
    self->remoteSecretAsArray[3] = (secret) & 0xff;
}

int connectionLayerOutgoingWrite(
    ConnectionLayerOutgoing* self, FldOutStream* stream, const uint8_t* data, size_t octetLength)
{
    uint32_t calculatedHashValue = mashMurmurHash3WithSeed(self->remoteSecretAsArray, 4, 0);
    calculatedHashValue = mashMurmurHash3WithSeed(data, octetLength, calculatedHashValue);
    fldOutStreamWriteMarker(stream, 0x8a);

    int error = fldOutStreamWriteUInt32(stream, calculatedHashValue);
    if (error < 0) {
        return error;
    }

    return 0;
}
