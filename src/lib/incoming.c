/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/connection-layer
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
#include <clog/clog.h>
#include <connection-layer/incoming.h>
#include <flood/in_stream.h>
#include <mash/murmur.h>

void connectionLayerIncomingInit(ConnectionLayerIncoming* self, uint64_t secret)
{
    self->remoteSecret = secret;
    self->remoteSecretAsArray[0] = (secret >> 24) & 0xff;
    self->remoteSecretAsArray[1] = (secret >> 16) & 0xff;
    self->remoteSecretAsArray[2] = (secret >> 8) & 0xff;
    self->remoteSecretAsArray[3] = (secret) & 0xff;
}

int connectionLayerIncomingVerify(ConnectionLayerIncoming* self, FldInStream* stream)
{
    fldInStreamCheckMarker(stream, 0x8a);
    uint32_t expectedHashValue;
    int error = fldInStreamReadUInt32(stream, &expectedHashValue);
    if (error < 0) {
        return error;
    }

    uint32_t hashValue = mashMurmurHash3WithSeed(self->remoteSecretAsArray, 4, 0);
    hashValue = mashMurmurHash3WithSeed(stream->p, stream->size - stream->pos, hashValue);

    if (hashValue != expectedHashValue) {
        CLOG_NOTICE("hash not equal, discard packet %04X vs %04X", hashValue, expectedHashValue)
        return -1;
    }

    return 0;
}
