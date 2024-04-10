/*----------------------------------------------------------------------------------------------------------
 *  Copyright (c) Peter Bjorklund. All rights reserved. https://github.com/piot/connection-layer
 *  Licensed under the MIT License. See LICENSE in the project root for license information.
 *--------------------------------------------------------------------------------------------------------*/
#include "utest.h"
#include <clog/clog.h>
#include <connection-layer/incoming.h>
#include <connection-layer/outgoing.h>
#include <flood/in_stream.h>
#include <flood/out_stream.h>

UTEST(ConnectionLayer, incoming)
{
    uint8_t packet[] = { 0x42, 0x99, 0xfe, 0x41 };
    const uint32_t sharedSecret = 42;

    FldOutStream outStream;
    uint8_t buf[128];
    fldOutStreamInit(&outStream, buf, sizeof(buf));

    ConnectionLayerOutgoing outgoing;
    connectionLayerOutgoingInit(&outgoing, sharedSecret);
    connectionLayerOutgoingWrite(&outgoing, &outStream, packet, sizeof(packet));

    fldOutStreamWriteOctets(&outStream, packet, sizeof(packet));

    FldInStream inStream;

    fldInStreamInit(&inStream, outStream.octets, outStream.pos);

    ConnectionLayerIncoming incoming;
    connectionLayerIncomingInit(&incoming, sharedSecret);

    int error = connectionLayerIncomingVerify(&incoming, &inStream);
    ASSERT_EQ(error, 0);
}

UTEST(ConnectionLayer, tampered)
{
    uint8_t packet[] = { 0x10, 0x2e, 0xd7, 0x99 };
    const uint32_t sharedSecret = 42;

    FldOutStream outStream;
    uint8_t buf[128];
    fldOutStreamInit(&outStream, buf, sizeof(buf));

    ConnectionLayerOutgoing outgoing;
    connectionLayerOutgoingInit(&outgoing, sharedSecret);
    connectionLayerOutgoingWrite(&outgoing, &outStream, packet, sizeof(packet));

    fldOutStreamWriteOctets(&outStream, packet, sizeof(packet));

    FldInStream inStream;

    // Tamper with packet
    outStream.octets[7]++;
    fldInStreamInit(&inStream, outStream.octets, outStream.pos);

    ConnectionLayerIncoming incoming;
    connectionLayerIncomingInit(&incoming, sharedSecret);

    int error = connectionLayerIncomingVerify(&incoming, &inStream);
    ASSERT_EQ(error, -1);
}
