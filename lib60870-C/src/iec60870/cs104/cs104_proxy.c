/*
 *  Copyright 2016-2019 MZ Automation GmbH
 *
 *  This file is part of lib60870-C
 *
 *  lib60870-C is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  lib60870-C is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with lib60870-C.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  See COPYING file for the complete license text.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer_frame.h"
#include "cs104_frame.h"
#include "cs104_proxy.h"
#include "frame.h"
#include "hal_socket.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "lib_memory.h"
#include "linked_list.h"

#include "iec60870_slave.h"
#include "lib60870_config.h"
#include "lib60870_internal.h"

#include "apl_types_internal.h"
#include "cs101_asdu_internal.h"

static struct sCS104_APCIParameters defaultConnectionParameters = {
    /* .k = */ 12,
    /* .w = */ 8,
    /* .t0 = */ 10,
    /* .t1 = */ 15,
    /* .t2 = */ 10,
    /* .t3 = */ 20};

static struct sCS101_AppLayerParameters defaultAppLayerParameters = {
    /* .sizeOfTypeId =  */ 1,
    /* .sizeOfVSQ = */ 1,
    /* .sizeOfCOT = */ 2,
    /* .originatorAddress = */ 0,
    /* .sizeOfCA = */ 2,
    /* .sizeOfIOA = */ 3,
    /* .maxSizeOfASDU = */ 249};

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif

typedef struct {
    uint8_t msg[256];
    int msgSize;
} FrameBuffer;

typedef struct {
  uint64_t sentTime; /* required for T1 timeout */
  int seqNo;
} SentASDUProxy;

/***************************************************
 * Proxy
 ***************************************************/

struct sCS104_Proxy {
  char hostname[HOST_NAME_MAX + 1];
  int tcpPort;

  struct sIMasterConnection iMasterConnection;
  
  struct sCS104_APCIParameters conParameters;
  struct sCS101_AppLayerParameters alParameters;

  uint8_t recvBuffer[260];
  int recvBufPos;

  uint8_t sendBuffer[260];

  int connectTimeoutInMs;

  bool waitingForTestFRcon;

  SentASDUProxy *sentASDUs; /* the k-buffer */
  uint16_t maxSentASDUs;    /* k-parameter */
  int16_t oldestSentASDU;   /* oldest sent ASDU in k-buffer */
  int16_t newestSentASDU;   /* newest sent ASDU in k-buffer */
  uint16_t sendCount;    /* sent messages - sequence counter */
  uint16_t receiveCount; /* received messages - sequence counter */

  int unconfirmedReceivedIMessages; /* number of unconfirmed messages received
                                     */
                                    /* timeout T2 handling */
  bool timeoutT2Triggered;
  uint64_t lastConfirmationTime; /* timestamp when the last confirmation message
                                    (for I messages) was sent */

  uint64_t nextT3Timeout;
  uint64_t nextTestFRConTimeout; /* timeout T1 when waiting for TEST FR con */

  Socket socket;
  bool running;
  bool failure;
  bool close;

#if (CONFIG_USE_SEMAPHORES == 1)
  Semaphore sentASDUsLock;
#endif

#if (CONFIG_USE_THREADS == 1)
  Thread connectionHandlingThread;
#endif

#if (CONFIG_CS104_SUPPORT_TLS == 1)
  TLSConfiguration tlsConfig;
  TLSSocket tlsSocket;
#endif

  CS101_InterrogationHandler interrogationHandler;
  void *interrogationHandlerParameter;

  CS101_CounterInterrogationHandler counterInterrogationHandler;
  void *counterInterrogationHandlerParameter;

  CS101_ReadHandler readHandler;
  void *readHandlerParameter;

  CS101_ClockSynchronizationHandler clockSyncHandler;
  void *clockSyncHandlerParameter;

  CS101_ResetProcessHandler resetProcessHandler;
  void *resetProcessHandlerParameter;

  CS101_DelayAcquisitionHandler delayAcquisitionHandler;
  void *delayAcquisitionHandlerParameter;

  CS101_ASDUHandler asduHandler;
  void *asduHandlerParameter;

  IEC60870_RawMessageHandler rawMessageHandler;
  void *rawMessageHandlerParameter;
};

static uint8_t STARTDT_CON_MSG[] = { 0x68, 0x04, 0x0b, 0x00, 0x00, 0x00 };

#define STARTDT_CON_MSG_SIZE 6

static uint8_t STOPDT_CON_MSG[] = { 0x68, 0x04, 0x23, 0x00, 0x00, 0x00 };

#define STOPDT_CON_MSG_SIZE 6

static uint8_t TESTFR_CON_MSG[] = { 0x68, 0x04, 0x83, 0x00, 0x00, 0x00 };

#define TESTFR_CON_MSG_SIZE 6

static uint8_t TESTFR_ACT_MSG[] = { 0x68, 0x04, 0x43, 0x00, 0x00, 0x00 };

#define TESTFR_ACT_MSG_SIZE 6

void
CS104_Proxy_setInterrogationHandler(CS104_Proxy self, CS101_InterrogationHandler handler, void*  parameter)
{
    self->interrogationHandler = handler;
    self->interrogationHandlerParameter = parameter;
}

void
CS104_Proxy_setCounterInterrogationHandler(CS104_Proxy self, CS101_CounterInterrogationHandler handler, void*  parameter)
{
    self->counterInterrogationHandler = handler;
    self->counterInterrogationHandlerParameter = parameter;
}

void
CS104_Proxy_setReadHandler(CS104_Proxy self, CS101_ReadHandler handler, void* parameter)
{
    self->readHandler = handler;
    self->readHandlerParameter = parameter;
}

void
CS104_Proxy_setASDUHandler(CS104_Proxy self, CS101_ASDUHandler handler, void* parameter)
{
    self->asduHandler = handler;
    self->asduHandlerParameter = parameter;
}

void
CS104_Proxy_setClockSyncHandler(CS104_Proxy self, CS101_ClockSynchronizationHandler handler, void* parameter)
{
    self->clockSyncHandler = handler;
    self->clockSyncHandlerParameter = parameter;
}

void
CS104_Proxy_setRawMessageHandler(CS104_Proxy self, IEC60870_RawMessageHandler handler, void* parameter)
{
    self->rawMessageHandler = handler;
    self->rawMessageHandlerParameter = parameter;
}

CS104_APCIParameters
CS104_Proxy_getConnectionParameters(CS104_Proxy self)
{
    return &(self->conParameters);
}

CS101_AppLayerParameters
CS104_Proxy_getAppLayerParameters(CS104_Proxy self)
{
    return &(self->alParameters);
}

void
CS104_Proxy_setConnectTimeout(CS104_Proxy self, int millies)
{
  self->connectTimeoutInMs = millies;
}

void
CS104_Proxy_setAPCIParameters(CS104_Proxy self, CS104_APCIParameters parameters)
{
  self->conParameters = *parameters;
  self->connectTimeoutInMs = self->conParameters.t0 * 1000;
}

void
CS104_Proxy_setAppLayerParameters(CS104_Proxy self, CS101_AppLayerParameters parameters)
{
  self->alParameters = *parameters;
}

/********************************************************
 * MasterConnection
 *********************************************************/
static void
printSendBuffer(CS104_Proxy self)
{
    if (self->oldestSentASDU != -1) {
        int currentIndex = self->oldestSentASDU;

        int nextIndex = 0;

        DEBUG_PRINT ("CS104 SLAVE: ------k-buffer------\n");

        do {
            DEBUG_PRINT("CS104 SLAVE: %02i : SeqNo=%i time=%llu : queueEntry=%p\n", currentIndex,
                    self->sentASDUs[currentIndex].seqNo,
                    self->sentASDUs[currentIndex].sentTime,
                    self->sentASDUs[currentIndex].queueEntry);

            if (currentIndex == self->newestSentASDU)
                nextIndex = -1;
            else
                currentIndex = (currentIndex + 1) % self->maxSentASDUs;

        } while (nextIndex != -1);

        DEBUG_PRINT ("CS104 SLAVE: --------------------\n");
    }
    else
        DEBUG_PRINT("CS104 SLAVE: k-buffer is empty\n");
}

/**
 * \return number of bytes read, or -1 in case of an error
 */
static int
readFromSocket(CS104_Proxy self, uint8_t* buffer, int size)
{
#if (CONFIG_CS104_SUPPORT_TLS == 1)
    if (self->tlsSocket != NULL)
        return TLSSocket_read(self->tlsSocket, buffer, size);
    else
        return Socket_read(self->socket, buffer, size);
#else
    return Socket_read(self->socket, buffer, size);
#endif
}

/**
 * \brief Read message part into receive buffer
 *
 * \return -1 in case of an error, 0 when no complete message can be read, > 0 when a complete message is in buffer
 */
static int
receiveMessage(CS104_Proxy self)
{
    uint8_t* buffer = self->recvBuffer;
    int bufPos = self->recvBufPos;

    /* read start byte */
    if (bufPos == 0) {
        int readFirst = readFromSocket(self, buffer, 1);

        if (readFirst < 1)
            return readFirst;

        if (buffer[0] != 0x68)
            return -1; /* message error */

        bufPos++;
    }

    /* read length byte */
    if (bufPos == 1)  {
        if (readFromSocket(self, buffer + 1, 1) != 1) {
            self->recvBufPos = 0;
            return -1;
        }

        bufPos++;
    }

    /* read remaining frame */
    if (bufPos > 1) {
        int length = buffer[1];

        int remainingLength = length - bufPos + 2;

        int readCnt = readFromSocket(self, buffer + bufPos, remainingLength);

        if (readCnt == remainingLength) {
            self->recvBufPos = 0;
            return length + 2;
        }
        else if (readCnt == -1) {
            self->recvBufPos = 0;
            return -1;
        }
        else {
            self->recvBufPos = bufPos + readCnt;
            return 0;
        }
    }

    self->recvBufPos = bufPos;
    return 0;
}

static int
writeToSocket(CS104_Proxy self, uint8_t* buf, int size)
{
    if (self->rawMessageHandler)
        self->rawMessageHandler(self->rawMessageHandlerParameter, buf, size, true);

#if (CONFIG_CS104_SUPPORT_TLS == 1)
    if (self->tlsSocket)
        return TLSSocket_write(self->tlsSocket, buf, size);
    else
        return Socket_write(self->socket, buf, size);
#else
    return Socket_write(self->socket, buf, size);
#endif
}

static int
sendIMessage(CS104_Proxy self, uint8_t* buffer, int msgSize)
{
    buffer[0] = (uint8_t) 0x68;
    buffer[1] = (uint8_t) (msgSize - 2);

    buffer[2] = (uint8_t) ((self->sendCount % 128) * 2);
    buffer[3] = (uint8_t) (self->sendCount / 128);

    buffer[4] = (uint8_t) ((self->receiveCount % 128) * 2);
    buffer[5] = (uint8_t) (self->receiveCount / 128);

    if (writeToSocket(self, buffer, msgSize) > 0) {
        DEBUG_PRINT("CS104 SLAVE: SEND I (size = %i) N(S) = %i N(R) = %i\n", msgSize, self->sendCount, self->receiveCount);
        self->sendCount = (self->sendCount + 1) % 32768;
        self->unconfirmedReceivedIMessages = 0;
        self->timeoutT2Triggered = false;
    }

    self->unconfirmedReceivedIMessages = 0;

    return self->sendCount;
}

static bool
isSentBufferFull(CS104_Proxy self)
{
    /* locking of k-buffer has to be done by caller! */
    if (self->oldestSentASDU == -1)
        return false;

    int newIndex = (self->newestSentASDU + 1) % (self->maxSentASDUs);

    if (newIndex == self->oldestSentASDU)
        return true;
    else
        return false;
}


static void
sendASDU(CS104_Proxy self, uint8_t* buffer, int msgSize)
{
    int currentIndex = 0;

    if (self->oldestSentASDU == -1) {
        self->oldestSentASDU = 0;
        self->newestSentASDU = 0;
    }
    else {
        currentIndex = (self->newestSentASDU + 1) % self->maxSentASDUs;
    }

    self->sentASDUs[currentIndex].seqNo = sendIMessage(self, buffer, msgSize);
    self->sentASDUs[currentIndex].sentTime = Hal_getTimeInMs();

    self->newestSentASDU = currentIndex;

    printSendBuffer(self);
}


static bool
sendASDUInternal(CS104_Proxy self, CS101_ASDU asdu)
{
    bool asduSent = false;

#if (CONFIG_USE_SEMAPHORES == 1)
        Semaphore_wait(self->sentASDUsLock);
#endif

    if (isSentBufferFull(self) == false) {

        FrameBuffer frameBuffer;

        struct sBufferFrame bufferFrame;

        Frame frame = BufferFrame_initialize(&bufferFrame, frameBuffer.msg, IEC60870_5_104_APCI_LENGTH);
        CS101_ASDU_encode(asdu, frame);

        frameBuffer.msgSize = Frame_getMsgSize(frame);

        sendASDU(self, frameBuffer.msg, frameBuffer.msgSize);

        asduSent = true;
    }

#if (CONFIG_USE_SEMAPHORES == 1)
        Semaphore_post(self->sentASDUsLock);
#endif

    if (asduSent == false)
        DEBUG_PRINT("CS104 SLAVE: unable to send response (isActive=%i)\n", self->isActive);

    return asduSent;
}


static void
responseCOTUnknown(CS101_ASDU asdu, CS104_Proxy self)
{
    DEBUG_PRINT("CS104 SLAVE:   with unknown COT\n");
    CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
    CS101_ASDU_setNegative(asdu, true);
    sendASDUInternal(self, asdu);
}

/*
 * Handle received ASDUs
 *
 * Call the appropriate callbacks according to ASDU type and CoT
 *
 * \return true when ASDU is valid, false otherwise (e.g. corrupted message data)
 */
static bool
handleASDU(CS104_Proxy self, CS101_ASDU asdu)
{
    bool messageHandled = false;

    CS104_Proxy slave = self;

    uint8_t cot = CS101_ASDU_getCOT(asdu);

    switch (CS101_ASDU_getTypeID(asdu)) {

    case C_IC_NA_1: /* 100 - interrogation command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd interrogation command C_IC_NA_1\n");

        if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_DEACTIVATION)) {
            if (slave->interrogationHandler != NULL) {

                union uInformationObject _io;

                InterrogationCommand irc = (InterrogationCommand) CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (irc) {
                    if (slave->interrogationHandler(slave->interrogationHandlerParameter,
                            &(self->iMasterConnection), asdu, InterrogationCommand_getQOI(irc)))
                        messageHandled = true;
                }
                else
                    return false;

            }
        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_CI_NA_1: /* 101 - counter interrogation command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd counter interrogation command C_CI_NA_1\n");

        if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_DEACTIVATION)) {

            if (slave->counterInterrogationHandler != NULL) {

                union uInformationObject _io;

                CounterInterrogationCommand cic = (CounterInterrogationCommand)  CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (cic) {
                    if (slave->counterInterrogationHandler(slave->counterInterrogationHandlerParameter,
                            &(self->iMasterConnection), asdu, CounterInterrogationCommand_getQCC(cic)))
                        messageHandled = true;
                }
                else
                    return false;
            }
        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_RD_NA_1: /* 102 - read command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd read command C_RD_NA_1\n");

        if (cot == CS101_COT_REQUEST) {
            if (slave->readHandler != NULL) {

                union uInformationObject _io;

                ReadCommand rc = (ReadCommand) CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (rc) {
                    if (slave->readHandler(slave->readHandlerParameter,
                            &(self->iMasterConnection), asdu, InformationObject_getObjectAddress((InformationObject) rc)))
                        messageHandled = true;
                }
                else
                    return false;
            }
        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_CS_NA_1: /* 103 - Clock synchronization command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd clock sync command C_CS_NA_1\n");

        if (cot == CS101_COT_ACTIVATION) {

            if (slave->clockSyncHandler != NULL) {

                union uInformationObject _io;

                ClockSynchronizationCommand csc = (ClockSynchronizationCommand) CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (csc) {
                    CP56Time2a newTime = ClockSynchronizationCommand_getTime(csc);

                    if (slave->clockSyncHandler(slave->clockSyncHandlerParameter,
                            &(self->iMasterConnection), asdu, newTime)) {

                        CS101_ASDU_removeAllElements(asdu);

                        ClockSynchronizationCommand_create(csc, 0, newTime);

                        CS101_ASDU_addInformationObject(asdu, (InformationObject) csc);

                        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

                        sendASDUInternal(self, asdu);
                    }
                    else {
                        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
                        CS101_ASDU_setNegative(asdu, true);

                        sendASDUInternal(self, asdu);
                    }

                    messageHandled = true;
                }
                else
                    return false;
            }
        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_TS_NA_1: /* 104 - test command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd test command C_TS_NA_1\n");

        if (cot != CS101_COT_ACTIVATION) {
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
            CS101_ASDU_setNegative(asdu, true);
        }
        else
            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

        sendASDUInternal(self, asdu);

        messageHandled = true;

        break;

    case C_RP_NA_1: /* 105 - Reset process command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd reset process command C_RP_NA_1\n");

        if (cot == CS101_COT_ACTIVATION) {

            if (slave->resetProcessHandler != NULL) {

                union uInformationObject _io;

                ResetProcessCommand rpc = (ResetProcessCommand) CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (rpc) {
                    if (slave->resetProcessHandler(slave->resetProcessHandlerParameter,
                            &(self->iMasterConnection), asdu, ResetProcessCommand_getQRP(rpc)))
                        messageHandled = true;
                }
                else
                    return false;
            }

        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_CD_NA_1: /* 106 - Delay acquisition command */

        DEBUG_PRINT("CS104 SLAVE: Rcvd delay acquisition command C_CD_NA_1\n");

        if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_SPONTANEOUS)) {

            if (slave->delayAcquisitionHandler != NULL) {

                union uInformationObject _io;

                DelayAcquisitionCommand dac = (DelayAcquisitionCommand) CS101_ASDU_getElementEx(asdu, (InformationObject) &_io, 0);

                if (dac) {
                    if (slave->delayAcquisitionHandler(slave->delayAcquisitionHandlerParameter,
                            &(self->iMasterConnection), asdu, DelayAcquisitionCommand_getDelay(dac)))
                        messageHandled = true;
                }
                else
                    return false;

            }
        }
        else
            responseCOTUnknown(asdu, self);

        break;

    case C_TS_TA_1: /* 107 - test command with timestamp */

        DEBUG_PRINT("CS104 SLAVE: Rcvd test command with CP56Time2a C_TS_TA_1\n");

        if (cot != CS101_COT_ACTIVATION) {
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
            CS101_ASDU_setNegative(asdu, true);
        }
        else
            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

        sendASDUInternal(self, asdu);

        messageHandled = true;

        break;


    default: /* no special handler available -> use default handler */
        break;
    }

    if ((messageHandled == false) && (slave->asduHandler != NULL))
        if (slave->asduHandler(slave->asduHandlerParameter, &(self->iMasterConnection), asdu))
            messageHandled = true;

    if (messageHandled == false) {
        /* send error response */
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_TYPE_ID);
        CS101_ASDU_setNegative(asdu, true);
        sendASDUInternal(self, asdu);
    }

    return true;
}

static bool
checkSequenceNumber(CS104_Proxy self, int seqNo)
{
#if (CONFIG_USE_SEMAPHORES == 1)
    Semaphore_wait(self->sentASDUsLock);
#endif

    /* check if received sequence number is valid */

    bool seqNoIsValid = false;
    bool counterOverflowDetected = false;
    int oldestValidSeqNo = -1;

    if (self->oldestSentASDU == -1) { /* if k-Buffer is empty */
        if (seqNo == self->sendCount)
            seqNoIsValid = true;
    }
    else {
        /* two cases are required to reflect sequence number overflow */
        int oldestAsduSeqNo = self->sentASDUs[self->oldestSentASDU].seqNo;
        int newestAsduSeqNo = self->sentASDUs[self->newestSentASDU].seqNo;

        if (oldestAsduSeqNo <= newestAsduSeqNo) {
            if ((seqNo >= oldestAsduSeqNo) && (seqNo <= newestAsduSeqNo))
                seqNoIsValid = true;
        }
        else {
            if ((seqNo >= oldestAsduSeqNo) || (seqNo <= newestAsduSeqNo))
                seqNoIsValid = true;

            counterOverflowDetected = true;
        }

        /* check if confirmed message was already removed from list */
        if (oldestAsduSeqNo == 0)
            oldestValidSeqNo = 32767;
        else
            oldestValidSeqNo = (oldestAsduSeqNo - 1) % 32768;

        if (oldestValidSeqNo == seqNo)
            seqNoIsValid = true;
    }

    if (seqNoIsValid) {
        if (self->oldestSentASDU != -1) {

            do {
                int oldestAsduSeqNo = self->sentASDUs[self->oldestSentASDU].seqNo;

                if (counterOverflowDetected == false) {
                    if (seqNo < oldestAsduSeqNo)
                        break;
                }

                if (seqNo == oldestValidSeqNo)
                    break;

                if (oldestAsduSeqNo == seqNo) {
                    /* we arrived at the seq# that has been confirmed */

                    if (self->oldestSentASDU == self->newestSentASDU)
                        self->oldestSentASDU = -1;
                    else
                        self->oldestSentASDU = (self->oldestSentASDU + 1) % self->maxSentASDUs;

                    break;
                }

                self->oldestSentASDU = (self->oldestSentASDU + 1) % self->maxSentASDUs;

                int checkIndex = (self->newestSentASDU + 1) % self->maxSentASDUs;

                if (self->oldestSentASDU == checkIndex) {
                    self->oldestSentASDU = -1;
                    break;
                }

            } while (true);
        }
    }
    else
        DEBUG_PRINT("CS104 SLAVE: Received sequence number out of range");


#if (CONFIG_USE_SEMAPHORES == 1)
    Semaphore_post(self->sentASDUsLock);
#endif

    return seqNoIsValid;
}

static void
resetT3Timeout(CS104_Proxy self, uint64_t currentTime)
{
    self->nextT3Timeout = currentTime + (uint64_t) (self->conParameters.t3 * 1000);
}

static bool
checkT3Timeout(CS104_Proxy self, uint64_t currentTime)
{
    if (self->waitingForTestFRcon)
        return false;

    if (self->nextT3Timeout > (currentTime + (uint64_t) (self->conParameters.t3 * 1000))) {
        /* timeout value not plausible (maybe system time changed) */
        resetT3Timeout(self, currentTime);
    }

    if (currentTime > self->nextT3Timeout)
        return true;
    else
        return false;
}

static void
resetTestFRConTimeout(CS104_Proxy self, uint64_t currentTime)
{
    self->nextTestFRConTimeout = currentTime + (uint64_t) (self->conParameters.t1 * 1000);
}

static bool
checkTestFRConTimeout(CS104_Proxy self, uint64_t currentTime)
{
    if (self->nextTestFRConTimeout > (currentTime + (uint64_t) (self->conParameters.t1 * 1000))) {
        /* timeout value not plausible (maybe system time changed) */
        resetTestFRConTimeout(self, currentTime);
    }

    if (currentTime > self->nextTestFRConTimeout)
        return true;
    else
        return false;
}

static void
sendSMessage(CS104_Proxy self)
{
    uint8_t msg[6];

    msg[0] = 0x68;
    msg[1] = 0x04;
    msg[2] = 0x01;
    msg[3] = 0;
    msg[4] = (uint8_t) ((self->receiveCount % 128) * 2);
    msg[5] = (uint8_t) (self->receiveCount / 128);

    if (writeToSocket(self, msg, 6) < 0) {

    }
}

static bool
handleMessage(CS104_Proxy self, uint8_t* buffer, int msgSize)
{
    uint64_t currentTime = Hal_getTimeInMs();

    if (msgSize >= 3) {

        if (buffer[0] != 0x68) {
            DEBUG_PRINT("CS104 SLAVE: Invalid START character!");
            return false;
        }

        uint8_t lengthOfApdu = buffer[1];

        if (lengthOfApdu != msgSize - 2) {
            DEBUG_PRINT("CS104 SLAVE: Invalid length of APDU");
            return false;
        }

        if ((buffer[2] & 1) == 0) { /* I message */

            if (msgSize < 7) {
                DEBUG_PRINT("CS104 SLAVE: Received I msg too small!");
                return false;
            }

            if (self->timeoutT2Triggered == false) {
                self->timeoutT2Triggered = true;
                self->lastConfirmationTime = currentTime; /* start timeout T2 */
            }

            int frameSendSequenceNumber = ((buffer [3] * 0x100) + (buffer [2] & 0xfe)) / 2;
            int frameRecvSequenceNumber = ((buffer [5] * 0x100) + (buffer [4] & 0xfe)) / 2;

            DEBUG_PRINT("CS104 SLAVE: Received I frame: N(S) = %i N(R) = %i\n", frameSendSequenceNumber, frameRecvSequenceNumber);

            if (frameSendSequenceNumber != self->receiveCount) {
                DEBUG_PRINT("CS104 SLAVE: Sequence error - close connection");
                return false;
            }

            if (checkSequenceNumber (self, frameRecvSequenceNumber) == false) {
                DEBUG_PRINT("CS104 SLAVE: Sequence number check failed - close connection");
                return false;
            }

            self->receiveCount = (self->receiveCount + 1) % 32768;
            self->unconfirmedReceivedIMessages++;


            CS101_ASDU asdu = CS101_ASDU_createFromBuffer(&(self->alParameters), buffer + 6, msgSize - 6);

            if (asdu) {
                bool validAsdu = handleASDU(self, asdu);

                CS101_ASDU_destroy(asdu);

                if (validAsdu == false) {
                    DEBUG_PRINT("CS104 SLAVE: ASDU corrupted");
                    return false;
                }
            }
            else {
                DEBUG_PRINT("CS104 SLAVE: Invalid ASDU");
                return false;
            }
        }

        /* Check for TESTFR_ACT message */
        else if ((buffer[2] & 0x43) == 0x43) {
            DEBUG_PRINT("CS104 SLAVE: Send TESTFR_CON\n");

            if (writeToSocket(self, TESTFR_CON_MSG, TESTFR_CON_MSG_SIZE) < 0)
                return false;
        }

        /* Check for STARTDT_ACT message */
        else if ((buffer [2] & 0x07) == 0x07) {
            DEBUG_PRINT("CS104 SLAVE: Send STARTDT_CON\n");

            if (writeToSocket(self, STARTDT_CON_MSG, STARTDT_CON_MSG_SIZE) < 0)
                return false;
        }

        /* Check for STOPDT_ACT message */
        else if ((buffer [2] & 0x13) == 0x13) {
            /* Send S-Message to confirm all outstanding messages */
            self->lastConfirmationTime = Hal_getTimeInMs();

            self->unconfirmedReceivedIMessages = 0;

            self->timeoutT2Triggered = false;

            sendSMessage(self);

            DEBUG_PRINT("CS104 SLAVE: Send STOPDT_CON\n");

            if (writeToSocket(self, STOPDT_CON_MSG, STOPDT_CON_MSG_SIZE) < 0)
                return false;
        }

        /* Check for TESTFR_CON message */
        else if ((buffer[2] & 0x83) == 0x83) {
            DEBUG_PRINT("CS104 SLAVE: Recv TESTFR_CON\n");

            self->waitingForTestFRcon = false;

            resetT3Timeout(self, currentTime); /* not required here -> is done below! */
        }

        else if (buffer [2] == 0x01) { /* S-message */
            int seqNo = (buffer[4] + buffer[5] * 0x100) / 2;

            DEBUG_PRINT("CS104 SLAVE: Rcvd S(%i) (own sendcounter = %i)\n", seqNo, self->sendCount);

            if (checkSequenceNumber(self, seqNo) == false)
                return false;
        }

        else {
            DEBUG_PRINT("CS104 SLAVE: unknown message - IGNORE\n");
            return true;
        }

        resetT3Timeout(self, currentTime);

        return true;
    }
    else {
        DEBUG_PRINT("CS104 SLAVE: Invalid message (too small)");
        return false;
    }
}

/********************************************
 * IMasterConnection
 *******************************************/

static bool
_IMasterConnection_isReady(IMasterConnection self)
{
    CS104_Proxy con = (CS104_Proxy) self->object;

    if (isSentBufferFull(con) == false)
      return true;
    else
      return false;
}

static bool
_IMasterConnection_sendASDU(IMasterConnection self, CS101_ASDU asdu)
{
    CS104_Proxy con = (CS104_Proxy) self->object;

    return sendASDUInternal(con, asdu);
}

static bool
_IMasterConnection_sendACT_CON(IMasterConnection self, CS101_ASDU asdu, bool negative)
{
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
    CS101_ASDU_setNegative(asdu, negative);

    return _IMasterConnection_sendASDU(self, asdu);
}

static bool
_IMasterConnection_sendACT_TERM(IMasterConnection self, CS101_ASDU asdu)
{
    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_TERMINATION);
    CS101_ASDU_setNegative(asdu, false);

    return _IMasterConnection_sendASDU(self, asdu);
}

static void
_IMasterConnection_close(IMasterConnection self)
{
    CS104_Proxy con = (CS104_Proxy) self->object;

    CS104_Proxy_close(con);
}

static int
_IMasterConnection_getPeerAddress(IMasterConnection self, char* addrBuf, int addrBufSize)
{
    CS104_Proxy con = (CS104_Proxy) self->object;

    char buf[50];

    char* addrStr = Socket_getPeerAddressStatic(con->socket, buf);

    if (addrStr == NULL)
        return 0;

    int len = (int) strlen(buf);

    if (len < addrBufSize) {
        strcpy(addrBuf, buf);
        return len;
    }
    else
        return 0;
}

static CS101_AppLayerParameters
_IMasterConnection_getApplicationLayerParameters(IMasterConnection self)
{
    CS104_Proxy con = (CS104_Proxy) self->object;

    return &(con->alParameters);
}

/********************************************
 * END IMasterConnection
 *******************************************/
static CS104_Proxy
createProxy(const char *hostname, int tcpPort)
{
  CS104_Proxy self = (CS104_Proxy)GLOBAL_MALLOC(sizeof(struct sCS104_Proxy));

  if (self != NULL) {
    strncpy(self->hostname, hostname, HOST_NAME_MAX);
    self->tcpPort = tcpPort;

    self->conParameters = defaultConnectionParameters;
    self->alParameters = defaultAppLayerParameters;

    self->asduHandler = NULL;
    self->interrogationHandler = NULL;
    self->counterInterrogationHandler = NULL;
    self->readHandler = NULL;
    self->clockSyncHandler = NULL;
    self->resetProcessHandler = NULL;
    self->delayAcquisitionHandler = NULL;
    self->rawMessageHandler = NULL;

#if (CONFIG_USE_SEMAPHORES == 1)
    self->sentASDUsLock = Semaphore_create(1);
#endif

#if (CONFIG_USE_THREADS == 1)
    self->connectionHandlingThread = NULL;
#endif

#if (CONFIG_CS104_SUPPORT_TLS == 1)
    self->tlsConfig = NULL;
    self->tlsSocket = NULL;
#endif

    self->maxSentASDUs = self->conParameters.k;
    self->sentASDUs = (SentASDUProxy*) GLOBAL_CALLOC(self->maxSentASDUs, sizeof(SentASDUProxy));;

    self->iMasterConnection.object = self;
    self->iMasterConnection.getApplicationLayerParameters = _IMasterConnection_getApplicationLayerParameters;
    self->iMasterConnection.isReady = _IMasterConnection_isReady;
    self->iMasterConnection.sendASDU = _IMasterConnection_sendASDU;
    self->iMasterConnection.sendACT_CON = _IMasterConnection_sendACT_CON;
    self->iMasterConnection.sendACT_TERM = _IMasterConnection_sendACT_TERM;
    self->iMasterConnection.close = _IMasterConnection_close;
    self->iMasterConnection.getPeerAddress = _IMasterConnection_getPeerAddress;
  }
  return self;
}

CS104_Proxy
CS104_Proxy_create(const char *hostname, int tcpPort)
{
  if (tcpPort == -1)
    tcpPort = IEC_60870_5_104_DEFAULT_PORT;
  return createProxy(hostname, tcpPort);
}

#if (CONFIG_CS104_SUPPORT_TLS == 1)
CS104_Proxy
CS104_Proxy_createSecure(const char *hostname, int tcpPort, TLSConfiguration tlsConfig)
{
  if (tcpPort == -1)
    tcpPort = IEC_60870_5_104_DEFAULT_TLS_PORT;

  CS104_Proxy self = createConnection(hostname, tcpPort);

  if (self != NULL) {
    self->tlsConfig = tlsConfig;
    TLSConfiguration_setClientMode(tlsConfig);
  }

  return self;
}
#endif /* (CONFIG_CS104_SUPPORT_TLS == 1) */

void
CS104_Proxy_close(CS104_Proxy self)
{
  self->close = true;
#if (CONFIG_USE_THREADS == 1)
  if (self->connectionHandlingThread) {
    Thread_destroy(self->connectionHandlingThread);
    self->connectionHandlingThread = NULL;
  }
#endif
}

void
CS104_Proxy_destroy(CS104_Proxy self)
{
  CS104_Proxy_close(self);

  if (self->sentASDUs != NULL)
    GLOBAL_FREEMEM(self->sentASDUs);

#if (CONFIG_USE_SEMAPHORES == 1)
  Semaphore_destroy(self->sentASDUsLock);
#endif

  GLOBAL_FREEMEM(self);
}
