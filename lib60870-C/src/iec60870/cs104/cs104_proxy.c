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

  SentASDUProxy *sentASDUs; /* the k-buffer */
  uint16_t maxSentASDUs;    /* k-parameter */
  int16_t oldestSentASDU;   /* oldest sent ASDU in k-buffer */
  int16_t newestSentASDU;   /* newest sent ASDU in k-buffer */

#if (CONFIG_USE_SEMAPHORES == 1)
  Semaphore sentASDUsLock;
#endif

#if (CONFIG_USE_THREADS == 1)
  Thread connectionHandlingThread;
#endif

  uint16_t sendCount;    /* sent messages - sequence counter */
  uint16_t receiveCount; /* received messages - sequence counter */

  int unconfirmedReceivedIMessages; /* number of unconfirmed messages received
                                     */
                                    /* timeout T2 handling */
  bool timeoutT2Trigger;
  uint64_t lastConfirmationTime; /* timestamp when the last confirmation message
                                    (for I messages) was sent */

  uint64_t nextT3Timeout;
  uint64_t nextTestFRConTimeout; /* timeout T1 when waiting for TEST FR con */

  Socket socket;
  bool running;
  bool failure;
  bool close;

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

void CS104_Proxy_setInterrogationHandler(CS104_Proxy self,
                                         CS101_InterrogationHandler handler,
                                         void *parameter) {
  self->interrogationHandler = handler;
  self->interrogationHandlerParameter = parameter;
}

void CS104_Proxy_setCounterInterrogationHandler(
    CS104_Proxy self, CS101_CounterInterrogationHandler handler,
    void *parameter) {
  self->counterInterrogationHandler = handler;
  self->counterInterrogationHandlerParameter = parameter;
}

void CS104_Proxy_setReadHandler(CS104_Proxy self, CS101_ReadHandler handler,
                                void *parameter) {
  self->readHandler = handler;
  self->readHandlerParameter = parameter;
}

void CS104_Proxy_setASDUHandler(CS104_Proxy self, CS101_ASDUHandler handler,
                                void *parameter) {
  self->asduHandler = handler;
  self->asduHandlerParameter = parameter;
}

void CS104_Proxy_setClockSyncHandler(CS104_Proxy self,
                                     CS101_ClockSynchronizationHandler handler,
                                     void *parameter) {
  self->clockSyncHandler = handler;
  self->clockSyncHandlerParameter = parameter;
}

void CS104_Proxy_setRawMessageHandler(CS104_Proxy self,
                                      IEC60870_RawMessageHandler handler,
                                      void *parameter) {
  self->rawMessageHandler = handler;
  self->rawMessageHandlerParameter = parameter;
}

CS104_APCIParameters CS104_Proxy_getConnectionParameters(CS104_Proxy self) {
  return &(self->conParameters);
}

CS101_AppLayerParameters CS104_Proxy_getAppLayerParameters(CS104_Proxy self) {
  return &(self->alParameters);
}

static int writeToSocket(CS104_Proxy self, uint8_t *buf, int size) {
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

static CS104_Proxy createProxy(const char *hostname, int tcpPort) {
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

    self->sentASDUs = NULL;
  }
  return self;
}

CS104_Proxy CS104_Proxy_create(const char *hostname, int tcpPort) {
  if (tcpPort == -1)
    tcpPort = IEC_60870_5_104_DEFAULT_PORT;
  return createProxy(hostname, tcpPort);
}

#if (CONFIG_CS104_SUPPORT_TLS == 1)
CS104_Proxy CS104_Proxy_createSecure(const char *hostname, int tcpPort,
                                     TLSConfiguration tlsConfig) {
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

static void resetT3Timeout(CS104_Proxy self) {
  self->nextT3Timeout =
      Hal_getTimeInMs() + (uint64_t)(self->conParameters.t3 * 1000);
}

static bool checkSequenceNumber(CS104_Proxy self, int seqNo) {
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
  } else {
    /* Two cases are required to reflect sequence number overflow */
    if (self->sentASDUs[self->oldestSentASDU].seqNo <=
        self->sentASDUs[self->newestSentASDU].seqNo) {
      if ((seqNo >= self->sentASDUs[self->oldestSentASDU].seqNo) &&
          (seqNo <= self->sentASDUs[self->newestSentASDU].seqNo))
        seqNoIsValid = true;
    } else {
      if ((seqNo >= self->sentASDUs[self->oldestSentASDU].seqNo) ||
          (seqNo <= self->sentASDUs[self->newestSentASDU].seqNo))
        seqNoIsValid = true;

      counterOverflowDetected = true;
    }

    /* check if confirmed message was already removed from list */
    if (self->sentASDUs[self->oldestSentASDU].seqNo == 0)
      oldestValidSeqNo = 32767;
    else
      oldestValidSeqNo =
          (self->sentASDUs[self->oldestSentASDU].seqNo - 1) % 32768;

    if (oldestValidSeqNo == seqNo)
      seqNoIsValid = true;
  }

  if (seqNoIsValid) {

    if (self->oldestSentASDU != -1) {

      do {
        if (counterOverflowDetected == false) {
          if (seqNo < self->sentASDUs[self->oldestSentASDU].seqNo)
            break;
        }

        if (seqNo == oldestValidSeqNo)
          break;

        if (self->sentASDUs[self->oldestSentASDU].seqNo == seqNo) {
          /* we arrived at the seq# that has been confirmed */

          if (self->oldestSentASDU == self->newestSentASDU)
            self->oldestSentASDU = -1;
          else
            self->oldestSentASDU =
                (self->oldestSentASDU + 1) % self->maxSentASDUs;

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

#if (CONFIG_USE_SEMAPHORES == 1)
  Semaphore_post(self->sentASDUsLock);
#endif

  return seqNoIsValid;
}

static bool isSentBufferFull(CS104_Proxy self) {
  if (self->oldestSentASDU == -1)
    return false;

  int newIndex = (self->newestSentASDU + 1) % self->maxSentASDUs;

  if (newIndex == self->oldestSentASDU)
    return true;
  else
    return false;
}

void CS104_Proxy_close(CS104_Proxy self) {
  self->close = true;
#if (CONFIG_USE_THREADS == 1)
  if (self->connectionHandlingThread) {
    Thread_destroy(self->connectionHandlingThread);
    self->connectionHandlingThread = NULL;
  }
#endif
}

void CS104_Proxy_destroy(CS104_Proxy self) {
  CS104_Proxy_close(self);

  if (self->sentASDUs != NULL)
    GLOBAL_FREEMEM(self->sentASDUs);

#if (CONFIG_USE_SEMAPHORES == 1)
  Semaphore_destroy(self->sentASDUsLock);
#endif

  GLOBAL_FREEMEM(self);
}

void CS104_Proxy_setAPCIParameters(CS104_Proxy self,
                                   CS104_APCIParameters parameters) {
  self->conParameters = *parameters;

  self->connectTimeoutInMs = self->conParameters.t0 * 1000;
}

void CS104_Proxy_setAppLayerParameters(CS104_Proxy self,
                                       CS101_AppLayerParameters parameters) {
  self->alParameters = *parameters;
}

CS101_AppLayerParameters CS104_Proxy_getAppLayerParameters(CS104_Proxy self) {
  return &(self->alParameters);
}

void CS104_Proxy_setConnectTimeout(CS104_Proxy self, int millies) {
  self->connectTimeoutInMs = millies;
}

CS104_APCIParameters CS104_Proxy_getAPCIParameters(CS104_Proxy self) {
  return &(self->conParameters);
}

/**
 * \return number of bytes read, or -1 in case of an error
 */
static int readFromSocket(CS104_Proxy self, uint8_t *buffer, int size) {
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
 * \return -1 in case of an error, 0 when no complete message can be read, > 0
 * when a complete message is in buffer
 */
static int receiveMessage(CS104_Proxy self) {
  uint8_t *buffer = self->recvBuffer;
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
  if (bufPos == 1) {

    int readCnt = readFromSocket(self, buffer + 1, 1);

    if (readCnt < 0) {
      self->recvBufPos = 0;
      return -1;
    } else if (readCnt == 0) {
      self->recvBufPos = 1;
      return 0;
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
    } else if (readCnt == -1) {
      self->recvBufPos = 0;
      return -1;
    } else {
      self->recvBufPos = bufPos + readCnt;
      return 0;
    }
  }

  self->recvBufPos = bufPos;
  return 0;
}

static bool checkConfirmTimeout(CS104_Proxy self, uint64_t currentTime) {
  if (currentTime > self->lastConfirmationTime) {
    if ((currentTime - self->lastConfirmationTime) >=
        (uint32_t)(self->conParameters.t2 * 1000)) {
      return true;
    }
  }

  return false;
}

static int sendIMessage(CS104_Proxy self, uint8_t *buffer, int msgSize) {
  buffer[0] = (uint8_t)0x68;
  buffer[1] = (uint8_t)(msgSize - 2);

  buffer[2] = (uint8_t)((self->sendCount % 128) * 2);
  buffer[3] = (uint8_t)(self->sendCount / 128);

  buffer[4] = (uint8_t)((self->receiveCount % 128) * 2);
  buffer[5] = (uint8_t)(self->receiveCount / 128);

  if (writeToSocket(self, buffer, msgSize) > 0) {
    DEBUG_PRINT("CS104 SLAVE: SEND I (size = %i) N(S) = %i N(R) = %i\n",
                msgSize, self->sendCount, self->receiveCount);
    self->sendCount = (self->sendCount + 1) % 32768;
    self->unconfirmedReceivedIMessages = 0;
    self->timeoutT2Trigger = false;
  } else
    self->running = false;

  self->unconfirmedReceivedIMessages = 0;

  return self->sendCount;
}

/*
 * Handle received ASDUs
 *
 * Call the appropriate callbacks according to ASDU type and CoT
 *
 * \return true when ASDU is valid, false otherwise (e.g. corrupted message data)
 */
static bool handleASDU(CS104_Proxy self, CS101_ASDU asdu) {
  bool messageHandled = false;

  uint8_t cot = CS101_ASDU_getCOT(asdu);

  switch (CS101_ASDU_getTypeID(asdu)) {

  case C_IC_NA_1: /* 100 - interrogation command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd interrogation command C_IC_NA_1\n");

    if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_DEACTIVATION)) {
      if (self->interrogationHandler != NULL) {

        union uInformationObject _io;

        InterrogationCommand irc =
            (InterrogationCommand)CS101_ASDU_getElementEx(
                asdu, (InformationObject)&_io, 0);

        if (irc) {
          if (self->interrogationHandler(self->interrogationHandlerParameter,
                                         &(self->iMasterConnection), asdu,
                                         InterrogationCommand_getQOI(irc)))
            messageHandled = true;
        } else
          return false;
      }
    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_CI_NA_1: /* 101 - counter interrogation command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd counter interrogation command C_CI_NA_1\n");

    if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_DEACTIVATION)) {

      if (self->counterInterrogationHandler != NULL) {

        union uInformationObject _io;

        CounterInterrogationCommand cic =
            (CounterInterrogationCommand)CS101_ASDU_getElementEx(
                asdu, (InformationObject)&_io, 0);

        if (cic) {
          if (self->counterInterrogationHandler(
                  self->counterInterrogationHandlerParameter,
                  &(self->iMasterConnection), asdu,
                  CounterInterrogationCommand_getQCC(cic)))
            messageHandled = true;
        } else
          return false;
      }
    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_RD_NA_1: /* 102 - read command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd read command C_RD_NA_1\n");

    if (cot == CS101_COT_REQUEST) {
      if (self->readHandler != NULL) {

        union uInformationObject _io;

        ReadCommand rc = (ReadCommand)CS101_ASDU_getElementEx(
            asdu, (InformationObject)&_io, 0);

        if (rc) {
          if (self->readHandler(
                  self->readHandlerParameter, &(self->iMasterConnection), asdu,
                  InformationObject_getObjectAddress((InformationObject)rc)))
            messageHandled = true;
        } else
          return false;
      }
    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_CS_NA_1: /* 103 - Clock synchronization command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd clock sync command C_CS_NA_1\n");

    if (cot == CS101_COT_ACTIVATION) {

      if (self->clockSyncHandler != NULL) {

        union uInformationObject _io;

        ClockSynchronizationCommand csc =
            (ClockSynchronizationCommand)CS101_ASDU_getElementEx(
                asdu, (InformationObject)&_io, 0);

        if (csc) {
          CP56Time2a newTime = ClockSynchronizationCommand_getTime(csc);

          if (self->clockSyncHandler(self->clockSyncHandlerParameter,
                                     &(self->iMasterConnection), asdu,
                                     newTime)) {

            CS101_ASDU_removeAllElements(asdu);

            ClockSynchronizationCommand_create(csc, 0, newTime);

            CS101_ASDU_addInformationObject(asdu, (InformationObject)csc);

            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

            sendASDUInternal(self, asdu);
          } else {
            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            CS101_ASDU_setNegative(asdu, true);

            sendASDUInternal(self, asdu);
          }

          messageHandled = true;
        } else
          return false;
      }
    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_TS_NA_1: /* 104 - test command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd test command C_TS_NA_1\n");

    if (cot != CS101_COT_ACTIVATION) {
      CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
      CS101_ASDU_setNegative(asdu, true);
    } else
      CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

    sendASDUInternal(self, asdu);

    messageHandled = true;

    break;

  case C_RP_NA_1: /* 105 - Reset process command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd reset process command C_RP_NA_1\n");

    if (cot == CS101_COT_ACTIVATION) {

      if (self->resetProcessHandler != NULL) {

        union uInformationObject _io;

        ResetProcessCommand rpc = (ResetProcessCommand)CS101_ASDU_getElementEx(
            asdu, (InformationObject)&_io, 0);

        if (rpc) {
          if (self->resetProcessHandler(self->resetProcessHandlerParameter,
                                        &(self->iMasterConnection), asdu,
                                        ResetProcessCommand_getQRP(rpc)))
            messageHandled = true;
        } else
          return false;
      }

    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_CD_NA_1: /* 106 - Delay acquisition command */

    DEBUG_PRINT("CS104 SLAVE: Rcvd delay acquisition command C_CD_NA_1\n");

    if ((cot == CS101_COT_ACTIVATION) || (cot == CS101_COT_SPONTANEOUS)) {

      if (self->delayAcquisitionHandler != NULL) {

        union uInformationObject _io;

        DelayAcquisitionCommand dac =
            (DelayAcquisitionCommand)CS101_ASDU_getElementEx(
                asdu, (InformationObject)&_io, 0);

        if (dac) {
          if (self->delayAcquisitionHandler(
                  self->delayAcquisitionHandlerParameter,
                  &(self->iMasterConnection), asdu,
                  DelayAcquisitionCommand_getDelay(dac)))
            messageHandled = true;
        } else
          return false;
      }
    } else
      responseCOTUnknown(asdu, self);

    break;

  case C_TS_TA_1: /* 107 - test command with timestamp */

    DEBUG_PRINT("CS104 SLAVE: Rcvd test command with CP56Time2a C_TS_TA_1\n");

    if (cot != CS101_COT_ACTIVATION) {
      CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
      CS101_ASDU_setNegative(asdu, true);
    } else
      CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

    sendASDUInternal(self, asdu);

    messageHandled = true;

    break;

  default: /* no special handler available -> use default handler */
    break;
  }

  if ((messageHandled == false) && (self->asduHandler != NULL))
    if (self->asduHandler(self->asduHandlerParameter,
                          &(self->iMasterConnection), asdu))
      messageHandled = true;

  if (messageHandled == false) {
    /* send error response */
    CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_TYPE_ID);
    CS101_ASDU_setNegative(asdu, true);
    sendASDUInternal(self, asdu);
  }

  return true;
}
