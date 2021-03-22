/*
 *  cs104_proxy.h
 *
 *  Copyright 2017, 2018 MZ Automation GmbH
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

#ifndef SRC_INC_API_CS104_PROXY_H_
#define SRC_INC_API_CS104_PROXY_H_

#include "iec60870_slave.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sCS104_Proxy *CS104_Proxy;

/**
 * \brief Create a new instance of a CS104 slave (server)
 *
 * \param maxLowPrioQueueSize the maximum size of the event queue
 * \param maxHighPrioQueueSize the maximum size of the high-priority queue
 *
 * \return the new slave instance
 */
CS104_Proxy
CS104_Proxy_create(const char *hostname, int tcpPort);

/**
 * \brief Create a new instance of a CS104 slave (server) with TLS enabled
 *
 * \param maxLowPrioQueueSize the maximum size of the event queue
 * \param maxHighPrioQueueSize the maximum size of the high-priority queue
 * \param tlsConfig the TLS configuration object (containing configuration parameters, keys, and certificates)
 *
 * \return the new slave instance
 */
CS104_Proxy
CS104_Proxy_createSecure(const char *hostname, int tcpPort, TLSConfiguration tlsConfig);

void
CS104_Proxy_setInterrogationHandler(CS104_Proxy self, CS101_InterrogationHandler handler, void*  parameter);

void
CS104_Proxy_setCounterInterrogationHandler(CS104_Proxy self, CS101_CounterInterrogationHandler handler, void*  parameter);

/**
 * \brief set handler for read request (C_RD_NA_1 - 102)
 */
void
CS104_Proxy_setReadHandler(CS104_Proxy self, CS101_ReadHandler handler, void* parameter);

void
CS104_Proxy_setASDUHandler(CS104_Proxy self, CS101_ASDUHandler handler, void* parameter);

void
CS104_Proxy_setClockSyncHandler(CS104_Proxy self, CS101_ClockSynchronizationHandler handler, void* parameter);

/**
 * \brief Set the raw message callback (called when a message is sent or received)
 *
 * \param handler user provided callback handler function
 * \param parameter user provided parameter that is passed to the callback handler
 */
void
CS104_Proxy_setRawMessageHandler(CS104_Proxy self, IEC60870_RawMessageHandler handler, void* parameter);

/**
 * \brief Get the APCI parameters instance. APCI parameters are CS 104 specific parameters.
 */
CS104_APCIParameters
CS104_Proxy_getConnectionParameters(CS104_Proxy self);

/**
 * \brief Get the application layer parameters instance..
 */
CS101_AppLayerParameters
CS104_Proxy_getAppLayerParameters(CS104_Proxy self);

void
CS104_Proxy_setConnectTimeout(CS104_Proxy self, int millies);

void
CS104_Proxy_setAPCIParameters(CS104_Proxy self, CS104_APCIParameters parameters);

void
CS104_Proxy_setAppLayerParameters(CS104_Proxy self, CS101_AppLayerParameters parameters);

void
CS104_Proxy_close(CS104_Proxy self);

void
CS104_Proxy_destroy(CS104_Proxy self);

#ifdef __cplusplus
}
#endif

#endif /* SRC_INC_API_CS104_PROXY_H_ */
