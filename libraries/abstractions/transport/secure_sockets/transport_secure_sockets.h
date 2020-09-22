/*
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef SECURE_SOCKETS_TRANSPORT_H_
#define SECURE_SOCKETS_TRANSPORT_H_

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the transport interface implemenation which uses
 * Secure Sockets. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "Secure_Sockets_Transport"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_DEBUG
#endif

#include "logging_stack.h"

/************ End of logging configuration ****************/

/* Transport includes. */
#include "transport_interface.h"

/* Secure Socket include. */
#include "aws_secure_sockets_wtp.h"

/**
 * @brief Definition of the network context for the transport interface
 * implemenation that uses secure sockets.
 */
struct NetworkContext
{
    Socket_t secureSocket;
};

/**
 * @brief Sets up a TLS session on top of a TCP connection.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 * @param[in] pxAddress Server to connect to.
 * @param[in] xAddressLength Length of pxAddress.
 *
 * @return SOCKETS_ERROR_NONE if a connection is established, otherwise a
 * negative error code.
 */
int32_t SecureSocketsTrasnport_Connect( NetworkContext_t * pNetworkContext,
                                        SocketsSockaddr_t * pxAddress,
                                        Socklen_t xAddressLength );

/**
 * @brief Closes a TLS session and the underlying TCP connection.
 *
 * @param[in] pNetworkContext The network context to dosconnect.
 *
 * @return On success, 0 is returned. Otherwise a negative error code is returned.
 */
int32_t SecureSocketsTrasnport_Disconnect( NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session.
 *
 * This can be used as #TransportInterface.recv function for receiving data
 * from the network.
 *
 * @param[in] pNetworkContext The network context created using SecureSocketsTrasnport_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value on error.
 */
int32_t SecureSocketsTrasnport_Recv( NetworkContext_t * pNetworkContext,
                                     void * pBuffer,
                                     size_t bytesToRecv );

/**
 * @brief Sends data over an established TLS session.
 *
 * @param[in] pNetworkContext The network context created using SecureSocketsTrasnport_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network stack.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 */
int32_t SecureSocketsTrasnport_Send( NetworkContext_t * pNetworkContext,
                                     const void * pBuffer,
                                     size_t bytesToSend );

#endif /* ifndef SECURE_SOCKETS_TRANSPORT_H_ */