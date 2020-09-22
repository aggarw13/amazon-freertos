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

/* Standard includes. */
#include <assert.h>
#include <string.h>

/* Transport interface include. */
#include "transport_interface.h"

/* Interface include. */
#include "transport_secure_sockets.h"

/*-----------------------------------------------------------*/

int32_t SecureSocketsTrasnport_Connect( NetworkContext_t * pNetworkContext,
                                        SocketsSockaddr_t * pxAddress,
                                        Socklen_t xAddressLength )
{
    int32_t returnStatus;

    Socket_t createdSocket = SOCKETS_Socket( SOCKETS_AF_INET, SOCKETS_SOCK_STREAM, SOCKETS_IPPROTO_TCP );

    returnStatus = SOCKETS_SetSockOpt( createdSocket, 0, SOCKETS_SO_REQUIRE_TLS, NULL, 0 );

    if( returnStatus != SOCKETS_ERROR_NONE )
    {
        LogError( ( "Failed to mark the socket as secure socket.\r\n" ) );
    }
    else
    {
        returnStatus = SOCKETS_Connect( createdSocket, pxAddress, xAddressLength );

        /* Log failure or success depending on status. */
        if( returnStatus != SOCKETS_ERROR_NONE )
        {
            LogError( ( "Failed to establish a TLS connection.\r\n" ) );
        }
        else
        {
            pNetworkContext->secureSocket = createdSocket;
            LogDebug( ( "Established a TLS connection.\r\n" ) );
        }
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

int32_t SecureSocketsTrasnport_Disconnect( NetworkContext_t * pNetworkContext )
{
    int32_t returnStatus;

    ( void ) SOCKETS_Shutdown( pNetworkContext->secureSocket, SOCKETS_SHUT_RDWR );

    returnStatus = SOCKETS_Close( pNetworkContext->secureSocket );

    /* Log failure or success depending on status. */
    if( returnStatus != SOCKETS_ERROR_NONE )
    {
        LogError( ( "Failed to close the TLS connection.\r\n" ) );
    }
    else
    {
        LogDebug( ( "Closed the TLS connection.\r\n" ) );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

int32_t SecureSocketsTrasnport_Recv( NetworkContext_t * pNetworkContext,
                                     void * pBuffer,
                                     size_t bytesToRecv )
{
    return SOCKETS_Recv( pNetworkContext->secureSocket, pBuffer, bytesToRecv, 0 );
}
/*-----------------------------------------------------------*/

int32_t SecureSocketsTrasnport_Send( NetworkContext_t * pNetworkContext,
                                     const void * pBuffer,
                                     size_t bytesToSend )
{
    return SOCKETS_Send( pNetworkContext->secureSocket, pBuffer, bytesToSend, 0 );
}
/*-----------------------------------------------------------*/
