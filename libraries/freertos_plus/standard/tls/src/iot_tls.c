/*
 * FreeRTOS TLS V1.3.1
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
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "iot_tls.h"
#include "iot_crypto.h"
#include "core_pkcs11_config.h"
#include "core_pkcs11.h"
#include "task.h"
#include "aws_clientcredential_keys.h"
#include "iot_default_root_certificates.h"
#include "core_pki_utils.h"

/* mbedTLS includes. */
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/debug.h"

#ifdef MBEDTLS_DEBUG_C
    #define tlsDEBUG_VERBOSE    4
#endif

/* Custom mbedtls utls include. */
#include "mbedtls_error.h"

/* C runtime includes. */
#include <string.h>
#include <time.h>
#include <stdio.h>

/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a high-level code.
 */
static const char * pNoHighLevelMbedTlsCodeStr = "<No-High-Level-Code>";

/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a low-level code.
 */
static const char * pNoLowLevelMbedTlsCodeStr = "<No-Low-Level-Code>";

/**
 * @brief Utility for converting the high-level code in an mbedTLS error to string,
 * if the code-contains a high-level code; otherwise, using a default string.
 */
#define mbedtlsHighLevelCodeOrDefault( mbedTlsCode )        \
    ( mbedtls_strerror_highlevel( mbedTlsCode ) != NULL ) ? \
    mbedtls_strerror_highlevel( mbedTlsCode ) : pNoHighLevelMbedTlsCodeStr


/**
 * @brief Utility for converting the level-level code in an mbedTLS error to string,
 * if the code-contains a level-level code; otherwise, using a default string.
 */
#define mbedtlsLowLevelCodeOrDefault( mbedTlsCode )        \
    ( mbedtls_strerror_lowlevel( mbedTlsCode ) != NULL ) ? \
    mbedtls_strerror_lowlevel( mbedTlsCode ) : pNoLowLevelMbedTlsCodeStr


/**
 * @brief Internal context structure.
 *
 * @param[in] pcDestination Server location, can be a DNS name or IP address.
 * @param[in] pcServerCertificate Server X.509 certificate in PEM format to trust.
 * @param[in] ulServerCertificateLength Length in bytes of the server certificate.
 * @param[in] xNetworkRecv Callback for receiving data on an open TCP socket.
 * @param[in] xNetworkSend Callback for sending data on an open TCP socket.
 * @param[in] pvCallerContext Opaque pointer provided by caller for above callbacks.
 * @param[out] xTLSHandshakeState Indicates the state of the TLS handshake.
 * @param[out] xMbedSslCtx Connection context for mbedTLS.
 * @param[out] xMbedSslConfig Configuration context for mbedTLS.
 * @param[out] xMbedX509CA Server certificate context for mbedTLS.
 * @param[out] xMbedX509Cli Client certificate context for mbedTLS.
 * @param[out] mbedPkAltCtx RSA crypto implementation context for mbedTLS.
 * @param[out] pxP11FunctionList PKCS#11 function list structure.
 * @param[out] xP11Session PKCS#11 session context.
 * @param[out] xP11PrivateKey PKCS#11 private key context.
 */
typedef struct TLSContext
{
    const char * pcDestination;
    const char * pcServerCertificate;
    uint32_t ulServerCertificateLength;
    const char ** ppcAlpnProtocols;
    uint32_t ulAlpnProtocolsCount;

    NetworkRecv_t xNetworkRecv;
    NetworkSend_t xNetworkSend;
    void * pvCallerContext;
    BaseType_t xTLSHandshakeState;

    /* mbedTLS. */
    mbedtls_ssl_context xMbedSslCtx;
    mbedtls_ssl_config xMbedSslConfig;
    mbedtls_x509_crt xMbedX509CA;
    mbedtls_x509_crt xMbedX509Cli;
    mbedtls_pk_context xMbedPkCtx;
    mbedtls_pk_info_t xMbedPkInfo;
    mbedtls_ctr_drbg_context xMbedDrbgCtx;

    /* PKCS#11. */
    CK_FUNCTION_LIST_PTR pxP11FunctionList;
    CK_SESSION_HANDLE xP11Session;
    CK_OBJECT_HANDLE xP11PrivateKey;
    CK_KEY_TYPE xKeyType;
} TLSContext_t;

#define TLS_HANDSHAKE_NOT_STARTED    ( 0 )      /* Must be 0 */
#define TLS_HANDSHAKE_STARTED        ( 1 )
#define TLS_HANDSHAKE_SUCCESSFUL     ( 2 )

#define TLS_PRINT( X )    configPRINTF( X )

static BaseType_t prvDefault_DateIsInThePast( BaseType_t day,
                                              BaseType_t month,
                                              BaseType_t year );
static DateIsInThePast_t pDateIsInThePast = prvDefault_DateIsInThePast;

/*-----------------------------------------------------------*/

/*
 * Helper routines.
 */

/**
 * @brief TLS internal context rundown helper routine.
 *
 * @param[in] pvContext Caller context.
 */
static void prvFreeContext( TLSContext_t * pxCtx )
{
    if( NULL != pxCtx )
    {
        /* Cleanup mbedTLS. */
        mbedtls_ssl_close_notify( &pxCtx->xMbedSslCtx ); /*lint !e534 The error is already taken care of inside mbedtls_ssl_close_notify*/
        mbedtls_ssl_free( &pxCtx->xMbedSslCtx );
        mbedtls_ssl_config_free( &pxCtx->xMbedSslConfig );
        mbedtls_ctr_drbg_free( &pxCtx->xMbedDrbgCtx );

        /* Cleanup PKCS11 only if the handshake was started. */
        if( ( TLS_HANDSHAKE_NOT_STARTED != pxCtx->xTLSHandshakeState ) &&
            ( NULL != pxCtx->pxP11FunctionList ) &&
            ( NULL != pxCtx->pxP11FunctionList->C_CloseSession ) &&
            ( CK_INVALID_HANDLE != pxCtx->xP11Session ) )
        {
            pxCtx->pxP11FunctionList->C_CloseSession( pxCtx->xP11Session ); /*lint !e534 This function always return CKR_OK. */
        }

        pxCtx->xTLSHandshakeState = TLS_HANDSHAKE_NOT_STARTED;
    }
}

static BaseType_t prvDefault_DateIsInThePast( BaseType_t day,
                                              BaseType_t month,
                                              BaseType_t year )
{
    return 0; /* Assume the certificate is valid. */
}

/*-----------------------------------------------------------*/

/**
 * @brief Network send callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[in] pucData Byte buffer to send.
 * @param[in] xDataLength Length of byte buffer to send.
 *
 * @return Number of bytes sent, or a negative value on error.
 */
static int prvNetworkSend( void * pvContext,
                           const unsigned char * pucData,
                           size_t xDataLength )
{
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    return ( int ) pxCtx->xNetworkSend( pxCtx->pvCallerContext, pucData, xDataLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Network receive callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[out] pucReceiveBuffer Byte buffer to receive into.
 * @param[in] xReceiveLength Length of byte buffer for receive.
 *
 * @return Number of bytes received, or a negative value on error.
 */
static int prvNetworkRecv( void * pvContext,
                           unsigned char * pucReceiveBuffer,
                           size_t xReceiveLength )
{
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    return ( int ) pxCtx->xNetworkRecv( pxCtx->pvCallerContext, pucReceiveBuffer, xReceiveLength );
}

/*-----------------------------------------------------------*/

/**
 * @brief Callback that wraps PKCS#11 for pseudo-random number generation.
 *
 * @param[in] pvCtx Caller context.
 * @param[in] pucRandom Byte array to fill with random data.
 * @param[in] xRandomLength Length of byte array.
 *
 * @return Zero on success.
 */
static int prvGenerateRandomBytes( void * pvCtx,
                                   unsigned char * pucRandom,
                                   size_t xRandomLength )
{
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvCtx; /*lint !e9087 !e9079 Allow casting void* to other types. */
    int xResult = 0;

    xResult = mbedtls_ctr_drbg_random( &pxCtx->xMbedDrbgCtx, pucRandom, xRandomLength );

    if( xResult != 0 )
    {
        TLS_PRINT( ( "ERROR: Failed to generate random bytes %s : %s \r\n",
                     mbedtlsHighLevelCodeOrDefault( xResult ),
                     mbedtlsLowLevelCodeOrDefault( xResult ) ) );
        xResult = TLS_ERROR_RNG;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/**
 * @brief Callback that enforces a worst-case expiration check on TLS server
 * certificates.
 *
 * @param[in] pvCtx Caller context.
 * @param[in] pxCertificate Certificate to check.
 * @param[in] lPathCount Location of this certificate in the chain.
 * @param[in] pulFlags Verification status flags.
 *
 * @return Zero on success.
 */
static int prvCheckCertificate( void * pvContext,
                                mbedtls_x509_crt * pxCertificate,
                                int lPathCount,
                                uint32_t * pulFlags )
{
    /* Unreferenced parameters. */
    ( void ) ( pvContext );
    ( void ) ( lPathCount );

    BaseType_t day = pxCertificate->valid_to.day;
    BaseType_t month = pxCertificate->valid_to.mon;
    BaseType_t year = pxCertificate->valid_to.year;

    if( pDateIsInThePast( day, month, year ) != 0 )
    {
        *pulFlags |= MBEDTLS_X509_BADCERT_EXPIRED;
    }

    return 0;
}

/*-----------------------------------------------------------*/

/**
 * @brief Sign a cryptographic hash with the private key.
 *
 * @param[in] pvContext Crypto context.
 * @param[in] xMdAlg Unused.
 * @param[in] pucHash Length in bytes of hash to be signed.
 * @param[in] uiHashLen Byte array of hash to be signed.
 * @param[out] pucSig RSA signature bytes.
 * @param[in] pxSigLen Length in bytes of signature buffer.
 * @param[in] piRng Unused.
 * @param[in] pvRng Unused.
 *
 * @return Zero on success.
 */
static int prvPrivateKeySigningCallback( void * pvContext,
                                         mbedtls_md_type_t xMdAlg,
                                         const unsigned char * pucHash,
                                         size_t xHashLen,
                                         unsigned char * pucSig,
                                         size_t * pxSigLen,
                                         int ( * piRng )( void *,
                                                          unsigned char *,
                                                          size_t ), /*lint !e955 This parameter is unused. */
                                         void * pvRng )
{
    CK_RV xResult = CKR_OK;
    int lFinalResult = 0;
    TLSContext_t * pxTLSContext = ( TLSContext_t * ) pvContext;
    CK_MECHANISM xMech = { 0 };
    CK_BYTE xToBeSigned[ 256 ];
    CK_ULONG xToBeSignedLen = sizeof( xToBeSigned );

    /* Unreferenced parameters. */
    ( void ) ( piRng );
    ( void ) ( pvRng );
    ( void ) ( xMdAlg );

    /* Sanity check buffer length. */
    if( xHashLen > sizeof( xToBeSigned ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Format the hash data to be signed. */
    if( CKK_RSA == pxTLSContext->xKeyType )
    {
        xMech.mechanism = CKM_RSA_PKCS;

        /* mbedTLS expects hashed data without padding, but PKCS #11 C_Sign function performs a hash
         * & sign if hash algorithm is specified.  This helper function applies padding
         * indicating data was hashed with SHA-256 while still allowing pre-hashed data to
         * be provided. */
        xResult = vAppendSHA256AlgorithmIdentifierSequence( ( uint8_t * ) pucHash, xToBeSigned );
        xToBeSignedLen = pkcs11RSA_SIGNATURE_INPUT_LENGTH;
    }
    else if( CKK_EC == pxTLSContext->xKeyType )
    {
        xMech.mechanism = CKM_ECDSA;
        memcpy( xToBeSigned, pucHash, xHashLen );
        xToBeSignedLen = xHashLen;
    }
    else
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( CKR_OK == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = pxTLSContext->pxP11FunctionList->C_SignInit( pxTLSContext->xP11Session,
                                                               &xMech,
                                                               pxTLSContext->xP11PrivateKey );
    }

    if( CKR_OK == xResult )
    {
        *pxSigLen = sizeof( xToBeSigned );
        xResult = pxTLSContext->pxP11FunctionList->C_Sign( ( CK_SESSION_HANDLE ) pxTLSContext->xP11Session,
                                                           xToBeSigned,
                                                           xToBeSignedLen,
                                                           pucSig,
                                                           ( CK_ULONG_PTR ) pxSigLen );
    }

    if( ( xResult == CKR_OK ) && ( CKK_EC == pxTLSContext->xKeyType ) )
    {
        /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
         * This must be converted to an ASN.1 encoded array. */
        if( *pxSigLen != pkcs11ECDSA_P256_SIGNATURE_LENGTH )
        {
            xResult = CKR_FUNCTION_FAILED;
        }

        if( xResult == CKR_OK )
        {
            PKI_pkcs11SignatureTombedTLSSignature( pucSig, pxSigLen );
        }
    }

    if( xResult != CKR_OK )
    {
        TLS_PRINT( ( "ERROR: Failure in signing callback: %d \r\n", xResult ) );
        lFinalResult = TLS_ERROR_SIGN;
    }

    return lFinalResult;
}

/*-----------------------------------------------------------*/

/**
 * @brief Helper for reading the specified certificate object, if present,
 * out of storage, into RAM, and then into an mbedTLS certificate context
 * object.
 *
 * @param[in] pxTlsContext Caller TLS context.
 * @param[in] pcLabelName PKCS #11 certificate object label.
 * @param[in] xClass PKCS #11 certificate object class.
 * @param[out] pxCertificateContext Certificate context.
 *
 * @return Zero on success.
 */
static int prvReadCertificateIntoContext( TLSContext_t * pxTlsContext,
                                          char * pcLabelName,
                                          CK_OBJECT_CLASS xClass,
                                          mbedtls_x509_crt * pxCertificateContext )
{
    BaseType_t xResult = CKR_OK;
    CK_ATTRIBUTE xTemplate = { 0 };
    CK_OBJECT_HANDLE xCertObj = 0;

    /* Get the handle of the certificate. */
    xResult = xFindObjectWithLabelAndClass( pxTlsContext->xP11Session,
                                            pcLabelName,
                                            strlen( pcLabelName ),
                                            xClass,
                                            &xCertObj );

    if( ( CKR_OK == xResult ) && ( xCertObj == CK_INVALID_HANDLE ) )
    {
        xResult = CKR_OBJECT_HANDLE_INVALID;
    }

    /* Query the certificate size. */
    if( 0 == xResult )
    {
        xTemplate.type = CKA_VALUE;
        xTemplate.ulValueLen = 0;
        xTemplate.pValue = NULL;
        xResult = ( BaseType_t ) pxTlsContext->pxP11FunctionList->C_GetAttributeValue( pxTlsContext->xP11Session,
                                                                                       xCertObj,
                                                                                       &xTemplate,
                                                                                       1 );
    }

    /* Create a buffer for the certificate. */
    if( 0 == xResult )
    {
        xTemplate.pValue = pvPortMalloc( xTemplate.ulValueLen ); /*lint !e9079 Allow casting void* to other types. */

        if( NULL == xTemplate.pValue )
        {
            xResult = ( BaseType_t ) CKR_HOST_MEMORY;
        }
    }

    /* Export the certificate. */
    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pxTlsContext->pxP11FunctionList->C_GetAttributeValue( pxTlsContext->xP11Session,
                                                                                       xCertObj,
                                                                                       &xTemplate,
                                                                                       1 );
    }

    /* const uint8_t clientCert[] = */
    /* { */
    /*     0x30, 0x82, 0x01, 0xa8, 0x30, 0x82, 0x01, 0x4f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x49, 0x1b, 0x38, 0x31, 0x0b, 0x69, 0x6b, 0x26, 0x6b, 0xf2, 0x4d, 0x1b, 0xf3, 0x28, 0xf1, 0x80, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x34, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x46, 0x46, 0x46, 0x46, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x37, 0x30, 0x38, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x33, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x33, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x30, 0x31, 0x32, 0x33, 0x30, 0x36, 0x32, 0x42, 0x31, 0x31, 0x33, 0x33, 0x43, 0x41, 0x41, 0x45, 0x45, 0x45, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x46, 0x52, 0x27, 0xa7, 0x2c, 0x56, 0x5b, 0x78, 0xd9, 0x64, 0x9a, 0xfc, 0x74, 0xa2, 0x61, 0xb7, 0x86, 0x13, 0x8a, 0x59, 0x4e, 0x23, 0xbb, 0x21, 0x42, 0xc0, 0x41, 0x4a, 0x77, 0xf6, 0x7c, 0xa5, 0xed, 0xc8, 0x7e, 0xb8, 0x14, 0x16, 0x32, 0x49, 0xb8, 0x55, 0x91, 0xd3, 0xd1, 0x9a, 0x99, 0x2e, 0xb1, 0x0f, 0xea, 0xae, 0x62, 0xe7, 0xda, 0xc3, 0x1d, 0xc9, 0xca, 0xe7, 0x21, 0x52, 0xaa, 0x44, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xfb, 0xf3, 0x3a, 0x32, 0xbf, 0x4d, 0x2a, 0x16, 0xfa, 0xe0, 0xa3, 0xf3, 0x47, 0xc4, 0x50, 0xb4, 0xff, 0xab, 0xee, 0x88, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6d, 0x75, 0x2a, 0xe9, 0x06, 0xfd, 0xeb, 0xf4, 0x55, 0x88, 0x2d, 0xc1, 0x6d, 0x04, 0x58, 0x06, 0x28, 0x2e, 0x7a, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x35, 0x83, 0xf0, 0x27, 0x49, 0xc4, 0x93, 0x5c, 0x00, 0xf1, 0xcf, 0xdf, 0xb0, 0x30, 0x71, 0x32, 0xaf, 0x2e, 0xef, 0xb8, 0x0e, 0xf1, 0x3c, 0x1e, 0x84, 0xf6, 0xa9, 0x48, 0xd3, 0xa4, 0xc8, 0x37, 0x02, 0x20, 0x3f, 0xf4, 0xb6, 0x4a, 0xe0, 0xa4, 0x16, 0x4f, 0xea, 0x2f, 0xf6, 0xff, 0x8f, 0x02, 0xfe, 0xf9, 0xf7, 0x8b, 0x61, 0x66, 0xf1, 0xf6, 0x86, 0xf1, 0xf9, 0x66, 0x0a, 0x1b, 0x7c, 0xef, 0x62, 0x04 */
    /* }; */


    const uint8_t clientCert[] =
    {
        0x30, 0x82, 0x01, 0xaa, 0x30, 0x82, 0x01, 0x4f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x45, 0x07, 0x50, 0x23, 0x9e, 0x33, 0x0b, 0x1d, 0x08, 0xe7, 0xce, 0xe4, 0x30, 0xf9, 0x50, 0x9a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x34, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x46, 0x46, 0x46, 0x46, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x37, 0x30, 0x39, 0x31, 0x38, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x33, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x33, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x30, 0x31, 0x32, 0x33, 0x35, 0x42, 0x42, 0x39, 0x36, 0x36, 0x45, 0x44, 0x36, 0x42, 0x32, 0x41, 0x45, 0x45, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x64, 0x83, 0xe0, 0x6f, 0x0a, 0xed, 0x41, 0xc8, 0x7e, 0xc1, 0xba, 0x6b, 0xd2, 0xff, 0x5a, 0x8b, 0xb6, 0x96, 0xcc, 0x4c, 0x9b, 0xf6, 0x76, 0x77, 0xb3, 0xa1, 0x5c, 0x1f, 0x8e, 0x61, 0xaf, 0x69, 0x19, 0xb3, 0xb3, 0xf1, 0x7e, 0xe8, 0xea, 0x10, 0xa4, 0x1e, 0x80, 0x1c, 0x7c, 0xcc, 0x59, 0xcf, 0x54, 0xe9, 0x55, 0x7f, 0x8a, 0xd5, 0x45, 0x68, 0x2b, 0x43, 0x94, 0xc9, 0x38, 0x8b, 0x12, 0x92, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x71, 0xa4, 0x41, 0x59, 0x2c, 0x17, 0xe1, 0x08, 0x5b, 0x07, 0x7a, 0x63, 0xbe, 0x94, 0xb0, 0x0c, 0x40, 0x12, 0xac, 0xee, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6d, 0x75, 0x2a, 0xe9, 0x06, 0xfd, 0xeb, 0xf4, 0x55, 0x88, 0x2d, 0xc1, 0x6d, 0x04, 0x58, 0x06, 0x28, 0x2e, 0x7a, 0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xe6, 0x3d, 0xd5, 0xf1, 0xa1, 0xff, 0xfb, 0x27, 0xe0, 0x72, 0x6c, 0xf5, 0x85, 0x34, 0x12, 0x7c, 0xc9, 0x29, 0xca, 0xfa, 0x10, 0x9b, 0x9c, 0xe5, 0xaa, 0xf0, 0xee, 0xe9, 0x71, 0xba, 0x23, 0xdd, 0x02, 0x21, 0x00, 0xa8, 0x86, 0x61, 0xa5, 0xc5, 0x84, 0xaa, 0x4c, 0x35, 0xfb, 0x15, 0x28, 0xb1, 0xb6, 0x44, 0xaf, 0x0c, 0xde, 0xa6, 0x5c, 0xda, 0xc6, 0x68, 0xdd, 0x2b, 0x9d, 0xf4, 0x99, 0xb2, 0x40, 0x05, 0xca
    };

    uint8_t * certFromPkcs11 = ( uint8_t * ) xTemplate.pValue;
    TLS_PRINT( ( "Some bytes from device certificate:\nBeginning: 0x%02x 0x%02x 0x%02x\n End: 0x%02x 0x%02x 0x%02x\n",
                 certFromPkcs11[ 0 ], certFromPkcs11[ 1 ], certFromPkcs11[ 2 ],
                 certFromPkcs11[ xTemplate.ulValueLen - 3 ], certFromPkcs11[ xTemplate.ulValueLen - 2 ], certFromPkcs11[ xTemplate.ulValueLen - 1 ] ) );

    /* Decode the certificate. */
    if( 0 == xResult )
    {
        xResult = mbedtls_x509_crt_parse( pxCertificateContext,
                                          ( const unsigned char * ) xTemplate.pValue,
                                          xTemplate.ulValueLen );
        xResult = mbedtls_x509_crt_parse( pxCertificateContext,
                                          ( const unsigned char * ) clientCert,
                                          sizeof( clientCert ) );
    }

    /* Free memory. */
    if( NULL != xTemplate.pValue )
    {
        vPortFree( xTemplate.pValue );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/**
 * @brief Helper for setting up potentially hardware-based cryptographic context
 * for the client TLS certificate and private key.
 *
 * @param Caller context.
 *
 * @return Zero on success.
 */
static int prvInitializeClientCredential( TLSContext_t * pxCtx )
{
    BaseType_t xResult = CKR_OK;
    CK_ATTRIBUTE xTemplate[ 2 ];
    mbedtls_pk_type_t xKeyAlgo = ( mbedtls_pk_type_t ) ~0;
    char * pcJitrCertificate = keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM;

    /* Initialize the mbed contexts. */
    mbedtls_x509_crt_init( &pxCtx->xMbedX509Cli );

    if( pxCtx->xP11Session == CK_INVALID_HANDLE )
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
        TLS_PRINT( ( "Error: PKCS #11 session was not initialized.\r\n" ) );
    }

    /* Put the module in authenticated mode. */
    if( CKR_OK == xResult )
    {
        pxCtx->xTLSHandshakeState = TLS_HANDSHAKE_STARTED;
        xResult = ( BaseType_t ) pxCtx->pxP11FunctionList->C_Login( pxCtx->xP11Session,
                                                                    CKU_USER,
                                                                    ( CK_UTF8CHAR_PTR ) configPKCS11_DEFAULT_USER_PIN,
                                                                    sizeof( configPKCS11_DEFAULT_USER_PIN ) - 1 );
    }

    if( CKR_OK == xResult )
    {
        /* Get the handle of the device private key. */
        xResult = xFindObjectWithLabelAndClass( pxCtx->xP11Session,
                                                pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                                sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) - 1,
                                                CKO_PRIVATE_KEY,
                                                &pxCtx->xP11PrivateKey );
    }

    if( ( CKR_OK == xResult ) && ( pxCtx->xP11PrivateKey == CK_INVALID_HANDLE ) )
    {
        xResult = TLS_ERROR_NO_PRIVATE_KEY;
        TLS_PRINT( ( "ERROR: Private key not found. " ) );
    }

    /* Query the device private key type. */
    if( xResult == CKR_OK )
    {
        xTemplate[ 0 ].type = CKA_KEY_TYPE;
        xTemplate[ 0 ].pValue = &pxCtx->xKeyType;
        xTemplate[ 0 ].ulValueLen = sizeof( CK_KEY_TYPE );
        xResult = pxCtx->pxP11FunctionList->C_GetAttributeValue( pxCtx->xP11Session,
                                                                 pxCtx->xP11PrivateKey,
                                                                 xTemplate,
                                                                 1 );
    }

    /* Map the PKCS #11 key type to an mbedTLS algorithm. */
    if( xResult == CKR_OK )
    {
        switch( pxCtx->xKeyType )
        {
            case CKK_RSA:
                xKeyAlgo = MBEDTLS_PK_RSA;
                break;

            case CKK_EC:
                xKeyAlgo = MBEDTLS_PK_ECKEY;
                break;

            default:
                xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
        }
    }

    /* Map the mbedTLS algorithm to its internal metadata. */
    if( xResult == CKR_OK )
    {
        memcpy( &pxCtx->xMbedPkInfo, mbedtls_pk_info_from_type( xKeyAlgo ), sizeof( mbedtls_pk_info_t ) );

        pxCtx->xMbedPkInfo.sign_func = prvPrivateKeySigningCallback;
        pxCtx->xMbedPkCtx.pk_info = &pxCtx->xMbedPkInfo;
        pxCtx->xMbedPkCtx.pk_ctx = pxCtx;
    }

    /* Get the handle of the device client certificate. */
    if( xResult == CKR_OK )
    {
        xResult = prvReadCertificateIntoContext( pxCtx,
                                                 pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                                 CKO_CERTIFICATE,
                                                 &pxCtx->xMbedX509Cli );
    }

    /* Add a Just-in-Time Registration (JITR) device issuer certificate, if
     * present, to the TLS context handle. */
    /* if( xResult == CKR_OK ) */
    /* { */
    /*     / * Prioritize a statically defined certificate over one in storage. * / */
    /*     if( ( NULL != pcJitrCertificate ) && */
    /*         ( 0 != strcmp( "", pcJitrCertificate ) ) ) */
    /*     { */
    /*         xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509Cli, */
    /*                                           ( const unsigned char * ) pcJitrCertificate, */
    /*                                           1 + strlen( pcJitrCertificate ) ); */
    /*     } */
    /*     else */
    /*     { */
    /*         / * Check for a device JITR certificate in storage. * / */
    /*         xResult = prvReadCertificateIntoContext( pxCtx, */
    /*                                                  pkcs11configLABEL_JITP_CERTIFICATE, */
    /*                                                  CKO_CERTIFICATE, */
    /*                                                  &pxCtx->xMbedX509Cli ); */

    /*         / * It is optional to have a JITR certificate in storage. * / */
    /*         if( CKR_OBJECT_HANDLE_INVALID == xResult ) */
    /*         { */
    /*             xResult = CKR_OK; */
    /*         } */
    /*     } */
    /* } */

    /* Attach the client certificate(s) and private key to the TLS configuration. */
    if( 0 == xResult )
    {
        xResult = mbedtls_ssl_conf_own_cert( &pxCtx->xMbedSslConfig,
                                             &pxCtx->xMbedX509Cli,
                                             &pxCtx->xMbedPkCtx );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

/**
 * @brief Helper to seed the entropy module used by the DRBG. Periodically this
 * this function will be called to get more random data from the TRNG.
 *
 * @param[in] tlsContext The TLS context.
 * @param[out] outputBuffer The output buffer to return the generated random data.
 * @param[in] outputBufferLength Length of the output buffer.
 *
 * @return Zero on success, otherwise a negative error code telling the cause of the error.
 */
static int prvEntropyCallback( void * tlsContext,
                               unsigned char * outputBuffer,
                               size_t outputBufferLength )
{
    int ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    CK_RV xResult = CKR_OK;
    TLSContext_t * pxCtx = ( TLSContext_t * ) tlsContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( pxCtx->xP11Session != CK_INVALID_HANDLE )
    {
        xResult = C_GenerateRandom( pxCtx->xP11Session,
                                    outputBuffer,
                                    outputBufferLength );
    }
    else
    {
        xResult = CKR_SESSION_HANDLE_INVALID;
        TLS_PRINT( ( "Error: PKCS #11 session was not initialized.\r\n" ) );
    }

    if( xResult == CKR_OK )
    {
        ret = 0;
    }
    else
    {
        TLS_PRINT( ( "Error: PKCS #11 C_GenerateRandom failed with error code:" \
                     "%d\r\n", xResult ) );
    }

    return ret;
}

/*
 * Interface routines.
 */

BaseType_t TLS_Init( void ** ppvContext,
                     TLSParams_t * pxParams )
{
    BaseType_t xResult = CKR_OK;
    int mbedTLSResult = 0;
    TLSContext_t * pxCtx = NULL;
    CK_C_GetFunctionList xCkGetFunctionList = NULL;

    /* Allocate an internal context. */
    pxCtx = ( TLSContext_t * ) pvPortMalloc( sizeof( TLSContext_t ) ); /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pxCtx )
    {
        memset( pxCtx, 0, sizeof( TLSContext_t ) );
        *ppvContext = pxCtx;

        /* Initialize the context. */
        pxCtx->pcDestination = pxParams->pcDestination;
        pxCtx->pcServerCertificate = pxParams->pcServerCertificate;
        pxCtx->ulServerCertificateLength = pxParams->ulServerCertificateLength;
        pxCtx->ppcAlpnProtocols = pxParams->ppcAlpnProtocols;
        pxCtx->ulAlpnProtocolsCount = pxParams->ulAlpnProtocolsCount;
        pxCtx->xNetworkRecv = pxParams->pxNetworkRecv;
        pxCtx->xNetworkSend = pxParams->pxNetworkSend;
        pxCtx->pvCallerContext = pxParams->pvCallerContext;

        /* Get the function pointer list for the PKCS#11 module. */
        xCkGetFunctionList = C_GetFunctionList;
        xResult = ( BaseType_t ) xCkGetFunctionList( &pxCtx->pxP11FunctionList );

        /* Ensure that the PKCS #11 module is initialized and create a session. */
        if( xResult == CKR_OK )
        {
            xResult = xInitializePkcs11Session( &pxCtx->xP11Session );

            /* It is ok if the module was previously initialized. */
            if( xResult == CKR_CRYPTOKI_ALREADY_INITIALIZED )
            {
                xResult = CKR_OK;
            }
        }

        if( xResult == CKR_OK )
        {
            mbedtls_ctr_drbg_init( &pxCtx->xMbedDrbgCtx );
            mbedTLSResult = mbedtls_ctr_drbg_seed( &pxCtx->xMbedDrbgCtx,
                                                   prvEntropyCallback,
                                                   pxCtx,
                                                   NULL,
                                                   0 );

            if( 0 != mbedTLSResult )
            {
                TLS_PRINT( ( "ERROR: Failed to setup DRBG seed %s : %s \r\n",
                             mbedtlsHighLevelCodeOrDefault( mbedTLSResult ),
                             mbedtlsLowLevelCodeOrDefault( mbedTLSResult ) ) );
                xResult = CKR_FUNCTION_FAILED;
            }
        }
    }
    else
    {
        xResult = ( BaseType_t ) CKR_HOST_MEMORY;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

#ifdef MBEDTLS_DEBUG_C
    static void prvTlsDebugPrint( void * ctx,
                                  int lLevel,
                                  const char * pcFile,
                                  int lLine,
                                  const char * pcStr )
    {
        /* Unused parameters. */
        ( void ) ctx;
        ( void ) pcFile;
        ( void ) lLine;

        /* Send the debug string to the portable logger. */
        vLoggingPrintf( "mbedTLS: |%d| %s", lLevel, pcStr );
    }
#endif /* ifdef MBEDTLS_DEBUG_C */

/*-----------------------------------------------------------*/

BaseType_t TLS_Connect( void * pvContext )
{
    BaseType_t xResult = 0;
    CK_RV xPKCSResult = CKR_OK;
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    /* Initialize mbedTLS structures. */
    mbedtls_ssl_init( &pxCtx->xMbedSslCtx );
    mbedtls_ssl_config_init( &pxCtx->xMbedSslConfig );
    mbedtls_x509_crt_init( &pxCtx->xMbedX509CA );

    /* Decode the root certificate: either the default or the override. */
    if( NULL != pxCtx->pcServerCertificate )
    {
        xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509CA,
                                          ( const unsigned char * ) pxCtx->pcServerCertificate,
                                          pxCtx->ulServerCertificateLength );

        if( 0 != xResult )
        {
            TLS_PRINT( ( "ERROR: Failed to parse custom server certificates %s : %s \r\n",
                         mbedtlsHighLevelCodeOrDefault( xResult ),
                         mbedtlsLowLevelCodeOrDefault( xResult ) ) );
        }
    }
    else
    {
        xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509CA,
                                          ( const unsigned char * ) tlsVERISIGN_ROOT_CERTIFICATE_PEM,
                                          tlsVERISIGN_ROOT_CERTIFICATE_LENGTH );

        if( 0 == xResult )
        {
            xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509CA,
                                              ( const unsigned char * ) tlsATS1_ROOT_CERTIFICATE_PEM,
                                              tlsATS1_ROOT_CERTIFICATE_LENGTH );

            if( 0 == xResult )
            {
                xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509CA,
                                                  ( const unsigned char * ) tlsATS3_ROOT_CERTIFICATE_PEM,
                                                  tlsATS3_ROOT_CERTIFICATE_LENGTH );

                if( 0 == xResult )
                {
                    xResult = mbedtls_x509_crt_parse( &pxCtx->xMbedX509CA,
                                                      ( const unsigned char * ) tlsSTARFIELD_ROOT_CERTIFICATE_PEM,
                                                      tlsSTARFIELD_ROOT_CERTIFICATE_LENGTH );
                }
            }
        }

        if( 0 != xResult )
        {
            /* Default root certificates should be in aws_default_root_certificate.h */
            TLS_PRINT( ( "ERROR: Failed to parse default server certificates %s : %s \r\n",
                         mbedtlsHighLevelCodeOrDefault( xResult ),
                         mbedtlsLowLevelCodeOrDefault( xResult ) ) );
        }
    }

    /* Start with protocol defaults. */
    if( 0 == xResult )
    {
        xResult = mbedtls_ssl_config_defaults( &pxCtx->xMbedSslConfig,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT );

        if( 0 != xResult )
        {
            TLS_PRINT( ( "ERROR: Failed to set ssl config defaults %s : %s \r\n",
                         mbedtlsHighLevelCodeOrDefault( xResult ),
                         mbedtlsLowLevelCodeOrDefault( xResult ) ) );
        }
    }

    if( 0 == xResult )
    {
        /* Use a callback for additional server certificate validation. */
        mbedtls_ssl_conf_verify( &pxCtx->xMbedSslConfig,
                                 &prvCheckCertificate,
                                 pxCtx );

        /* Server certificate validation is mandatory. */
        mbedtls_ssl_conf_authmode( &pxCtx->xMbedSslConfig, MBEDTLS_SSL_VERIFY_REQUIRED );

        /* Set the RNG callback. */
        mbedtls_ssl_conf_rng( &pxCtx->xMbedSslConfig, &prvGenerateRandomBytes, pxCtx ); /*lint !e546 Nothing wrong here. */

        /* Set issuer certificate. */
        mbedtls_ssl_conf_ca_chain( &pxCtx->xMbedSslConfig, &pxCtx->xMbedX509CA, NULL );

        /* Configure the SSL context to contain device credentials (eg device cert
         * and private key) obtained from the PKCS #11 layer.  The result of
         * loading device key and certificate is placed in a separate variable
         * (xPKCSResult instead of xResult). The reason is that we want to
         * attempt TLS handshake, even if the device key and certificate
         * are not loaded. This allows the TLS layer to still connect to servers
         * that do not require mutual authentication. If the server does
         * require mutual authentication, the handshake will fail. */
        xPKCSResult = prvInitializeClientCredential( pxCtx );
    }

    if( ( 0 == xResult ) && ( NULL != pxCtx->ppcAlpnProtocols ) )
    {
        /* Include an application protocol list in the TLS ClientHello
         * message. */
        xResult = mbedtls_ssl_conf_alpn_protocols(
            &pxCtx->xMbedSslConfig,
            pxCtx->ppcAlpnProtocols );
    }

    #ifdef MBEDTLS_DEBUG_C

        /* If mbedTLS is being compiled with debug support, assume that the
         * runtime configuration should use verbose output. */
        mbedtls_ssl_conf_dbg( &pxCtx->xMbedSslConfig, prvTlsDebugPrint, NULL );
        mbedtls_debug_set_threshold( tlsDEBUG_VERBOSE );
    #endif

    if( 0 == xResult )
    {
        /* Set the resulting protocol configuration. */
        xResult = mbedtls_ssl_setup( &pxCtx->xMbedSslCtx, &pxCtx->xMbedSslConfig );
    }

    #ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
        if( 0 == xResult )
        {
            /* Enable the max fragment extension. 4096 bytes is currently the largest fragment size permitted.
             * See RFC 8449 https://tools.ietf.org/html/rfc8449 for more information.
             *
             * Smaller values can be found in "mbedtls/include/ssl.h".
             */
            xResult = mbedtls_ssl_conf_max_frag_len( &pxCtx->xMbedSslConfig, MBEDTLS_SSL_MAX_FRAG_LEN_4096 );
        }
    #endif

    /* Set the hostname, if requested. */
    if( ( 0 == xResult ) && ( NULL != pxCtx->pcDestination ) )
    {
        xResult = mbedtls_ssl_set_hostname( &pxCtx->xMbedSslCtx, pxCtx->pcDestination );
    }

    /* Set the socket callbacks. */
    if( 0 == xResult )
    {
        mbedtls_ssl_set_bio( &pxCtx->xMbedSslCtx,
                             pxCtx,
                             prvNetworkSend,
                             prvNetworkRecv,
                             NULL );

        /* Negotiate. */
        while( 0 != ( xResult = mbedtls_ssl_handshake( &pxCtx->xMbedSslCtx ) ) )
        {
            if( ( MBEDTLS_ERR_SSL_WANT_READ != xResult ) &&
                ( MBEDTLS_ERR_SSL_WANT_WRITE != xResult ) )
            {
                /* There was an unexpected error. Per mbedTLS API documentation,
                 * ensure that upstream clean-up code doesn't accidentally use
                 * a context that failed the handshake. */
                prvFreeContext( pxCtx );

                if( xPKCSResult != CKR_OK )
                {
                    TLS_PRINT( ( "ERROR: The handshake failed and it is likely "
                                 "due to a failure in PKCS #11. Consider enabling "
                                 "error logging in PKCS #11 or checking if your device "
                                 "is properly provisioned with client credentials. "
                                 "PKCS #11 error=0x(%0X). TLS handshake error=%s : %s \r\n",
                                 xPKCSResult,
                                 mbedtlsHighLevelCodeOrDefault( xResult ),
                                 mbedtlsLowLevelCodeOrDefault( xResult ) ) );
                }
                else
                {
                    TLS_PRINT( ( "ERROR: TLS handshake failed trying to connect. %s : %s \r\n",
                                 mbedtlsHighLevelCodeOrDefault( xResult ),
                                 mbedtlsLowLevelCodeOrDefault( xResult ) ) );
                }

                break;
            }
        }
    }

    /* Keep track of successful completion of the handshake. */
    if( 0 == xResult )
    {
        pxCtx->xTLSHandshakeState = TLS_HANDSHAKE_SUCCESSFUL;
    }
    else if( xResult > 0 )
    {
        TLS_PRINT( ( "ERROR: TLS_Connect failed with error code %d \r\n", xResult ) );
        /* Convert PKCS #11 failures to a negative error code. */
        xResult = TLS_ERROR_HANDSHAKE_FAILED;
    }

    /* Free up allocated memory. */
    mbedtls_x509_crt_free( &pxCtx->xMbedX509CA );
    mbedtls_x509_crt_free( &pxCtx->xMbedX509Cli );

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Recv( void * pvContext,
                     unsigned char * pucReadBuffer,
                     size_t xReadLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xRead = 0;

    if( ( NULL != pxCtx ) && ( TLS_HANDSHAKE_SUCCESSFUL == pxCtx->xTLSHandshakeState ) )
    {
        /* This routine will return however many bytes are returned from from mbedtls_ssl_read
         * immediately unless MBEDTLS_ERR_SSL_WANT_READ is returned, in which case we try again. */
        do
        {
            xResult = mbedtls_ssl_read( &pxCtx->xMbedSslCtx,
                                        pucReadBuffer + xRead,
                                        xReadLength - xRead );

            if( xResult > 0 )
            {
                /* Got data, so update the tally and keep looping. */
                xRead += ( size_t ) xResult;
            }

            /* If xResult == 0, then no data was received (and there is no error).
             * The secure sockets API supports non-blocking read, so stop the loop,
             * but don't flag an error. */
        } while( ( xResult == MBEDTLS_ERR_SSL_WANT_READ ) );
    }
    else
    {
        xResult = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if( xResult >= 0 )
    {
        xResult = ( BaseType_t ) xRead;
    }
    else
    {
        /* xResult < 0 is a hard error, so invalidate the context and stop. */
        prvFreeContext( pxCtx );
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Send( void * pvContext,
                     const unsigned char * pucMsg,
                     size_t xMsgLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xWritten = 0;

    if( ( NULL != pxCtx ) && ( TLS_HANDSHAKE_SUCCESSFUL == pxCtx->xTLSHandshakeState ) )
    {
        while( xWritten < xMsgLength )
        {
            xResult = mbedtls_ssl_write( &pxCtx->xMbedSslCtx,
                                         pucMsg + xWritten,
                                         xMsgLength - xWritten );

            if( 0 < xResult )
            {
                /* Sent data, so update the tally and keep looping. */
                xWritten += ( size_t ) xResult;
            }
            else if( ( 0 == xResult ) || ( -pdFREERTOS_ERRNO_ENOSPC == xResult ) )
            {
                /* No data sent. The secure sockets
                 * API supports non-blocking send, so stop the loop but don't
                 * flag an error. */
                xResult = 0;
                break;
            }
            else if( MBEDTLS_ERR_SSL_WANT_WRITE != xResult )
            {
                /* Hard error: invalidate the context and stop. */
                prvFreeContext( pxCtx );
                break;
            }
        }
    }
    else
    {
        xResult = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if( 0 <= xResult )
    {
        xResult = ( BaseType_t ) xWritten;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

void TLS_Cleanup( void * pvContext )
{
    TLSContext_t * pxCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pxCtx )
    {
        prvFreeContext( pxCtx );

        /* Free memory. */
        vPortFree( pxCtx );
    }
}

/*-----------------------------------------------------------*/

void TLS_setDateIsInThePastFunction( DateIsInThePast_t DateIsInThePast )
{
    pDateIsInThePast = DateIsInThePast;
}
