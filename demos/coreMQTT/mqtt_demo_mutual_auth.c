/*
 * FreeRTOS V202010.00
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
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 */

/*
 * Demo for showing use of the MQTT API using a mutually authenticated
 * network connection.
 *
 * The Example shown below uses MQTT APIs to create MQTT messages and send them
 * over the mutually authenticated network connection established with the
 * MQTT broker. This example is single threaded and uses statically allocated
 * memory. It uses QoS1 for sending to and receiving messages from the broker.
 *
 * A mutually authenticated TLS connection is used to connect to the
 * MQTT message broker in this example. Define democonfigMQTT_BROKER_ENDPOINT,
 * democonfigROOT_CA_PEM, democonfigCLIENT_CERTIFICATE_PEM,
 * and democonfigCLIENT_PRIVATE_KEY_PEM in mqtt_demo_mutual_auth_config.h to establish a
 * mutually authenticated connection.
 */

/**
 * @file mqtt_demo_mutual_auth.c
 * @brief Demonstrates usage of the MQTT library.
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Demo Specific configs. */
#include "mqtt_demo_mutual_auth_config.h"

/* Include common demo header. */
#include "aws_demo.h"

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* Retry utilities include. */
#include "retry_utils.h"

/* Transport interface implementation include header for TLS. */
#include "transport_secure_sockets.h"

/* Include header for connection configurations. */
#include "aws_clientcredential.h"

/* Include header for client credentials. */
#include "aws_clientcredential_keys.h"

/* Include header for root CA certificates. */
#include "iot_default_root_certificates.h"

/*------------- Demo configurations -------------------------*/

/** Note: The device client certificate and private key credentials are
 * obtained by the transport interface implementation (with Secure Sockets)
 * from the demos/include/aws_clientcredential_keys.h file.
 *
 * The following macros SHOULD be defined for this demo which uses both server
 * and client authentications for TLS session:
 *   - keyCLIENT_CERTIFICATE_PEM for client certificate.
 *   - keyCLIENT_PRIVATE_KEY_PEM for client private key.
 */

#ifndef democonfigMQTT_BROKER_ENDPOINT
    #define democonfigMQTT_BROKER_ENDPOINT    clientcredentialMQTT_BROKER_ENDPOINT
#endif

#ifndef democonfigROOT_CA_PEM
    #define democonfigROOT_CA_PEM    tlsATS1_ROOT_CERTIFICATE_PEM
#endif
static uint8_t rootCADer[] = { 48, 130, 3, 65, 48, 130, 2, 41, 160, 3, 2, 1, 2, 2, 19, 6, 108, 159, 207, 153, 191, 140, 10, 57, 226, 240, 120, 138, 67, 230, 150, 54, 91, 202, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 57, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15, 48, 13, 6, 3, 85, 4, 10, 19, 6, 65, 109, 97, 122, 111, 110, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 65, 109, 97, 122, 111, 110, 32, 82, 111, 111, 116, 32, 67, 65, 32, 49, 48, 30, 23, 13, 49, 53, 48, 53, 50, 54, 48, 48, 48, 48, 48, 48, 90, 23, 13, 51, 56, 48, 49, 49, 55, 48, 48, 48, 48, 48, 48, 90, 48, 57, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15, 48, 13, 6, 3, 85, 4, 10, 19, 6, 65, 109, 97, 122, 111, 110, 49, 25, 48, 23, 6, 3, 85, 4, 3, 19, 16, 65, 109, 97, 122, 111, 110, 32, 82, 111, 111, 116, 32, 67, 65, 32, 49, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 178, 120, 128, 113, 202, 120, 213, 227, 113, 175, 71, 128, 80, 116, 125, 110, 216, 215, 136, 118, 244, 153, 104, 247, 88, 33, 96, 249, 116, 132, 1, 47, 172, 2, 45, 134, 211, 160, 67, 122, 78, 178, 164, 208, 54, 186, 1, 190, 141, 219, 72, 200, 7, 23, 54, 76, 244, 238, 136, 35, 199, 62, 235, 55, 245, 181, 25, 248, 73, 104, 176, 222, 215, 185, 118, 56, 29, 97, 158, 164, 254, 130, 54, 165, 229, 74, 86, 228, 69, 225, 249, 253, 180, 22, 250, 116, 218, 156, 155, 53, 57, 47, 250, 176, 32, 80, 6, 108, 122, 208, 128, 178, 166, 249, 175, 236, 71, 25, 143, 80, 56, 7, 220, 162, 135, 57, 88, 248, 186, 213, 169, 249, 72, 103, 48, 150, 238, 148, 120, 94, 111, 137, 163, 81, 192, 48, 134, 102, 161, 69, 102, 186, 84, 235, 163, 195, 145, 249, 72, 220, 255, 209, 232, 48, 45, 125, 45, 116, 112, 53, 215, 136, 36, 247, 158, 196, 89, 110, 187, 115, 135, 23, 242, 50, 70, 40, 184, 67, 250, 183, 29, 170, 202, 180, 242, 159, 36, 14, 45, 75, 247, 113, 92, 94, 105, 255, 234, 149, 2, 203, 56, 138, 174, 80, 56, 111, 219, 251, 45, 98, 27, 197, 199, 30, 84, 225, 119, 224, 103, 200, 15, 156, 135, 35, 214, 63, 64, 32, 127, 32, 128, 196, 128, 76, 62, 59, 36, 38, 142, 4, 174, 108, 154, 200, 170, 13, 2, 3, 1, 0, 1, 163, 66, 48, 64, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 132, 24, 204, 133, 52, 236, 188, 12, 148, 148, 46, 8, 89, 156, 199, 178, 16, 78, 10, 8, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 152, 242, 55, 90, 65, 144, 161, 26, 197, 118, 81, 40, 32, 54, 35, 14, 174, 230, 40, 187, 170, 248, 148, 174, 72, 164, 48, 127, 27, 252, 36, 141, 75, 180, 200, 161, 151, 246, 182, 241, 122, 112, 200, 83, 147, 204, 8, 40, 227, 152, 37, 207, 35, 164, 249, 222, 33, 211, 124, 133, 9, 173, 78, 154, 117, 58, 194, 11, 106, 137, 120, 118, 68, 71, 24, 101, 108, 141, 65, 142, 59, 127, 154, 203, 244, 181, 167, 80, 215, 5, 44, 55, 232, 3, 75, 173, 233, 97, 160, 2, 110, 245, 242, 240, 197, 178, 237, 91, 183, 220, 250, 148, 92, 119, 158, 19, 165, 127, 82, 173, 149, 242, 248, 147, 59, 222, 139, 92, 91, 202, 90, 82, 91, 96, 175, 20, 247, 75, 239, 163, 251, 159, 64, 149, 109, 49, 84, 252, 66, 211, 199, 70, 31, 35, 173, 217, 15, 72, 112, 154, 217, 117, 120, 113, 209, 114, 67, 52, 117, 110, 87, 89, 194, 2, 92, 38, 96, 41, 207, 35, 25, 22, 142, 136, 67, 165, 212, 228, 203, 8, 251, 35, 17, 67, 232, 67, 41, 114, 98, 161, 169, 93, 94, 8, 212, 144, 174, 184, 216, 206, 20, 194, 208, 85, 242, 134, 246, 196, 147, 67, 119, 102, 97, 192, 185, 232, 65, 215, 151, 120, 96, 3, 110, 74, 114, 174, 165, 209, 125, 186, 16, 158, 134, 108, 27, 138, 185, 89, 51, 248, 235, 196, 144, 190, 241, 185 };
static size_t rootCADerSize = sizeof( rootCADer );
/* This function can be found in libraries/3rdparty/mbedtls_utils/mbedtls_utils.c. */
extern int convert_pem_to_der( const unsigned char * pucInput,
                               size_t xLen,
                               unsigned char * pucOutput,
                               size_t * pxOlen );

#ifndef democonfigCLIENT_IDENTIFIER

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique so edit as required to ensure no two clients connecting to the
 * same broker use the same client identifier.
 */
    #define democonfigCLIENT_IDENTIFIER    clientcredentialIOT_THING_NAME
#endif

#ifndef democonfigMQTT_BROKER_PORT

/**
 * @brief The port to use for the demo.
 */
    #define democonfigMQTT_BROKER_PORT    clientcredentialMQTT_BROKER_PORT
#endif

/**
 * @brief The maximum number of times to run the subscribe publish loop in this
 * demo.
 */
#ifndef democonfigMQTT_MAX_DEMO_COUNT
    #define democonfigMQTT_MAX_DEMO_COUNT    ( 3 )
#endif
/*-----------------------------------------------------------*/

/**
 * @brief Timeout for receiving CONNACK packet in milliseconds.
 */
#define mqttexampleCONNACK_RECV_TIMEOUT_MS                ( 1000U )

/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define mqttexampleTOPIC                                  democonfigCLIENT_IDENTIFIER "/example/topic"

/**
 * @brief The number of topic filters to subscribe.
 */
#define mqttexampleTOPIC_COUNT                            ( 1 )

/**
 * @brief The MQTT message published in this example.
 */
#define mqttexampleMESSAGE                                "Hello World!"

/**
 * @brief Time in ticks to wait between each cycle of the demo implemented
 * by RunCoreMqttMutualAuthDemo().
 */
#define mqttexampleDELAY_BETWEEN_DEMO_ITERATIONS_TICKS    ( pdMS_TO_TICKS( 5000U ) )

/**
 * @brief Timeout for MQTT_ProcessLoop in milliseconds.
 */
#define mqttexamplePROCESS_LOOP_TIMEOUT_MS                ( 500U )

/**
 * @brief Keep alive time reported to the broker while establishing
 * an MQTT connection.
 *
 * It is the responsibility of the Client to ensure that the interval between
 * Control Packets being sent does not exceed the this Keep Alive value. In the
 * absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS             ( 60U )

/**
 * @brief Delay (in ticks) between consecutive cycles of MQTT publish operations in a
 * demo iteration.
 *
 * Note that the process loop also has a timeout, so the total time between
 * publishes is the sum of the two delays.
 */
#define mqttexampleDELAY_BETWEEN_PUBLISHES_TICKS          ( pdMS_TO_TICKS( 2000U ) )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS         ( 200U )

/**
 * @brief Milliseconds per second.
 */
#define MILLISECONDS_PER_SECOND                           ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define MILLISECONDS_PER_TICK                             ( MILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

/*-----------------------------------------------------------*/

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pxNetworkContext The output parameter to return the created network context.
 *
 * @return pdFAIL on failure; pdPASS on successful TLS+TCP network connection.
 */
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief Sends an MQTT Connect packet over the already connected TLS over TCP connection.
 *
 * @param[in, out] pxMQTTContext MQTT context pointer.
 * @param[in] xNetworkContext Network context.
 *
 * @return pdFAIL on failure; pdPASS on successful MQTT connection.
 */
static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext );

/**
 * @brief Function to update variable #xTopicFilterContext with status
 * information from Subscribe ACK. Called by the event callback after processing
 * an incoming SUBACK packet.
 *
 * @param[in] Server response to the subscription request.
 */
static void prvUpdateSubAckStatus( MQTTPacketInfo_t * pxPacketInfo );

/**
 * @brief Subscribes to the topic as specified in mqttexampleTOPIC at the top of
 * this file. In the case of a Subscribe ACK failure, then subscription is
 * retried using an exponential backoff strategy with jitter.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful SUBSCRIBE request.
 */
static BaseType_t prvMQTTSubscribeWithBackoffRetries( MQTTContext_t * pxMQTTContext );

/**
 * @brief Publishes a message mqttexampleMESSAGE on mqttexampleTOPIC topic.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful PUBLISH operation.
 */
static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext );

/**
 * @brief Unsubscribes from the previously subscribed topic as specified
 * in mqttexampleTOPIC.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful UNSUBSCRIBE request.
 */
static BaseType_t prvMQTTUnsubscribeFromTopic( MQTTContext_t * pxMQTTContext );

/**
 * @brief The timer query function provided to the MQTT context.
 *
 * @return Time in milliseconds.
 */
static uint32_t prvGetTimeMs( void );

/**
 * @brief Process a response or ack to an MQTT request (PING, PUBLISH,
 * SUBSCRIBE or UNSUBSCRIBE). This function processes PINGRESP, PUBACK,
 * SUBACK, and UNSUBACK.
 *
 * @param[in] pxIncomingPacket is a pointer to structure containing deserialized
 * MQTT response.
 * @param[in] usPacketId is the packet identifier from the ack received.
 */
static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId );

/**
 * @brief Process incoming Publish message.
 *
 * @param[in] pxPublishInfo is a pointer to structure containing deserialized
 * Publish message.
 */
static void prvMQTTProcessIncomingPublish( MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief The application callback function for getting the incoming publishes,
 * incoming acks, and ping responses reported from the MQTT library.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] pxPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pxDeserializedInfo Deserialized information from the incoming packet.
 */
static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo );

/*-----------------------------------------------------------*/

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[ democonfigNETWORK_BUFFER_SIZE ];

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/**
 * @brief Packet Identifier generated when Publish request was sent to the broker;
 * it is used to match received Publish ACK to the transmitted Publish packet.
 */
static uint16_t usPublishPacketIdentifier;

/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker;
 * it is used to match received Subscribe ACK to the transmitted Subscribe packet.
 */
static uint16_t usSubscribePacketIdentifier;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker;
 * it is used to match received Unsubscribe response to the transmitted Unsubscribe
 * request.
 */
static uint16_t usUnsubscribePacketIdentifier;

/**
 * @brief A pair containing a topic filter and its SUBACK status.
 */
typedef struct topicFilterContext
{
    const char * pcTopicFilter;
    MQTTSubAckStatus_t xSubAckStatus;
} topicFilterContext_t;

/**
 * @brief An array containing the context of a SUBACK; the SUBACK status
 * of a filter is updated when the event callback processes a SUBACK.
 */
static topicFilterContext_t xTopicFilterContext[ mqttexampleTOPIC_COUNT ] =
{
    { mqttexampleTOPIC, MQTTSubAckFailure }
};


/** @brief Static buffer used to hold MQTT messages being sent and received. */
static MQTTFixedBuffer_t xBuffer =
{
    ucSharedBuffer,
    democonfigNETWORK_BUFFER_SIZE
};

/*-----------------------------------------------------------*/

/*
 * @brief The example shown below uses MQTT APIs to create MQTT messages and
 * send them over the mutually authenticated network connection established with the
 * MQTT broker. This example is single threaded and uses statically allocated
 * memory. It uses QoS1 for sending to and receiving messages from the broker.
 *
 * This MQTT client subscribes to the topic as specified in mqttexampleTOPIC at the
 * top of this file by sending a subscribe packet and then waiting for a subscribe
 * acknowledgment (SUBACK).This client will then publish to the same topic it
 * subscribed to, so it will expect all the messages it sends to the broker to be
 * sent back to it from the broker.
 *
 * This example runs for democonfigMQTT_MAX_DEMO_COUNT, if the
 * connection to the broker goes down, the code tries to reconnect to the broker
 * with an exponential backoff mechanism.
 */
int RunCoreMqttMutualAuthDemo( bool awsIotMqttMode,
                               const char * pIdentifier,
                               void * pNetworkServerInfo,
                               void * pNetworkCredentialInfo,
                               const IotNetworkInterface_t * pNetworkInterface )
{
    uint32_t ulPublishCount = 0U, ulTopicCount = 0U;
    const uint32_t ulMaxPublishCount = 5UL;
    NetworkContext_t xNetworkContext = { 0 };
    MQTTContext_t xMQTTContext = { 0 };
    MQTTStatus_t xMQTTStatus;
    uint32_t ulDemoRunCount = 0;
    TransportSocketStatus_t xNetworkStatus;
    BaseType_t xIsConnectionEstablished = pdFALSE;

    /* Upon return, pdPASS will indicate a successful demo execution.
    * pdFAIL will indicate some failures occurred during execution. The
    * user of this demo must check the logs for any failure codes. */
    BaseType_t xDemoStatus = pdPASS;

    /* Remove compiler warnings about unused parameters. */
    ( void ) awsIotMqttMode;
    ( void ) pIdentifier;
    ( void ) pNetworkServerInfo;
    ( void ) pNetworkCredentialInfo;
    ( void ) pNetworkInterface;

    /* Set the entry time of the demo application. This entry time will be used
     * to calculate relative time elapsed in the execution of the demo application,
     * by the timer utility function that is provided to the MQTT library.
     */
    ulGlobalEntryTimeMs = prvGetTimeMs();

    for( ; ulDemoRunCount < democonfigMQTT_MAX_DEMO_COUNT; ulDemoRunCount++ )
    {
        /****************************** Connect. ******************************/

        /* Attempt to establish TLS session with MQTT broker. If connection fails,
         * retry after a timeout. Timeout value will be exponentially increased until
         * the maximum number of attempts are reached or the maximum timeout value is reached.
         * The function returns a failure status if the TLS over TCP connection cannot be established
         * to the broker after the configured number of attempts. */
        xDemoStatus = prvConnectToServerWithBackoffRetries( &xNetworkContext );

        if( xDemoStatus == pdPASS )
        {
            /* Set a flag indicating a TLS connection exists. This is done to
             * disconnect if the loop exits before disconnection happens. */
            xIsConnectionEstablished = pdTRUE;

            /* Sends an MQTT Connect packet over the already established TLS connection,
             * and waits for connection acknowledgment (CONNACK) packet. */
            LogInfo( ( "Creating an MQTT connection to %s.", democonfigMQTT_BROKER_ENDPOINT ) );
            xDemoStatus = prvCreateMQTTConnectionWithBroker( &xMQTTContext, &xNetworkContext );
        }

        /**************************** Subscribe. ******************************/

        if( xDemoStatus == pdPASS )
        {
            /* If server rejected the subscription request, attempt to resubscribe to topic.
             * Attempts are made according to the exponential backoff retry strategy
             * implemented in retry_utils. */
            xDemoStatus = prvMQTTSubscribeWithBackoffRetries( &xMQTTContext );
        }

        /**************************** Publish and Keep Alive Loop. ******************************/

        /* Publish messages with QoS1, send and process Keep alive messages. */
        for( ulPublishCount = 0;
             ( ( xDemoStatus == pdPASS ) && ( ulPublishCount < ulMaxPublishCount ) );
             ulPublishCount++ )
        {
            LogInfo( ( "Publish to the MQTT topic %s.", mqttexampleTOPIC ) );
            xDemoStatus = prvMQTTPublishToTopic( &xMQTTContext );

            if( xDemoStatus == pdPASS )
            {
                /* Process incoming publish echo, since application subscribed to the same
                 * topic, the broker will send publish message back to the application. */
                LogInfo( ( "Attempt to receive publish message from broker." ) );
                xMQTTStatus = MQTT_ProcessLoop( &xMQTTContext, mqttexamplePROCESS_LOOP_TIMEOUT_MS );

                if( xMQTTStatus != MQTTSuccess )
                {
                    xDemoStatus = pdFAIL;
                    LogError( ( "MQTT_ProcessLoop failed: LoopDuration=%u, Error=%s",
                                mqttexamplePROCESS_LOOP_TIMEOUT_MS,
                                MQTT_Status_strerror( xMQTTStatus ) ) );
                }
            }

            /* Leave Connection Idle for some time. */
            LogInfo( ( "Keeping Connection Idle..." ) );
            vTaskDelay( mqttexampleDELAY_BETWEEN_PUBLISHES_TICKS );
        }

        /************************ Unsubscribe from the topic. **************************/

        if( xDemoStatus == pdPASS )
        {
            LogInfo( ( "Unsubscribe from the MQTT topic %s.", mqttexampleTOPIC ) );
            xDemoStatus = prvMQTTUnsubscribeFromTopic( &xMQTTContext );
        }

        if( xDemoStatus == pdPASS )
        {
            /* Process incoming UNSUBACK packet from the broker. */
            xMQTTStatus = MQTT_ProcessLoop( &xMQTTContext, mqttexamplePROCESS_LOOP_TIMEOUT_MS );

            if( xMQTTStatus != MQTTSuccess )
            {
                xDemoStatus = pdFAIL;
                LogError( ( "Failed to receive UNSUBACK packet from broker: ProcessLoopDuration=%u, Error=%s",
                            mqttexamplePROCESS_LOOP_TIMEOUT_MS,
                            MQTT_Status_strerror( xMQTTStatus ) ) );
            }
        }

        /**************************** Disconnect. ******************************/

        /* Send an MQTT Disconnect packet over the already connected TLS over TCP connection.
         * There is no corresponding response for the disconnect packet. After sending
         * disconnect, client must close the network connection. */
        LogInfo( ( "Disconnecting the MQTT connection with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xMQTTStatus = MQTT_Disconnect( &xMQTTContext );

        /* We will always close the network connection, even if an error may have occurred during
         * demo execution, to clean up the system resources that it may have consumed. */
        if( xIsConnectionEstablished == pdTRUE )
        {
            /* Close the network connection.  */
            xNetworkStatus = SecureSocketsTransport_Disconnect( &xNetworkContext );

            if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
            {
                xDemoStatus = pdFAIL;
                LogError( ( "SecureSocketsTransport_Disconnect() failed to close the network connection. "
                            "StatusCode=%d.", ( int ) xNetworkStatus ) );
            }
        }

        /* Reset SUBACK status for each topic filter after completion of subscription request cycle. */
        for( ulTopicCount = 0; ulTopicCount < mqttexampleTOPIC_COUNT; ulTopicCount++ )
        {
            xTopicFilterContext[ ulTopicCount ].xSubAckStatus = MQTTSubAckFailure;
        }

        if( xDemoStatus == pdPASS )
        {
            /* Wait for some time between two iterations to ensure that we do not
             * bombard the broker. */
            LogInfo( ( "Demo completed an iteration successfully." ) );
            LogInfo( ( "Demo iteration %lu completed successfully.", ( ulDemoRunCount + 1UL ) ) );
        }
        else
        {
            /* Terminate the demo due to failure. */
            LogInfo( ( "Demo failed at iteration %lu.", ( ulDemoRunCount + 1UL ) ) );
            LogInfo( ( "Exiting demo." ) );
            break;
        }

        LogInfo( ( "Short delay before starting the next iteration.... " ) );
        vTaskDelay( mqttexampleDELAY_BETWEEN_DEMO_ITERATIONS_TICKS );
    }

    return ( xDemoStatus == pdPASS ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
/*-----------------------------------------------------------*/

static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pxNetworkContext )
{
    ServerInfo_t xServerInfo = { 0 };
    SocketsConfig_t xSocketsConfig = { 0 };
    BaseType_t xStatus = pdPASS;
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;
    RetryUtilsStatus_t xRetryUtilsStatus = RetryUtilsSuccess;
    RetryUtilsParams_t xReconnectParams;

    /* Set the credentials for establishing a TLS connection. */
    /* Initializer server information. */
    xServerInfo.pHostName = democonfigMQTT_BROKER_ENDPOINT;
    xServerInfo.hostNameLength = strlen( democonfigMQTT_BROKER_ENDPOINT );
    xServerInfo.port = democonfigMQTT_BROKER_PORT;

    /* Configure credentials for TLS mutual authenticated session. */
    xSocketsConfig.enableTls = true;
    xSocketsConfig.pAlpnProtos = NULL;
    xSocketsConfig.maxFragmentLength = 0;
    xSocketsConfig.disableSni = true;

    /* if( convert_pem_to_der( democonfigROOT_CA_PEM, */
    /*                         strlen( democonfigROOT_CA_PEM ), */
    /*                         rootCADer, */
    /*                         &rootCADerSize ) != 0 ) */
    /* { */
    /*     LogError( ( "Failed to convert Root CA from PEM to DER" ) ); */
    /* } */

    xSocketsConfig.pRootCa = tlsATS1_ROOT_CERTIFICATE_PEM;
    xSocketsConfig.rootCaSize = sizeof( tlsATS1_ROOT_CERTIFICATE_PEM );
    xSocketsConfig.sendTimeoutMs = mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;
    xSocketsConfig.recvTimeoutMs = mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;

    /* Initialize reconnect attempts and interval. */
    RetryUtils_ParamsReset( &xReconnectParams );
    xReconnectParams.maxRetryAttempts = MAX_RETRY_ATTEMPTS;

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase till maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects to
         * the MQTT broker as specified in democonfigMQTT_BROKER_ENDPOINT and
         * democonfigMQTT_BROKER_PORT at the top of this file. */
        LogInfo( ( "Creating a TLS connection to %s:%u.",
                   democonfigMQTT_BROKER_ENDPOINT,
                   democonfigMQTT_BROKER_PORT ) );
        /* Attempt to create a mutually authenticated TLS connection. */
        xNetworkStatus = SecureSocketsTransport_Connect( pxNetworkContext,
                                                         &xServerInfo,
                                                         &xSocketsConfig );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            LogWarn( ( "Connection to the broker failed. Status=%d ."
                       "Retrying connection with backoff and jitter.", xNetworkStatus ) );
            xStatus = pdFAIL;
            xRetryUtilsStatus = RetryUtils_BackoffAndSleep( &xReconnectParams );
        }

        if( xRetryUtilsStatus == RetryUtilsRetriesExhausted )
        {
            LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
            xNetworkStatus = TRANSPORT_SOCKET_STATUS_CONNECT_FAILURE;
        }
    } while( ( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS ) && ( xRetryUtilsStatus == RetryUtilsSuccess ) );

    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext )
{
    MQTTStatus_t xResult;
    MQTTConnectInfo_t xConnectInfo;
    bool xSessionPresent;
    TransportInterface_t xTransport;
    BaseType_t xStatus = pdFAIL;

    /* Fill in Transport Interface send and receive function pointers. */
    xTransport.pNetworkContext = pxNetworkContext;
    xTransport.send = SecureSocketsTransport_Send;
    xTransport.recv = SecureSocketsTransport_Recv;

    /* Initialize MQTT library. */
    xResult = MQTT_Init( pxMQTTContext, &xTransport, prvGetTimeMs, prvEventCallback, &xBuffer );
    configASSERT( xResult == MQTTSuccess );

    /* Some fields are not used in this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xConnectInfo, 0x00, sizeof( xConnectInfo ) );

    /* Start with a clean session i.e. direct the MQTT broker to discard any
     * previous session data. Also, establishing a connection with clean session
     * will ensure that the broker does not store any data when this client
     * gets disconnected. */
    xConnectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    xConnectInfo.pClientIdentifier = democonfigCLIENT_IDENTIFIER;
    xConnectInfo.clientIdentifierLength = ( uint16_t ) strlen( democonfigCLIENT_IDENTIFIER );

    /* Set MQTT keep-alive period. If the application does not send packets at an interval less than
     * the keep-alive period, the MQTT library will send PINGREQ packets. */
    xConnectInfo.keepAliveSeconds = mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS;

    /* Send MQTT CONNECT packet to broker. LWT is not used in this demo, so it
     * is passed as NULL. */
    xResult = MQTT_Connect( pxMQTTContext,
                            &xConnectInfo,
                            NULL,
                            mqttexampleCONNACK_RECV_TIMEOUT_MS,
                            &xSessionPresent );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to establish MQTT connection: Server=%s, MQTTStatus=%s",
                    democonfigMQTT_BROKER_ENDPOINT, MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        /* Successfully established and MQTT connection with the broker. */
        LogInfo( ( "An MQTT connection is established with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xStatus = pdPASS;
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static void prvUpdateSubAckStatus( MQTTPacketInfo_t * pxPacketInfo )
{
    MQTTStatus_t xResult = MQTTSuccess;
    uint8_t * pucPayload = NULL;
    size_t ulSize = 0;
    uint32_t ulTopicCount = 0U;

    xResult = MQTT_GetSubAckStatusCodes( pxPacketInfo, &pucPayload, &ulSize );

    /* MQTT_GetSubAckStatusCodes always returns success if called with packet info
     * from the event callback and non-NULL parameters. */
    configASSERT( xResult == MQTTSuccess );

    for( ulTopicCount = 0; ulTopicCount < ulSize; ulTopicCount++ )
    {
        xTopicFilterContext[ ulTopicCount ].xSubAckStatus = pucPayload[ ulTopicCount ];
    }
}
/*-----------------------------------------------------------*/

static BaseType_t prvMQTTSubscribeWithBackoffRetries( MQTTContext_t * pxMQTTContext )
{
    MQTTStatus_t xResult = MQTTSuccess;
    RetryUtilsStatus_t xRetryUtilsStatus = RetryUtilsSuccess;
    RetryUtilsParams_t xRetryParams;
    MQTTSubscribeInfo_t xMQTTSubscription[ mqttexampleTOPIC_COUNT ];
    bool xFailedSubscribeToTopic = false;
    uint32_t ulTopicCount = 0U;
    BaseType_t xStatus = pdFAIL;

    /* Some fields not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTSubscription, 0x00, sizeof( xMQTTSubscription ) );

    /* Get a unique packet id. */
    usSubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Subscribe to the mqttexampleTOPIC topic filter. This example subscribes to
     * only one topic and uses QoS1. */
    xMQTTSubscription[ 0 ].qos = MQTTQoS1;
    xMQTTSubscription[ 0 ].pTopicFilter = mqttexampleTOPIC;
    xMQTTSubscription[ 0 ].topicFilterLength = ( uint16_t ) strlen( mqttexampleTOPIC );

    /* Initialize retry attempts and interval. */
    RetryUtils_ParamsReset( &xRetryParams );
    xRetryParams.maxRetryAttempts = MAX_RETRY_ATTEMPTS;

    do
    {
        /* The client is now connected to the broker. Subscribe to the topic
         * as specified in mqttexampleTOPIC at the top of this file by sending a
         * subscribe packet then waiting for a subscribe acknowledgment (SUBACK).
         * This client will then publish to the same topic it subscribed to, so it
         * will expect all the messages it sends to the broker to be sent back to it
         * from the broker. This demo uses QOS0 in Subscribe, therefore, the Publish
         * messages received from the broker will have QOS0. */
        LogInfo( ( "Attempt to subscribe to the MQTT topic %s.", mqttexampleTOPIC ) );
        xResult = MQTT_Subscribe( pxMQTTContext,
                                  xMQTTSubscription,
                                  sizeof( xMQTTSubscription ) / sizeof( MQTTSubscribeInfo_t ),
                                  usSubscribePacketIdentifier );

        if( xResult != MQTTSuccess )
        {
            LogError( ( "Failed to SUBSCRIBE to MQTT topic %s. Error=%s",
                        mqttexampleTOPIC, MQTT_Status_strerror( xResult ) ) );
        }
        else
        {
            xStatus = pdPASS;
            LogInfo( ( "SUBSCRIBE sent for topic %s to broker.", mqttexampleTOPIC ) );

            /* Process incoming packet from the broker. After sending the subscribe, the
             * client may receive a publish before it receives a subscribe ack. Therefore,
             * call generic incoming packet processing function. Since this demo is
             * subscribing to the topic to which no one is publishing, probability of
             * receiving Publish message before subscribe ack is zero; but application
             * must be ready to receive any packet.  This demo uses the generic packet
             * processing function everywhere to highlight this fact. */
            xResult = MQTT_ProcessLoop( pxMQTTContext, mqttexamplePROCESS_LOOP_TIMEOUT_MS );

            if( xResult != MQTTSuccess )
            {
                LogError( ( "Failed to receive SUBACK response for SUBSCRIBE request: ProcessLoopDuration=%u, Error=%s",
                            mqttexamplePROCESS_LOOP_TIMEOUT_MS, MQTT_Status_strerror( xResult ) ) );
            }
        }

        if( xStatus == pdPASS )
        {
            /* Reset flag before checking suback responses. */
            xFailedSubscribeToTopic = false;

            /* Check if recent subscription request has been rejected. #xTopicFilterContext is updated
             * in the event callback to reflect the status of the SUBACK sent by the broker. It represents
             * either the QoS level granted by the server upon subscription, or acknowledgement of
             * server rejection of the subscription request. */
            for( ulTopicCount = 0; ulTopicCount < mqttexampleTOPIC_COUNT; ulTopicCount++ )
            {
                if( xTopicFilterContext[ ulTopicCount ].xSubAckStatus == MQTTSubAckFailure )
                {
                    LogWarn( ( "Server rejected subscription request. Attempting to re-subscribe to topic %s.",
                               xTopicFilterContext[ ulTopicCount ].pcTopicFilter ) );
                    xFailedSubscribeToTopic = true;
                    xRetryUtilsStatus = RetryUtils_BackoffAndSleep( &xRetryParams );
                    break;
                }
            }
        }

        if( xRetryUtilsStatus == RetryUtilsRetriesExhausted )
        {
            LogError( ( "SUBSCRIBE request re-tries exhausted." ) );
        }
    } while( ( xFailedSubscribeToTopic == true ) && ( xRetryUtilsStatus == RetryUtilsSuccess ) );

    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext )
{
    MQTTStatus_t xResult;
    MQTTPublishInfo_t xMQTTPublishInfo;
    BaseType_t xStatus = pdPASS;

    /* Some fields are not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTPublishInfo, 0x00, sizeof( xMQTTPublishInfo ) );

    /* This demo uses QoS1. */
    xMQTTPublishInfo.qos = MQTTQoS1;
    xMQTTPublishInfo.retain = false;
    xMQTTPublishInfo.pTopicName = mqttexampleTOPIC;
    xMQTTPublishInfo.topicNameLength = ( uint16_t ) strlen( mqttexampleTOPIC );
    xMQTTPublishInfo.pPayload = mqttexampleMESSAGE;
    xMQTTPublishInfo.payloadLength = strlen( mqttexampleMESSAGE );

    /* Get a unique packet id. */
    usPublishPacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Send PUBLISH packet. Packet ID is not used for a QoS1 publish. */
    xResult = MQTT_Publish( pxMQTTContext, &xMQTTPublishInfo, usPublishPacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        xStatus = pdFAIL;
        LogError( ( "Failed to send PUBLISH message to broker: Topic=%s, Error=%s",
                    mqttexampleTOPIC,
                    MQTT_Status_strerror( xResult ) ) );
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvMQTTUnsubscribeFromTopic( MQTTContext_t * pxMQTTContext )
{
    MQTTStatus_t xResult;
    MQTTSubscribeInfo_t xMQTTSubscription[ mqttexampleTOPIC_COUNT ];
    BaseType_t xStatus = pdPASS;

    /* Some fields not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTSubscription, 0x00, sizeof( xMQTTSubscription ) );

    /* Get a unique packet id. */
    usSubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Subscribe to the mqttexampleTOPIC topic filter. This example subscribes to
     * only one topic and uses QoS1. */
    xMQTTSubscription[ 0 ].qos = MQTTQoS1;
    xMQTTSubscription[ 0 ].pTopicFilter = mqttexampleTOPIC;
    xMQTTSubscription[ 0 ].topicFilterLength = ( uint16_t ) strlen( mqttexampleTOPIC );

    /* Get next unique packet identifier. */
    usUnsubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Send UNSUBSCRIBE packet. */
    xResult = MQTT_Unsubscribe( pxMQTTContext,
                                xMQTTSubscription,
                                sizeof( xMQTTSubscription ) / sizeof( MQTTSubscribeInfo_t ),
                                usUnsubscribePacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        xStatus = pdFAIL;
        LogError( ( "Failed to send UNSUBSCRIBE request to broker: TopicFilter=%s, Error=%s",
                    mqttexampleTOPIC,
                    MQTT_Status_strerror( xResult ) ) );
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId )
{
    uint32_t ulTopicCount = 0U;

    switch( pxIncomingPacket->type )
    {
        case MQTT_PACKET_TYPE_PUBACK:
            LogInfo( ( "PUBACK received for packet Id %u.", usPacketId ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usPublishPacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_SUBACK:

            /* A SUBACK from the broker, containing the server response to our subscription request, has been received.
             * It contains the status code indicating server approval/rejection for the subscription to the single topic
             * requested. The SUBACK will be parsed to obtain the status code, and this status code will be stored in global
             * variable #xTopicFilterContext. */
            prvUpdateSubAckStatus( pxIncomingPacket );

            for( ulTopicCount = 0; ulTopicCount < mqttexampleTOPIC_COUNT; ulTopicCount++ )
            {
                if( xTopicFilterContext[ ulTopicCount ].xSubAckStatus != MQTTSubAckFailure )
                {
                    LogInfo( ( "Subscribed to the topic %s with maximum QoS %u.",
                               xTopicFilterContext[ ulTopicCount ].pcTopicFilter,
                               xTopicFilterContext[ ulTopicCount ].xSubAckStatus ) );
                }
            }

            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usSubscribePacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            LogInfo( ( "Unsubscribed from the topic %s.", mqttexampleTOPIC ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usUnsubscribePacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_PINGRESP:
            LogInfo( ( "Ping Response successfully received." ) );
            break;

        /* Any other packet type is invalid. */
        default:
            LogWarn( ( "prvMQTTProcessResponse() called with unknown packet type:(%02X).",
                       pxIncomingPacket->type ) );
    }
}

/*-----------------------------------------------------------*/

static void prvMQTTProcessIncomingPublish( MQTTPublishInfo_t * pxPublishInfo )
{
    configASSERT( pxPublishInfo != NULL );

    /* Process incoming Publish. */
    LogInfo( ( "Incoming QoS : %d\n", pxPublishInfo->qos ) );

    /* Verify the received publish is for the we have subscribed to. */
    if( ( pxPublishInfo->topicNameLength == strlen( mqttexampleTOPIC ) ) &&
        ( 0 == strncmp( mqttexampleTOPIC, pxPublishInfo->pTopicName, pxPublishInfo->topicNameLength ) ) )
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s matches subscribed topic."
                   "Incoming Publish Message : %.*s",
                   pxPublishInfo->topicNameLength,
                   pxPublishInfo->pTopicName,
                   pxPublishInfo->payloadLength,
                   pxPublishInfo->pPayload ) );
    }
    else
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s does not match subscribed topic.",
                   pxPublishInfo->topicNameLength,
                   pxPublishInfo->pTopicName ) );
    }
}

/*-----------------------------------------------------------*/

static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo )
{
    /* The MQTT context is not used for this demo. */
    ( void ) pxMQTTContext;

    if( ( pxPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        prvMQTTProcessIncomingPublish( pxDeserializedInfo->pPublishInfo );
    }
    else
    {
        prvMQTTProcessResponse( pxPacketInfo, pxDeserializedInfo->packetIdentifier );
    }
}

/*-----------------------------------------------------------*/

static uint32_t prvGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) xTickCount * MILLISECONDS_PER_TICK;

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}

/*-----------------------------------------------------------*/
