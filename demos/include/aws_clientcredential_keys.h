/*
 * FreeRTOS V202012.00
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

/*
 ****************************************************************************
 * NOTE!
 * This file is for ease of demonstration only.  Secret information should not
 * be pasted into the header file in production devices.  Do not paste
 * production secrets here!  Production devices should store secrets such as
 * private keys securely, such as within a secure element.  See our examples that
 * demonstrate how to use the PKCS #11 API for secure keys access.
 ****************************************************************************
 */

#ifndef AWS_CLIENT_CREDENTIAL_KEYS_H
#define AWS_CLIENT_CREDENTIAL_KEYS_H

/*
 * @brief PEM-encoded client certificate.
 *
 * @todo If you are running one of the FreeRTOS demo projects, set this
 * to the certificate that will be used for TLS client authentication.
 *
 * @note Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 */
#define keyCLIENT_CERTIFICATE_PEM \
"-----BEGIN CERTIFICATE-----\n"\
"MIIDWjCCAkKgAwIBAgIVAJFsHNe686S2JV2BytyTEKnTo4BbMA0GCSqGSIb3DQEB\n"\
"CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n"\
"IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0xOTA3MjkyMjM4\n"\
"NTlaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n"\
"dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv5xTbsNCf2tIODOuY\n"\
"Z5VqrSVXN8wnx3c77VaFbaspNFWwQLEFUjd/4asAfeJzdsngtT3bC4fcVXmGkSkY\n"\
"g0SxMETeU07o9nAvhhIUOudWfiWUTNhbyk1PgJxl1D3JIl7br2Vk/LPfd4Ql8KUS\n"\
"9Yfsl/W1gOBbfkJDwztm43exF0v9knRQ9F6Nz4jM2xl13TCNTXlKC95WzMwqrftL\n"\
"3s/sgEDBPFoVHj9t3psOFCUxLEfP55GjaKH9JZPPIXTrhxsvhjOw3ohK74DziK0+\n"\
"Ww1Ua38vZWzkP5nvxKGDNS7z5QJ3Al2EnGY3HveDQnxGA7+GXM8A19Zm3Vmn86LA\n"\
"4pTHAgMBAAGjYDBeMB8GA1UdIwQYMBaAFE4lPoscNahfsDhQmjl1DHYbsso0MB0G\n"\
"A1UdDgQWBBSsmCCOqeOjf4iipBJEnfcZI5ZqajAMBgNVHRMBAf8EAjAAMA4GA1Ud\n"\
"DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAo59ChV+kjZJKag5Qff7dZlfp\n"\
"5CG/XGknCBd6UuymX13B890cqRpSD2inAl820WnJSN6QDcda+LpjjO/WUHotr+gn\n"\
"HiQAmIqax4m/m6DsIJh6ADnAQbbY5M7bvtO9WPfY9uhfxB6jQ1Y1BtixTwXpCahL\n"\
"KhVjBdWvXOT7hfdjUwS3ewEtLYAzAbPCLIi88z5dallEB4q4EkXJji+vEGBllZ4e\n"\
"DG+jipwA7OB8VNpXW8zVD7gdxrlMichsdPMsQ3FlGDu19h3jTjOg0sZn7VK/5gk6\n"\
"dfSLpQeUOK+qLO7lOT1MEPmtO221jMENPUFCvdgU+7uqJHOdVKA4hA0dHFMt9w==\n"\
"-----END CERTIFICATE-----"

/*
 * @brief PEM-encoded issuer certificate for AWS IoT Just In Time Registration (JITR).
 *
 * @todo If you are using AWS IoT Just in Time Registration (JITR), set this to
 * the issuer (Certificate Authority) certificate of the client certificate above.
 *
 * @note This setting is required by JITR because the issuer is used by the AWS
 * IoT gateway for routing the device's initial request. (The device client
 * certificate must always be sent as well.) For more information about JITR, see:
 *  https://docs.aws.amazon.com/iot/latest/developerguide/jit-provisioning.html,
 *  https://aws.amazon.com/blogs/iot/just-in-time-registration-of-device-certificates-on-aws-iot/.
 *
 * If you're not using JITR, set below to NULL.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 */
#define keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM    NULL

/*
 * @brief PEM-encoded client private key.
 *
 * @todo If you are running one of the FreeRTOS demo projects, set this
 * to the private key that will be used for TLS client authentication.
 * Please note pasting a key into the header file in this manner is for
 * convenience of demonstration only and should not be done in production.
 * Never past a production private key here!.  Production devices should
 * store keys securely, such as within a secure element.  Additionally,
 * we provide the corePKCS library that further enhances security by
 * enabling keys to be used without exposing them to software.
 *
 * @note Must include the PEM header and footer:
 * "-----BEGIN RSA PRIVATE KEY-----\n"\
 * "...base64 data...\n"\
 * "-----END RSA PRIVATE KEY-----\n"
 */
#define keyCLIENT_PRIVATE_KEY_PEM \
"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEogIBAAKCAQEAr+cU27DQn9rSDgzrmGeVaq0lVzfMJ8d3O+1WhW2rKTRVsECx\n"\
"BVI3f+GrAH3ic3bJ4LU92wuH3FV5hpEpGINEsTBE3lNO6PZwL4YSFDrnVn4llEzY\n"\
"W8pNT4CcZdQ9ySJe269lZPyz33eEJfClEvWH7Jf1tYDgW35CQ8M7ZuN3sRdL/ZJ0\n"\
"UPRejc+IzNsZdd0wjU15SgveVszMKq37S97P7IBAwTxaFR4/bd6bDhQlMSxHz+eR\n"\
"o2ih/SWTzyF064cbL4YzsN6ISu+A84itPlsNVGt/L2Vs5D+Z78ShgzUu8+UCdwJd\n"\
"hJxmNx73g0J8RgO/hlzPANfWZt1Zp/OiwOKUxwIDAQABAoIBAFtBB1oddW2oqJZv\n"\
"b32mJyarYpbHtJriaOHm857O0R/ULav9M5iuGWq3WO4tYGBEPODdRZSwe6/7i8sa\n"\
"3XYBC47cmq24DFThHDwbUp+6Gy+My9QOtaOQ5OCcuQY+wDrrIMjZSkHEs0/4Ac9o\n"\
"80pNpFFCWE7r5/ivHJNo4hUzZnGw5u2oOQsYbrALzjOrfVsuG8xindMyzlLvKGLH\n"\
"pIsIFns0db8iiPOIFiFQ2uJ/GsOx9rMGBaiXC0mW+d5xhu1bBAQzs8rZDw3pxSJO\n"\
"r7LXZvfIzAdOA27nyzWp2D6ZmHyIJmyS/TEeR6A6wKHsoXyhevFL0Nf5fN2E+PF6\n"\
"NAMWBDECgYEA3f0hSBCSwY8HD4tcKooPKw1xR2QG2f0Pxh2EjWLx8mQ/bE1ZE2fQ\n"\
"1C46Dd03zR7RWnxucMCxM6xSOjHbz6Mi/Cd5n5SZ99DSFf/3UK8rdPTOD6hvZg+a\n"\
"JQ1AsO4OVBMb6688/oLFYHKUFdhHOo6StfY4kyO+77dv2g+Xl6RVHBkCgYEAytpb\n"\
"JqO3VvsqSB8UiCbRi6a1vU+iDRRPwE4NT65LdrxIkC1RZXUlaLVFVIzhZPqfsyMc\n"\
"x6ekKdvrI+b94L7D0AGdCNxbgBe92AKTYxGH2AzZ3MQvJgECWzhrqjjuFqPKah7T\n"\
"U0Z0NJ7t3A2gDgBGpCXqUJoS0YEdOqKosuwbU98CgYAyAJSAkQsdgkQK4k8uXc6w\n"\
"2eRMOmG4tGHbNEbpOgJZoO8QTBPmZRoK0SbOfKfXEjwB78lIqH7Bru0OorBqgsqc\n"\
"lZ+1rFlKEsVfozpn+C0HuSS5Li15hcYo1mVd9SFRGsTNP7mzcm1XHjfw+7h/niG5\n"\
"zu5LZl/Zyy3splp1E9T/8QKBgEZO9obm+bXZKieDNj+WjMyFhLpP7o/v+VBi/TQf\n"\
"6iIGUnQ+cNbkionHQndyuPCh+VZClkgRL9IeWlrARkBufjoLRR18Gu7Dy9Yh1mng\n"\
"+p+EnMJq8RiQAvwRCygdwU/xh0fO1VooskBG0ZSS2GXh7JoaViOHs3wP70yScjxJ\n"\
"n5MrAoGAN2jDXWY2foNwTNP7wAAyyTA8tQAFiUC2anXDN47OKiajNyhCJJmg5UPI\n"\
"ROViXnPxD2xHwOAl/r7c+TxzxhwhvJMURwS5utc1urv8VDCoNsqBYOmBkL5TWsDh\n"\
"3VaQ+9CdGT0od65HgrbdrCdT9GvOMSWzYLWD0vMqNNTEmkt5m3M=\n"\
"-----END RSA PRIVATE KEY-----"

#endif /* AWS_CLIENT_CREDENTIAL_KEYS_H */
