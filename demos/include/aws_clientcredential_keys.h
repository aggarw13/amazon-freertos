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
"-----BEGIN CERTIFICATE-----\n" \
"MIIDWjCCAkKgAwIBAgIVAPviMJhMxmBaQQ5p+gEQe8Ar6Y29MA0GCSqGSIb3DQEB\n" \
"CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n" \
"IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0yMTA3MDIwMDE5\n" \
"MzhaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n" \
"dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCs5RdH6De6R26ATBMC\n" \
"PGm/4H6rsk389sVwActwmRzcahk2umGkonPLGFeAy9WLfmLPnbxQRl3KLIPmcZ5/\n" \
"uC6b6xTs8CB1ItiuXKUHufCXFTo8OXdJqeRSBx1I/tnLnk7llrXITkAjHlB1GkGF\n" \
"wC2NtfUF5MmYieD5K5ToRb90wIOndSRD+sEkYiYnzrQ8tzeWWIVxgj0CEkW0vwMW\n" \
"Psqyw05VU1a6733DEIs8YWnVFv1MgEHg3E6ZTBiPp10/QdUmcJwbNEJuwXkCPqJy\n" \
"3zf0BUP2eO7JEvfaN37sEkeOgaNSw37OBBX3g6+v9RkmcGPZQD4q7a9Vt1e5mcjf\n" \
"i6SVAgMBAAGjYDBeMB8GA1UdIwQYMBaAFFQMtxQLZQ4J0HtKL7WTNdkYIjfCMB0G\n" \
"A1UdDgQWBBQ7rAn94F5cRIZWwjDgB503qhwM7zAMBgNVHRMBAf8EAjAAMA4GA1Ud\n" \
"DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAllUB/O2Yqt6GRdiGRAoxM/IJ\n" \
"pPShZ6QW6Ejk0GOHOlmu1XNnN9JEVL7gArXVjgfpnvEr18BE/e/k7ZMlh4fd1oeQ\n" \
"QEF99gUlyvfw9NBnV62mgKbgurvnmnnpHYt+T13d7Nuxum0mLfryX6L19vzBxky+\n" \
"lEuSWK1D1sL4Y8qsCAkGKPIzrmiuolla+qSv4h+jO9Bnt9ndUMlbdz3NbFLpvIBH\n" \
"bL8LWakG5BG7cEPPbf/vr6lZO4KZd469ySpPGWItfCIlB9MoVZtnNS4aBIfa/FDe\n" \
"Sr1YFffE4r6Ud1xtKHT3Uy39UfhIF7W82t2GAVZmjYeNA/wps5UTY7cPtnnDZg==\n" \
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
"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIIEogIBAAKCAQEArOUXR+g3ukdugEwTAjxpv+B+q7JN/PbFcAHLcJkc3GoZNrph\n" \
"pKJzyxhXgMvVi35iz528UEZdyiyD5nGef7gum+sU7PAgdSLYrlylB7nwlxU6PDl3\n" \
"SankUgcdSP7Zy55O5Za1yE5AIx5QdRpBhcAtjbX1BeTJmIng+SuU6EW/dMCDp3Uk\n" \
"Q/rBJGImJ860PLc3lliFcYI9AhJFtL8DFj7KssNOVVNWuu99wxCLPGFp1Rb9TIBB\n" \
"4NxOmUwYj6ddP0HVJnCcGzRCbsF5Aj6ict839AVD9njuyRL32jd+7BJHjoGjUsN+\n" \
"zgQV94Ovr/UZJnBj2UA+Ku2vVbdXuZnI34uklQIDAQABAoIBAFtAtt7vA6q/1OTG\n" \
"Qiol9LKfLHw2qc7f+Ck76UJOrdrv7Mrj6HFahL8m49hIvTbYyBJIcIH2Ab6ZbCyO\n" \
"v1ctwPvuQackvhzU/YRZxYikbQVw4MG0mu84She5RY2nZRCBR6cJunw0QMnIUDLe\n" \
"XsLXQbPP27j2nihybVlV1UwatAhMTPzPiGgFCSXR0Pf3CEhEqi2cjuJIgGiEX5XO\n" \
"HFn0m9URbgyMyTsY5LX0v8EtMqM6sdm9NnpNRcHrN+2SCTAjXawmA5ZeGvKvMBDm\n" \
"PvUkvQx72FG0XTNjP5zkKQZFLH5EMYgCQGuvZ9X4Ygi8pjsvI8nEKGT9/19CaILZ\n" \
"zifWPkECgYEA4rWDHOpoLBXBTVW7YpGhjG8v9WV/u60X4bnTDIh5MUwH8iSrEgd1\n" \
"R2rd55COke8UAiu9rLvVyuPlqctqwZGg0q6JrA0CcI99YtqLSZF7Wkli99ja64p3\n" \
"BJ5sEd8CLVeuG6olswBQsxJsb3H6/HLhAaAXunoz/5bKzuB5tVpR/mkCgYEAwzun\n" \
"xeYfEul0FHlhz+ACbDaEduRjtGBa4kEhNGGQ66xKsa+2EL8+eRSOjADeYB4pEr+q\n" \
"hx2vfkhCDPMGqgUiUi44YU1uTkMTGe3OyoUHMHl4U+tu+umzp809jL0lR0K8njNX\n" \
"jr7xx7c3yR9U9ZxTXouxxZhQYfPA+V0F9UhbR00CgYBe2IVj4YV3fBqE2istD7RA\n" \
"Znvv9Gi+AaqOGwn6olXhk+d3HHQddNVR7ZmsuUOMNjNuvRH7ZBILcdCxepLNLLnV\n" \
"qoOaYU71/HH+m2POgXjTywQGoMjl5eXpHsYjq+LjSV1j4YkoHCem4zxOW6cfWohb\n" \
"/7gtodaDRXjPmAYTIxhOkQKBgFO0yStFjj8qjxWUMYbSMde5zDO5mrIkufLWH+l4\n" \
"h400UtY6UyJ9DMkXMkL+wFmPtOaP/QpvhOXtDzzEGjBdgSihHpVBgLDXe2IbnxUf\n" \
"0kRLYHcCs5OrDdc9XU1xb4FNMNfXhYvzfHC3spht8ZxZCTm5RWBF/PjybOO9qadP\n" \
"/arlAoGATb2O0lXCezxnDE1EHhkuSApPOV85/amMHHD5iS0Oalo+UlguIS3pT7M2\n" \
"aqJbeqIDfahyBjAaJ79EVOZws4wmgYAObX+NB/Sk9Ms0M1kehVzhzZfqfWzvqHZc\n" \
"/jtk6ElKKJBg2IRTq++aYVJvGTosoVg5Lb7ShjtSU2h2bxI9sDE=\n" \
"-----END RSA PRIVATE KEY-----"

#endif /* AWS_CLIENT_CREDENTIAL_KEYS_H */
