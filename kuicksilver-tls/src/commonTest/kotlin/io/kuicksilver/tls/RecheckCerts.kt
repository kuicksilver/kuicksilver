// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlin.io.encoding.Base64

/**
 * Client CA re-verification fixtures (valid until 2126, generated with OpenSSL): [weakRoot] is a 1024-bit RSA root (below
 * security level 2) with [clientUnderWeakRoot] under it; [intermediateByX] and [intermediateByY] are one intermediate (one
 * subject, one key) signed by [rootX] and by another root, and [clientViaCross] is a client certificate under that
 * intermediate. All client certificates are P-256 with extendedKeyUsage clientAuth.
 */
internal object RecheckCerts {
    val weakRoot: ByteArray by lazy {
        Base64.decode(
            "MIICBTCCAW6gAwIBAgICMp8wDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaUmVjaGVjayB3ZWFrIFJTQS0xMDI0IHJvb3QwIBcNMjYxMTEyMDEzMjQ0WhgPMjEyNjEwMTkwMTMyNDRaMCUxIzAhBgNVBAMMGlJlY2hlY2sgd2VhayBSU0EtMTAyNCByb290MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9hggWVfsALLUYNRyijm+w5tatmyE2J95hCovArDDDHx1AcKJ3k45kuTSHGZJTG5p5P0l3VJLrrmhnRipSdaGkt1cIQr8YzbDKavpAGd78W+i5l8CXL7D6AsOdtNt0Bsvp9wbqY8C6YmtldxFxu4EjwgqzKkNfET1wd+UtegWKRwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUykxBYWwmlV4P1CJkVbqouwVpqUMwDQYJKoZIhvcNAQELBQADgYEArnfNRvXgEQOQ7fHwkA+Muu9vwlAWFDlUyfJc5+nULX1ex2ie5rsbDwmeWvOPpGECxazHfnVlx8sZwllc0zX+VHbNhfdOkQdUnCiACJoh9Buyzbsq2IC6t/1PzUYFKKqOAR6MRheszIdQElHAI6nwyfbYP2RkEa9l0TkI3ShkeqY=",
        )
    }
    val clientUnderWeakRoot: ByteArray by lazy {
        Base64.decode(
            "MIIBuzCCASSgAwIBAgICC94wDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAwwaUmVjaGVjayB3ZWFrIFJTQS0xMDI0IHJvb3QwIBcNMjYxMTEyMDEzMjQ0WhgPMjEyNjEwMTkwMTMyNDRaMBExDzANBgNVBAMMBmNsd2VhazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLgZeCpSBIPhq9zi5KBwayNCw28eUQD4g5KTbKu5/oMHVs4n9pTYMlbmWOBWmk8QYYqR+5wKcrtjv8EvqAVtR/KjUzBRMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFMpMQWFsJpVeD9QiZFW6qLsFaalDMA0GCSqGSIb3DQEBCwUAA4GBALbkDWIwoE+s33MSGcgGqJfJFT7bxabM9DQ4OssvLItEBTY83hNF0ANXGqPLmDa4olM0ZcJTZSRGDXApQ4i5gIfH/85oQjRfUb5EFyeCVXiYGwqL7Dr+ybErXuwH8kujAulPSgaQFtaXceJnRRngVvnFr2kn3CXJ9j/1nxUBlvNZ",
        )
    }
    val clientUnderWeakRootKey: ByteArray by lazy {
        Base64.decode(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLmHl1+7tLLszm7RlxYup5mQr0ZfJ/8RsbCgzhk9uTXqhRANCAAS4GXgqUgSD4avc4uSgcGsjQsNvHlEA+IOSk2yruf6DB1bOJ/aU2DJW5ljgVppPEGGKkfucCnK7Y7/BL6gFbUfy",
        )
    }
    val rootX: ByteArray by lazy {
        Base64.decode(
            "MIIBZjCCAQygAwIBAgICJNkwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOUmVjaGVjayByb290IFgwIBcNMjYxMTEyMDEzMjQ0WhgPMjEyNjEwMTkwMTMyNDRaMBkxFzAVBgNVBAMMDlJlY2hlY2sgcm9vdCBYMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB7b/CpH64uA5ruNZ7O6JazSxT1SDD+ZRzxFgIwvj2xH5+rga3NmGwUR1fvXgyWy5NIORwjqfXCaIagsa1Bjt1qNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0OBBYEFDv2Vk0LRbKssbrdH+A2wZNHBECYMAoGCCqGSM49BAMCA0gAMEUCIQCsW9ou7R0k+IskH8o3rUtSoVwYLFHQKNXgG/nu9ADyfwIgZo0rSodGk1nhxQXGryiHj0VzOjxqtf2js5NuYvsW1Vs=",
        )
    }
    val intermediateByX: ByteArray by lazy {
        Base64.decode(
            "MIIBjDCCATKgAwIBAgIBCzAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5SZWNoZWNrIHJvb3QgWDAgFw0yNjExMTIwMTMyNDRaGA8yMTI2MTAxOTAxMzI0NFowHzEdMBsGA1UEAwwUUmVjaGVjayBpbnRlcm1lZGlhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQEKk1BOiDQrUEKM28YU7p9IkvwypHJQTFLHP/NHhc6DpakKdNPVu1ABCqV+9GpYJUkC11buXB5fGJ3TAxZ8sdJo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQU6C4B5aDlF87bGWt5Fus+rb3kuR4wHwYDVR0jBBgwFoAUO/ZWTQtFsqyxut0f4DbBk0cEQJgwCgYIKoZIzj0EAwIDSAAwRQIhAIJsmGlDg6MC6clBc679x5mOgIfcGlqAbKCLr1sLYJY+AiBZnv8RjT0Yrv3CepBDs0DSRnsJ8RxtPXFsbmJJ7HbB3g==",
        )
    }
    val intermediateByY: ByteArray by lazy {
        Base64.decode(
            "MIIBjDCCATKgAwIBAgIBDDAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5SZWNoZWNrIHJvb3QgWTAgFw0yNjExMTIwMTMyNDRaGA8yMTI2MTAxOTAxMzI0NFowHzEdMBsGA1UEAwwUUmVjaGVjayBpbnRlcm1lZGlhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQEKk1BOiDQrUEKM28YU7p9IkvwypHJQTFLHP/NHhc6DpakKdNPVu1ABCqV+9GpYJUkC11buXB5fGJ3TAxZ8sdJo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQU6C4B5aDlF87bGWt5Fus+rb3kuR4wHwYDVR0jBBgwFoAU3Wb9i0ydCB/aXL4t5fpYGRYNxPEwCgYIKoZIzj0EAwIDSAAwRQIgDNvY6fi3C47HDOcuD2jpj4AUehJ4WVO+Al2yy3Un5B4CIQDmdP8XC1S+dEAQH5vFktZtOjEZoD5Bh2vEwH4DlWsjvQ==",
        )
    }
    val clientViaCross: ByteArray by lazy {
        Base64.decode(
            "MIIBdTCCARygAwIBAgICXRUwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUUmVjaGVjayBpbnRlcm1lZGlhdGUwIBcNMjYxMTEyMDEzMjQ0WhgPMjEyNjEwMTkwMTMyNDRaMBIxEDAOBgNVBAMMB2NsY3Jvc3MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASK4P6WPo4uP25KP3qtO6Tyf/pwmCt4F7iqVzjKfVHQlSTLo02L7QqaMOusj5Lvta4N6z30d3N+NpXrtwzsj+dco1MwUTAJBgNVHRMEAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBToLgHloOUXztsZa3kW6z6tveS5HjAKBggqhkjOPQQDAgNHADBEAiAT0duKXa9RgSMHuEXMx7Jaz3hbEXgp6YwZudeu+61hrAIgMn/Yvl60vTQqt0GMrCKIfVdki+340UjjTbTTlhM7n9U=",
        )
    }
    val clientViaCrossKey: ByteArray by lazy {
        Base64.decode(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSM/GYRxIR+4pUQFY0716I9GBZTSHz9/+wjvAJCfvNGihRANCAASK4P6WPo4uP25KP3qtO6Tyf/pwmCt4F7iqVzjKfVHQlSTLo02L7QqaMOusj5Lvta4N6z30d3N+NpXrtwzsj+dc",
        )
    }
}
