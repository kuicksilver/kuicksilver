// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import kotlin.io.encoding.Base64

/**
 * A CA issued twice on one key ("Reissued CA": serial 1 without a path length, serial 2 with pathlen 0; same subject, same
 * key, so the same SPKI) and a client certificate under it, valid until 2126. Generated with OpenSSL (prime256v1).
 */
internal object ReissuedCaCerts {
    val ca1: ByteArray by lazy {
        Base64.decode(
            "MIIBXzCCAQWgAwIBAgIBATAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtSZWlzc3VlZCBDQTAgFw0yNjExMTIwMDMxMzNaGA8yMTI2MTAxOTAwMzEzM1owFjEUMBIGA1UEAwwLUmVpc3N1ZWQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARI8Ex6xWXvRpZ6xbbqlMHZtbHxmjq4hqwJX7qhDxd767IiPwTx4dNdKshjg8hgqNa1GJeqrC4yT6JHJ0Ne3JoHo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUMnInpR8wmDiGhSbuogXxGs4wv2AwCgYIKoZIzj0EAwIDSAAwRQIhAJNlkExiUHbJUIJPfiofqmkkUssqPghbkYtS4fsLWph7AiAjBHEtc/QemAtHPEgU242UMGNZRz0qtdWdBg3VY08xtA==",
        )
    }
    val ca2: ByteArray by lazy {
        Base64.decode(
            "MIIBYjCCAQigAwIBAgIBAjAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtSZWlzc3VlZCBDQTAgFw0yNjExMTIwMDMxMzNaGA8yMTI2MTAxOTAwMzEzM1owFjEUMBIGA1UEAwwLUmVpc3N1ZWQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARI8Ex6xWXvRpZ6xbbqlMHZtbHxmjq4hqwJX7qhDxd767IiPwTx4dNdKshjg8hgqNa1GJeqrC4yT6JHJ0Ne3JoHo0UwQzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUMnInpR8wmDiGhSbuogXxGs4wv2AwCgYIKoZIzj0EAwIDSAAwRQIhANlTEN8mt7Yjb8DK9jufstOMLiR1VxfwxVvrmd4YZSPTAiAJ2oqPkoSgGoXMoZRbQFAEUYOwg5j0/dtEEesnFZXEcQ==",
        )
    }
    val client: ByteArray by lazy {
        Base64.decode(
            "MIIBczCCARmgAwIBAgIBAzAKBggqhkjOPQQDAjAWMRQwEgYDVQQDDAtSZWlzc3VlZCBDQTAgFw0yNjExMTIwMDMxMzNaGA8yMTI2MTAxOTAwMzEzM1owGTEXMBUGA1UEAwwOcmVpc3N1ZSBjbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARTFqlOwd0IIT/125Me2AyyfVRAcqHaggT3HcwD3fTC/Ejx7bFERf58clR9iHyBcQb8qlHe9ay6Tz/qXLkhlQf6o1MwUTAJBgNVHRMEAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBQycielHzCYOIaFJu6iBfEazjC/YDAKBggqhkjOPQQDAgNIADBFAiBB0ntCSUVVHMDuUr/NFFLi66oGVofpZKqPpsmcdDqpigIhAKZHVinxUMB8zt/F3e1qWpOGIxj0jpLCqLQetaVUo/a7",
        )
    }
    val clientKey: ByteArray by lazy {
        Base64.decode(
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmPPRLHM+pVueJsrjHT6rWY6O91pfYfz452mnP0s5GwShRANCAARTFqlOwd0IIT/125Me2AyyfVRAcqHaggT3HcwD3fTC/Ejx7bFERf58clR9iHyBcQb8qlHe9ay6Tz/qXLkhlQf6",
        )
    }
}
