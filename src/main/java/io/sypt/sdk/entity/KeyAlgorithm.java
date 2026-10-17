package io.sypt.sdk.entity;

/**
 * Algorithms of a PEM private key.
 *
 * @param algorithm     {@link java.security.KeyFactory} algorithm of the key (ex: EC, RSA, Ed25519)
 * @param algorithmHash signature algorithm, either its RFC 9421 name (ex: ecdsa-p256-sha256)
 *                      or its JCA name (ex: SHA256withECDSA), as returned by sypt.io for agents
 */
public record KeyAlgorithm(String algorithm, String algorithmHash) {

}
