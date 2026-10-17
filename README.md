# sypt.io - Java SDK

Client of the [sypt.io](https://www.sypt.io) API: every request is signed with your own key according to
[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures), and sypt.io signs or decrypts
with the key of your domain, which never leaves the platform.

The SDK also verifies signatures and encrypts data locally with the public certificates of a key material.

- Java 25
- Works in a GraalVM native image without reflection configuration: JSON is read and written with the
  Jackson streaming API only (no data binding, no annotations).
- Does not register any JCA provider. EC encryption (ECIES) needs BouncyCastle: register it in your
  application (`Security.addProvider(new BouncyCastleProvider())`). ML-DSA and ML-KEM are provided by the JDK.

## Installation

```xml
<dependency>
	<groupId>io.sypt</groupId>
	<artifactId>sypt-sdk</artifactId>
	<version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Sign a digest

```java
SyptClient client = SyptClient.newBuilder()
	.timeout(Duration.ofSeconds(30))
	.build();

// Private key of the certificate registered on sypt.io for the domain
SyptSignatureParameters credentials = new SyptSignatureParametersKeystore(
	new KeyCertificateId("sypt_kc_..."),
	new KeystorePath("/path/to/caller.p12"),
	new KeystorePassword(password),
	new KeyAlias("caller"),
	new KeyAlg("ecdsa-p256-sha256")
);

HttpResponse<String> response = client.sign(
	new Domain("example.com"),
	SyptRequest.sign("sypt_km_...", base64Digest, "invoice-42"),
	credentials
);
```

A PEM private key (unencrypted PKCS#8, for example the key of an agent) is used with
`SyptSignatureParametersPrivateKey`. Its signature algorithm can be given by its RFC 9421 name
(`ecdsa-p256-sha256`) or by its JCA name (`SHA256withECDSA`).

`client.decrypt(...)` and `client.createAgent(...)` work the same way. Any status other than 200 raises a
`SyptException` carrying the HTTP status and the body of the response.

## Verify a signature, encrypt data

```java
SyptKeys keys = new SyptKeys(client);

boolean valid = keys.verify(new Domain("example.com"), new KeyMaterialId("sypt_km_..."), base64Digest, signature);
AsymmetricSypterObject encrypted = keys.encrypt(new Domain("example.com"), new KeyMaterialId("sypt_km_..."), data);
```

The certificates are fetched once (`GET /{domain}/keys/{keyMaterialId}`) and kept in memory.

## sypt profile v1 of RFC 9421

Every SDK, whatever its language, must produce exactly these requests.

| Item | Value |
|---|---|
| Covered components | `"@method" "@path" "date" "content-digest"` |
| Parameters, in this order | `alg`, `created` (Unix seconds), `nonce` (unique per request), `keyid` (Key ID of the certificate) |
| Label | `sig1` |
| `Date` | RFC 1123 date of the same instant as `created` |
| `Content-Digest` | `sha-256=:<base64 SHA-256 of the body>:` (RFC 9530); the body cannot be empty |
| Other headers | `Content-Type: application/json`, `Want-Content-Digest: sha-256=10` |
| Algorithms | `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `rsa-pss-sha512`, `rsa-v1_5-sha256` |

ECDSA signatures use the raw `r || s` encoding required by RFC 9421 (`SHA256withECDSAinP1363Format`).

### Test vectors

[`src/test/resources/vectors/profile-v1`](src/test/resources/vectors/profile-v1) contains the inputs (key,
method, URL, body, `created`, `nonce`) and the expected outputs (signature base and headers) of each
algorithm. The test keys are in [`src/test/resources/vectors/keys`](src/test/resources/vectors/keys)
(the Ed25519 key is the one of RFC 9421, appendix B.1.4).

- Ed25519 and RSA PKCS#1 v1.5 signatures are deterministic: the `Signature` header must be identical.
- ECDSA and RSA-PSS signatures are not: the signature base must be identical, and the expected signature
  must verify with the public key.

They are regenerated with `mvn test -Dtest=ProfileV1VectorsTest -Dsypt.vectors.generate=true`. A change of
these files is a change of the protocol.

## Build

```bash
mvn clean verify
```

The tests start a local HTTP server on `127.0.0.1` standing for the API.

## License

Apache License, Version 2.0
