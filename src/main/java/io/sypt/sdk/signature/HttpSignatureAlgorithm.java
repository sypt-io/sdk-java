package io.sypt.sdk.signature;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;

import io.sypt.sdk.exception.SyptException;

public enum HttpSignatureAlgorithm {

	ECDSA_P256_SHA256	("ECDSA P-256 / SHA-256",			"ecdsa-p256-sha256",	"SHA256withECDSAinP1363Format",	null,
							List.of("SHA256withECDSA")),
	ECDSA_P384_SHA384	("ECDSA P-384 / SHA-384",			"ecdsa-p384-sha384",	"SHA384withECDSAinP1363Format",	null,
							List.of("SHA384withECDSA")),
	RSA_PSS_SHA512		("RSA-PSS / SHA-512", 				"rsa-pss-sha512",		"RSASSA-PSS",
							new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1),
							List.of("SHA512withRSA/PSS", "SHA512withRSAandMGF1")),
	RSA_V1_5_SHA256		("RSA PKCS#1 v1.5 / SHA-256",		"rsa-v1_5-sha256",		"SHA256withRSA",				null,
							List.of()),
	ED25519				(HttpSignatureAlgorithm.ED_25519,	"ed25519",				HttpSignatureAlgorithm.ED_25519,	null,
							List.of("EdDSA"));
	
	private static final String ED_25519 = "Ed25519";

	private final String name;
	private final String rfcName;
	private final String jcaName;
	private final AlgorithmParameterSpec spec;
	private final List<String> aliases;

	HttpSignatureAlgorithm(String name, String rfcName, String jcaName, AlgorithmParameterSpec spec, List<String> aliases) {
		this.name = name;
		this.rfcName = rfcName;
		this.jcaName = jcaName;
		this.spec = spec;
		this.aliases = aliases;
	}
	
	public String getName() {
		return name;
	}

	public String getRfcName() {
		return rfcName;
	}

	public String getJcaName() {
		return jcaName;
	}
	
	public AlgorithmParameterSpec getSpec() {
		return spec;
	}
	
	public void validatePrivateKey(PrivateKey privateKey) throws SyptException {
	    if (privateKey == null) {
	        throw new SyptException(400, "Private key is missing");
	    }

	    switch (this) {
	        case ECDSA_P256_SHA256 -> validateEcKey(privateKey, 256, "EC P-256");
	        case ECDSA_P384_SHA384 -> validateEcKey(privateKey, 384, "EC P-384");
	        case RSA_PSS_SHA512, RSA_V1_5_SHA256 -> validateRsaKey(privateKey);
	        case ED25519 -> validateEd25519Key(privateKey);
	    }
	}

	private void validateEcKey(PrivateKey privateKey, int expectedFieldSize, String expectedKeyType) throws SyptException {
	    if (!(privateKey instanceof ECPrivateKey ecKey)) {
	        throw incompatible(expectedKeyType, privateKey);
	    }

	    int fieldSize = ecKey.getParams()
	        .getCurve()
	        .getField()
	        .getFieldSize();

	    if (fieldSize != expectedFieldSize) {
	        throw incompatible(expectedKeyType, privateKey);
	    }
	}

	private void validateRsaKey(PrivateKey privateKey) throws SyptException {
	    if (!(privateKey instanceof RSAPrivateKey rsaKey)) {
	        throw incompatible("RSA", privateKey);
	    }

	    if (rsaKey.getModulus().bitLength() < 2048) {
	        throw new SyptException(400, "RSA key must be at least 2048 bits");
	    }
	}

	private void validateEd25519Key(PrivateKey privateKey) throws SyptException {
	    if (!(privateKey instanceof EdECPrivateKey edKey) || !NamedParameterSpec.ED25519.getName().equals(edKey.getParams().getName())) {
	        throw incompatible(HttpSignatureAlgorithm.ED_25519, privateKey);
	    }
	}

	private SyptException incompatible(String expected, PrivateKey actual) {
	    return new SyptException(400,
	        "Algorithm " + rfcName
	            + " requires a " + expected
	            + " private key, but got a "
	            + actual.getAlgorithm()
	            + " key"
	    );
	}

	/**
	 * Find an algorithm by its RFC 9421 name (ex: ecdsa-p256-sha256).
	 */
	public static HttpSignatureAlgorithm fromRfcName(String rfcName) throws SyptException {
		return Arrays.stream(values())
			.filter(algorithm -> algorithm.rfcName.equals(rfcName))
			.findFirst()
			.orElseThrow(() -> new SyptException(400, "Unsupported HTTP Signature algorithm: " + rfcName));
	}

	/**
	 * Find an algorithm by its RFC 9421 name, its JCA name or a common JCA alias, ignoring case
	 * (ex: ecdsa-p256-sha256, SHA256withECDSA, SHA256withRSA, Ed25519).
	 */
	public static HttpSignatureAlgorithm resolve(String name) throws SyptException {
		if (name == null || name.isBlank()) {
			throw new SyptException(400, "HTTP Signature algorithm is missing");
		}

		String stripped = name.strip();
		return Arrays.stream(values())
			.filter(algorithm -> algorithm.matches(stripped))
			.findFirst()
			.orElseThrow(() -> new SyptException(400, "Unsupported HTTP Signature algorithm: " + name));
	}

	private boolean matches(String candidate) {
		return rfcName.equalsIgnoreCase(candidate)
			|| jcaName.equalsIgnoreCase(candidate)
			|| aliases.stream().anyMatch(alias -> alias.equalsIgnoreCase(candidate));
	}
}
