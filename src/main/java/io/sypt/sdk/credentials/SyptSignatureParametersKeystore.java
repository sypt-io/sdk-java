package io.sypt.sdk.credentials;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import io.sypt.sdk.entity.KeyAlg;
import io.sypt.sdk.entity.KeyAlias;
import io.sypt.sdk.entity.KeyCertificateId;
import io.sypt.sdk.entity.KeystorePassword;
import io.sypt.sdk.entity.KeystorePath;
import io.sypt.sdk.exception.SyptException;

/**
 * Private key stored in a PKCS#12 keystore. The keystore password also protects the key.
 */
public record SyptSignatureParametersKeystore(
	
	KeyCertificateId keyCertificateId,
	KeystorePath keystorePath,
	KeystorePassword keystorePassword,
	KeyAlias keyAlias,
	KeyAlg keyAlg
	
) implements SyptSignatureParameters {
	
	@Override
	public String alg() {
		return keyAlg.val();
	}
	
	@Override
	public String keyId() {
		return keyCertificateId().val();
	}
	
	@Override
	public PrivateKey privateKey() throws SyptException {
		String keystorePath = keystorePath().val();
		String keyAlias = keyAlias().val();
		char[] keystorePassword = keystorePassword().val().toCharArray();
		
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");

			try (InputStream is = new FileInputStream(keystorePath)) {
				keyStore.load(is, keystorePassword);
			}

			if (!keyStore.containsAlias(keyAlias)) {
				throw new SyptException(400, "Alias '" + keyAlias + "' not found in the Keystore.");
			}

			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keystorePassword);
			if (privateKey == null) {
				throw new SyptException(400, "Unable to retrieve the Private Key for alias: " + keyAlias);
			}

			return privateKey;
		} catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new SyptException("Unable to retrieve the Private Key", e);
		}
	}

}
