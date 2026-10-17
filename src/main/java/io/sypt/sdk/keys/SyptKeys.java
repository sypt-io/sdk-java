package io.sypt.sdk.keys;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.crypter.factory.CrypterFactory;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.signer.exception.SignerException;
import io.sypt.core.signer.factory.SignerFactory;
import io.sypt.sdk.SyptClient;
import io.sypt.sdk.entity.Domain;
import io.sypt.sdk.entity.KeyMaterialId;
import io.sypt.sdk.exception.SyptException;

/**
 * Local operations with the public certificates of a key material: verify a signature produced by
 * sypt.io, or encrypt data that only sypt.io can decrypt. Certificates are fetched once per
 * domain and key material, then kept in memory.
 */
public final class SyptKeys {

	private final SyptClient client;
	private final Map<String, PublicKeyHolderKSM> ksms = new HashMap<>();

	public SyptKeys(SyptClient client) {
		this.client = Objects.requireNonNull(client, "client cannot be null");
	}

	/**
	 * Verify a signature returned by {@code POST /{domain}/sign}.
	 *
	 * @param digest    Base64 digest that was signed
	 * @param signature Base64 signature
	 */
	public boolean verify(Domain domain, KeyMaterialId keyMaterialId, String digest, String signature) throws SyptException {
		Objects.requireNonNull(digest, "digest cannot be null");
		Objects.requireNonNull(signature, "signature cannot be null");

		PublicKeyHolderKSM ksm = load(domain, keyMaterialId);
		String alias = keyMaterialId.val();

		try {
			return SignerFactory.getSigner(ksm.getVerificationType(alias), ksm, alias).verify(
				Base64.getDecoder().decode(digest),
				signature.getBytes(StandardCharsets.UTF_8)
			);
		} catch (IllegalArgumentException e) {
			throw new SyptException(400, "digest and signature must be Base64 encoded", e);
		} catch (SignerException | KSMException e) {
			throw new SyptException("Unable to verify the signature", e);
		}
	}

	/**
	 * Encrypt data with the encryption certificate of a key material.
	 */
	public AsymmetricSypterObject encrypt(Domain domain, KeyMaterialId keyMaterialId, byte[] data) throws SyptException {
		Objects.requireNonNull(data, "data cannot be null");

		PublicKeyHolderKSM ksm = load(domain, keyMaterialId);
		String alias = keyMaterialId.val();

		try {
			return CrypterFactory.getCrypter(ksm.getEncryptionType(alias), ksm, alias).encrypt(data);
		} catch (CrypterException | KSMException e) {
			throw new SyptException("Unable to encrypt the data", e);
		}
	}

	private PublicKeyHolderKSM load(Domain domain, KeyMaterialId keyMaterialId) throws SyptException {
		Objects.requireNonNull(domain, "domain cannot be null");
		Objects.requireNonNull(keyMaterialId, "keyMaterialId cannot be null");

		PublicKeyHolderKSM ksm = ksms.computeIfAbsent(domain.val(), _ -> new PublicKeyHolderKSM());

		try {
			if (!ksm.exists(keyMaterialId.val())) {
				SyptKeyMaterialResponse keyMaterial = KeyMaterialParser.parse(client.getKey(domain, keyMaterialId).body());

				// Stored under the requested ID, which is the one used for the lookups
				ksm.addCertificates(
					keyMaterialId.val(),
					keyMaterial.keyType(),
					keyMaterial.encryptionCertificate(),
					keyMaterial.verificationCertificate()
				);
			}
		} catch (KSMException e) {
			throw new SyptException("Unable to load the key material " + keyMaterialId.val(), e);
		}

		return ksm;
	}
}
