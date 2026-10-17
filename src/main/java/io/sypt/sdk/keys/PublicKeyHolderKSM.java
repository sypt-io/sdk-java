package io.sypt.sdk.keys;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

/**
 * In-memory {@link KSM} holding only public certificates: it can verify and encrypt, never sign nor decrypt.
 */
public class PublicKeyHolderKSM implements KSM {

	private static final String NOT_ALLOWED = "Operation is not allowed";

	private final Map<String, Certificate> certificates = new HashMap<>();
	private final Map<String, KSMType> ksmTypes = new HashMap<>();
	private final AtomicBoolean closed = new AtomicBoolean(false);

	@Override
	public String getProvider() {
		return null;
	}

	public void addCertificates(String alias, KSMType ksmType, Certificate encCertificate, Certificate sigCertificate) throws KSMException {
		getCertificates().put(normalizeAlias(alias, "-enc"), encCertificate);
		ksmTypes.put(normalizeAlias(alias, "-enc"), ksmType);

		getCertificates().put(normalizeAlias(alias, "-sig"), sigCertificate);
		ksmTypes.put(normalizeAlias(alias, "-sig"), ksmType);
	}

	@Override
	public Certificate getEncryptionCertificate(String alias) throws KSMException {
		Certificate cert = getCertificates().get(normalizeAlias(alias, "-enc"));
		if (cert == null) {
			throw new KSMException("Unable to get the EncryptionCertificate");
		}

		return cert;
	}

	@Override
	public Certificate[] getEncryptionCertificateChain(String alias) throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public PublicKey getEncryptionKey(String alias) throws KSMException {
		return getEncryptionCertificate(alias).getPublicKey();
	}

	@Override
	public KSMType getEncryptionType(String alias) throws KSMException {
		return ksmTypes.get(normalizeAlias(alias, "-enc"));
	}

	@Override
	public PrivateKey getDecryptionKey(String alias) throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public Certificate getVerificationCertificate(String alias) throws KSMException {
		Certificate cert = getCertificates().get(normalizeAlias(alias, "-sig"));
		if (cert == null) {
			throw new KSMException("Unable to get the VerificationCertificate");
		}

		return cert;
	}

	@Override
	public Certificate[] getVerificationCertificateChain(String alias) throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public PublicKey getVerificationKey(String alias) throws KSMException {
		return getVerificationCertificate(alias).getPublicKey();
	}

	@Override
	public KSMType getVerificationType(String alias) throws KSMException {
		return ksmTypes.get(normalizeAlias(alias, "-sig"));
	}

	@Override
	public PrivateKey getSigningKey(String alias) throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public boolean exists(String alias) throws KSMException {
		boolean containsEnc = getCertificates().containsKey(normalizeAlias(alias, "-enc"));
		boolean containsSig = getCertificates().containsKey(normalizeAlias(alias, "-sig"));

		if (containsSig ^ containsEnc) {
			throw new KSMException("Keystore is not in sync for alias " + alias);
		}

		return containsSig && containsEnc;
	}

	@Override
	public void put(String alias, KSM ksm) throws KSMException {
		String sigAlias = normalizeAlias(alias, "-sig");
		getCertificates().put(sigAlias, ksm.getVerificationCertificate(sigAlias));
		ksmTypes.put(sigAlias, ksm.getVerificationType(sigAlias));

		String encAlias = normalizeAlias(alias, "-enc");
		getCertificates().put(encAlias, ksm.getEncryptionCertificate(encAlias));
		ksmTypes.put(encAlias, ksm.getEncryptionType(encAlias));
	}

	@Override
	public void remove(String alias) throws KSMException {
		getCertificates().remove(normalizeAlias(alias, "-enc"));
		getCertificates().remove(normalizeAlias(alias, "-sig"));
		ksmTypes.remove(normalizeAlias(alias, "-enc"));
		ksmTypes.remove(normalizeAlias(alias, "-sig"));
	}

	@Override
	public String toBase64() throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public String toBase64(char[] password) throws KSMException {
		throw new KSMException(NOT_ALLOWED);
	}

	@Override
	public void close() {
		if (closed.compareAndSet(false, true)) {
			certificates.clear();
			ksmTypes.clear();
		}
	}

	private Map<String, Certificate> getCertificates() throws KSMException {
		if (closed.get()) {
            throw new KSMException("KSM is closed. Certificates have been wiped.");
        }

        return certificates;
	}

	private String normalizeAlias(String alias, String suffix) {
		if (!alias.endsWith(suffix)) {
			return alias + suffix;
		}

		return alias;
	}

}
