package io.sypt.sdk.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;
import io.sypt.sdk.TestKeys;

class PublicKeyHolderKSMTest {

	private static final String ALIAS = "sypt-crypto-data";

	/**
	 * Regression: put() copied the encryption certificate in place of the verification certificate.
	 */
	@Test
	void putCopiesBothCertificates() throws Exception {
		try (KSM source = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12", TestKeys.KEYSTORE_PASSWORD.toCharArray());
				PublicKeyHolderKSM ksm = new PublicKeyHolderKSM()) {
			ksm.put(ALIAS, source);

			assertThat(ksm.exists(ALIAS)).isTrue();
			assertThat(ksm.getVerificationCertificate(ALIAS)).isEqualTo(source.getVerificationCertificate(ALIAS));
			assertThat(ksm.getEncryptionCertificate(ALIAS)).isEqualTo(source.getEncryptionCertificate(ALIAS));
			assertThat(ksm.getVerificationCertificate(ALIAS)).isNotEqualTo(ksm.getEncryptionCertificate(ALIAS));
			assertThat(ksm.getVerificationType(ALIAS)).isEqualTo(KSMType.EC_384);
		}
	}

	@Test
	void privateOperationsAreNotAllowed() {
		try (PublicKeyHolderKSM ksm = new PublicKeyHolderKSM()) {
			assertThatThrownBy(() -> ksm.getSigningKey(ALIAS)).isInstanceOf(KSMException.class);
			assertThatThrownBy(() -> ksm.getDecryptionKey(ALIAS)).isInstanceOf(KSMException.class);
			assertThatThrownBy(ksm::toBase64).isInstanceOf(KSMException.class);
			assertThatThrownBy(() -> ksm.toBase64(new char[0])).isInstanceOf(KSMException.class);
		}
	}

	@Test
	void missingCertificatesAreReported() throws Exception {
		try (PublicKeyHolderKSM ksm = new PublicKeyHolderKSM()) {
			assertThat(ksm.exists(ALIAS)).isFalse();
			assertThatThrownBy(() -> ksm.getVerificationCertificate(ALIAS))
				.isInstanceOf(KSMException.class)
				.hasMessageContaining("VerificationCertificate");
		}
	}

	@Test
	void closedKsmCannotBeUsed() {
		PublicKeyHolderKSM ksm = new PublicKeyHolderKSM();
		ksm.close();

		assertThatThrownBy(() -> ksm.exists(ALIAS)).isInstanceOf(KSMException.class);
	}
}
