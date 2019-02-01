package fr.loghub.naclprovider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class KeyStoreTest {

    private static final String KEYSTOREFORMAT = "JCEKS";
    private static final char[] password = new char[] {};

    private static final ProtectionParameter protection = new KeyStore.PasswordProtection(password);

    @BeforeClass
    public static void register() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").newInstance(), Security.getProviders().length + 1);
    }

    private static final byte[] publicKey = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
    private static final byte[] privateKey = new byte[curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES];

    @BeforeClass
    public static void createKeys() {
        int rc = curve25519xsalsa20poly1305.crypto_box_keypair(publicKey, privateKey);
        assert (rc == 0);
    }

    @Test
    public void ZMQCurveTest() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        createKs("/tmp/lh.jceks");
        loadKs("/tmp/lh.jceks");
    }

    private void loadKs(String path) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KEYSTOREFORMAT);
        ks.load(new FileInputStream(path), null);
        System.out.println(Collections.list(ks.aliases()));
        Certificate cert = ks.getCertificate("public");
        Assert.assertNotNull(cert);
        PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry("bi", protection);
        System.out.println(e.getCertificate());
        System.out.println(e.getPrivateKey());
    }

    private void createKs(String path) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        KeyStore ks = KeyStore.getInstance(KEYSTOREFORMAT);
        ks.load(null);

        NaclKeySpec privatekey = new NaclKeySpec(privateKey);
        NaclCertificate certificate = new NaclCertificate(publicKey);

        KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);

        KeyStore.TrustedCertificateEntry tce = new KeyStore.TrustedCertificateEntry(certificate);
        ks.setEntry("public", tce, null);
        ks.setKeyEntry("bi", kf.generatePrivate(privatekey), password, new Certificate[] {certificate});
        ks.store(new FileOutputStream(path), password);
    }
}