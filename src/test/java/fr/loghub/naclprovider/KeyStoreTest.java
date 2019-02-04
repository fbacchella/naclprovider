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

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class KeyStoreTest {

    private static final char[] password = new char[] {};

    private static final ProtectionParameter protection = new KeyStore.PasswordProtection(password);

    @BeforeClass
    public static void register() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Security.insertProviderAt((Provider) Class.forName("fr.loghub.naclprovider.NaclProvider").newInstance(), Security.getProviders().length + 1);
    }

    private static final byte[] PUBLICKEY = new byte[curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES];
    private static final byte[] PRIVATEKEY = new byte[curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES];

    @BeforeClass
    public static void createKeys() {
        int rc = curve25519xsalsa20poly1305.crypto_box_keypair(PUBLICKEY, PRIVATEKEY);
        assert (rc == 0);
    }

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void TestJks() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        String kspath = testFolder.getRoot().getCanonicalPath() + "/naclprovider.jks";
        createKs(kspath, "JKS");
        loadKs(kspath, "JKS");
    }

    @Test
    public void TestJceks() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        String kspath = testFolder.getRoot().getCanonicalPath() + "/naclprovider.jceks";
        createKs(kspath, "JCEKS");
        loadKs(kspath, "JCEKS");
    }

    @Test(expected=ClassCastException.class)
    public void TestPkcs12() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        String kspath = testFolder.getRoot().getCanonicalPath() + "/naclprovider.p12";
        createKs(kspath, "PKCS12");
        loadKs(kspath, "PKCS12");
    }

    private void loadKs(String path, String keystoreformat) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(keystoreformat);
        ks.load(new FileInputStream(path), null);
        Certificate cert = ks.getCertificate("public");
        Assert.assertNotNull(cert);
        PrivateKeyEntry e = (PrivateKeyEntry) ks.getEntry("pair", protection);
        Assert.assertTrue(e.getCertificate() instanceof NaclCertificate);
        Assert.assertTrue(e.getPrivateKey() instanceof NaclPrivateKey);

    }

    private void createKs(String path, String keystoreformat) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, InvalidKeySpecException {
        KeyStore ks = KeyStore.getInstance(keystoreformat);
        ks.load(null);

        NaclPrivateKeySpec privatekey = new NaclPrivateKeySpec(PRIVATEKEY);
        NaclPublicKeySpec publickey = new NaclPublicKeySpec(PUBLICKEY);
        
        KeyFactory kf = KeyFactory.getInstance(NaclProvider.NAME);

        NaclCertificate certificate = new NaclCertificate(kf.generatePublic(publickey).getEncoded());

        KeyStore.TrustedCertificateEntry tce = new KeyStore.TrustedCertificateEntry(certificate);
        ks.setEntry("public", tce, null);
        ks.setKeyEntry("pair", kf.generatePrivate(privatekey), password, new Certificate[] {certificate});
        ks.store(new FileOutputStream(path), password);
    }

}
